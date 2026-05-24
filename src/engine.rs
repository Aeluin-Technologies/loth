//! Orchestrates SpiceDB ReBAC + optional Cedar ABAC, plus optional replication.

use std::sync::Arc;

use crate::cedar::abac::AbacEngine;
use crate::replication::{
    FatalReplicationRx, ReplicationHandle, ReplicationSettings, replication_pipeline,
};
use crate::spicedb::client::SpiceDbClient;
use crate::spicedb::rebac::{
    DEFAULT_SCHEMA_ZED, Rebac, RebacDecision, RelationshipOp, SubjectFilter,
};
use crate::spicedb::schema::{SchemaManager, SchemaMode};
use crate::types::{AuthError, CedarContext, LothConfig};

/// The unified authorization coordinator engine ("Loth").
///
/// This engine harmonizes a structural Relationship-Based Access Control (ReBAC) layer
/// managed via SpiceDB alongside a dynamic Attribute-Based Access Control (ABAC) layer
/// powered by the Cedar policy language. It also supports fail-closed tracking behavior
/// linked directly to upstream transactional data replication streams.
pub struct LothEngine {
    rebac: Rebac,
    abac: AbacEngine,
    zed_schema: String,
    fatal_replication: Option<FatalReplicationRx>,
}

/// Operational parameters defining runtime schema verification and failure safety policies.
#[derive(Debug, Clone)]
pub struct EngineSettings {
    /// Strategy to utilize when parsing and matching schema definitions during boot hooks.
    pub schema_mode: SchemaMode,
    /// Bypasses authorization requests or forces failure if replication state trackers fault out.
    pub enable_replication_fail_closed: bool,
}

impl Default for EngineSettings {
    /// Provides default engine execution policies focusing on cautious schema verification
    /// and strict fail-closed safety semantics.
    fn default() -> Self {
        Self {
            schema_mode: SchemaMode::VerifyOnly,
            enable_replication_fail_closed: true,
        }
    }
}

impl LothEngine {
    /// Initializes the engine, builds client attachments, and verifies or applies target schemas.
    ///
    /// # Arguments
    ///
    /// * `cfg` - Path configuration metadata pointing to schemas, access tokens, and server addresses.
    /// * `settings` - Validation behaviors enforcing automatic database provisioning strategies.
    ///
    /// # Errors
    ///
    /// Returns an `AuthError` if connecting to SpiceDB fails, input policy syntax contains
    /// layout bugs, or the initial schema synchronization checks fail.
    pub async fn from_config(
        cfg: LothConfig<'_>,
        settings: EngineSettings,
    ) -> Result<(Self, Arc<SpiceDbClient>), AuthError> {
        let client = SpiceDbClient::connect(&cfg.spicedb_endpoint, &cfg.spicedb_token).await?;

        let zed_schema = match cfg.zed_schema {
            Some(src) => src.load_to_string()?,
            None => DEFAULT_SCHEMA_ZED.to_owned(),
        };

        // Ensure schema so definitions exist (fixes your "object definition not found" errors).
        SchemaManager::new(Arc::clone(&client))
            .ensure_schema(&zed_schema, settings.schema_mode)
            .await?;

        let cedar_policies = match cfg.cedar_policies {
            Some(src) => Some(src.load_to_string()?),
            None => None,
        };

        let rebac = Rebac::new(Arc::clone(&client));
        let abac = AbacEngine::new(cedar_policies.as_deref())?;

        let engine = Self {
            rebac,
            abac,
            zed_schema,
            fatal_replication: None,
        };

        Ok((engine, client))
    }

    /// Attaches replication fail-closed monitoring to the engine.
    ///
    /// # Arguments
    ///
    /// * `fatal_rx` - A watch channel receiver tracking fatal errors occurring in background workers.
    pub fn with_replication_fail_closed(mut self, fatal_rx: FatalReplicationRx) -> Self {
        self.fatal_replication = Some(fatal_rx);
        self
    }

    /// Assembles an unstarted transactional replication data pipeline.
    ///
    /// # Arguments
    ///
    /// * `client` - The reference-counted client pointing to the target cluster connection.
    /// * `queue_capacity` - Total number of event slots allocated inside memory queues before blocking.
    /// * `settings` - Replication throttling policies and transaction boundaries.
    pub fn create_replication(
        &self,
        client: Arc<SpiceDbClient>,
        queue_capacity: usize,
        settings: ReplicationSettings,
    ) -> (ReplicationHandle, crate::replication::ReplicationWorker) {
        replication_pipeline(client, queue_capacity, settings)
    }

    /// Exposes a copy slice of the validated active Zed schema rules.
    pub fn zed_schema(&self) -> &str {
        &self.zed_schema
    }

    /// Enforces short-circuit error paths if attached data replication tasks have crashed.
    ///
    /// # Errors
    ///
    /// Returns an `AuthError` containing structural protocol failure payloads if replication is dead.
    fn fail_closed_if_replication_broken(&self) -> Result<(), AuthError> {
        let Some(rx) = &self.fatal_replication else {
            return Ok(());
        };

        if let Some(err) = rx.borrow().as_ref() {
            return Err(AuthError::spicedb_protocol(
                "check_permission",
                format!("replication is in fatal state: {err}"),
            ));
        }

        Ok(())
    }

    /// Primary permission gateway entrypoint bypassing supplemental Cedar engine attributes.
    ///
    /// # Arguments
    ///
    /// * `user_id` - Unique identity tag pointing to the challenging user subject.
    /// * `action` - The specific operation permission flag name to validate.
    /// * `resource_type` - Categorization namespace of the targeted object type.
    /// * `resource_id` - The identifier matching the specific object instance.
    ///
    /// # Errors
    ///
    /// Returns an `AuthError` if replication streams fail-closed, or connection timeouts occur.
    pub async fn check_permission(
        &self,
        user_id: &str,
        action: &str,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<bool, AuthError> {
        self.check_permission_with_context::<'_, ()>(
            user_id,
            action,
            resource_type,
            resource_id,
            None,
        )
        .await
    }

    /// Primary permission gateway. Combines relational validation with contextual attribute evaluation.
    ///
    /// # Arguments
    ///
    /// * `user_id` - Unique identity tag pointing to the challenging user subject.
    /// * `action` - The specific operation permission flag name to validate.
    /// * `resource_type` - Categorization namespace of the targeted object type.
    /// * `resource_id` - The identifier matching the specific object instance.
    /// * `context` - An optional container carrying extra property attributes evaluated by Cedar.
    ///
    /// # Errors
    ///
    /// Returns an `AuthError` if the backend connection breaks or evaluation context conversions fail.
    pub async fn check_permission_with_context<'a, C>(
        &self,
        user_id: &str,
        action: &str,
        resource_type: &str,
        resource_id: &str,
        context: Option<&'a C>,
    ) -> Result<bool, AuthError>
    where
        C: CedarContext<'a>,
    {
        self.fail_closed_if_replication_broken()?;

        let decision = self
            .rebac
            .check_permission(user_id, action, resource_type, resource_id)
            .await?;

        let is_structural_allowed = matches!(
            decision,
            RebacDecision::Allowed | RebacDecision::Conditional
        );

        self.abac.is_allowed(
            is_structural_allowed,
            user_id,
            action,
            resource_type,
            resource_id,
            context,
        )
    }

    /// Provisions or touches a relationship edge tuple linking a resource to a subject.
    ///
    /// # Arguments
    ///
    /// * `resource_type` - Resource namespace target.
    /// * `resource_id` - Unique identity mapping the target resource item.
    /// * `relation` - The connection relation edge name.
    /// * `subject_type` - Identity namespace matching the target subject type.
    /// * `subject_id` - Core identifier key string pointing to the identity subject.
    ///
    /// # Errors
    ///
    /// Returns an `AuthError` if replication blocks updates or SpiceDB transactional faults occur.
    pub async fn register_relation(
        &self,
        resource_type: &str,
        resource_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<(), AuthError> {
        self.fail_closed_if_replication_broken()?;

        self.rebac
            .write_relationship(
                RelationshipOp::Touch,
                resource_type,
                resource_id,
                relation,
                subject_type,
                subject_id,
            )
            .await
    }

    /// Revokes an exact relationship tuple binding configuration.
    ///
    /// # Arguments
    ///
    /// * `resource_type` - Resource namespace target.
    /// * `resource_id` - Unique identity mapping the target resource item.
    /// * `relation` - The connection relation edge name to sever.
    /// * `subject_type` - Identity namespace matching the target subject type.
    /// * `subject_id` - Core identifier key string pointing to the identity subject.
    ///
    /// # Errors
    ///
    /// Returns an `AuthError` if network paths disconnect or verification filters reject arguments.
    pub async fn revoke_relation(
        &self,
        resource_type: &str,
        resource_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<(), AuthError> {
        self.fail_closed_if_replication_broken()?;

        self.rebac
            .write_relationship(
                RelationshipOp::Delete,
                resource_type,
                resource_id,
                relation,
                subject_type,
                subject_id,
            )
            .await
    }

    /// Performs a bulk prune deletion of relationship edges filtering on flexible subject definitions.
    ///
    /// # Arguments
    ///
    /// * `resource_type` - Resource type identifier constraints.
    /// * `resource_id` - Exact resource ID lookup key boundary.
    /// * `relation` - Target edge descriptor to clean up.
    /// * `subject_type` - Optional type namespace constraint to filter deletions.
    /// * `subject_id` - Optional exact user ID pattern to target for deletion.
    ///
    /// # Returns
    ///
    /// Count of deleted tuples evicted from the graph.
    ///
    /// # Errors
    ///
    /// Returns an `AuthError` if the underlying query engine drops requests.
    pub async fn revoke_by_filter(
        &self,
        resource_type: &str,
        resource_id: &str,
        relation: &str,
        subject_type: Option<&str>,
        subject_id: Option<&str>,
    ) -> Result<u64, AuthError> {
        self.fail_closed_if_replication_broken()?;

        let filter = subject_type.map(|st| SubjectFilter {
            subject_type: st,
            subject_id,
            relation: None,
        });

        self.rebac
            .delete_relationships(resource_type, resource_id, relation, filter)
            .await
    }

    /// Retrieves all object instances of a given type that a user can access.
    ///
    /// # Arguments
    ///
    /// * `user_id` - Target checking subject identifier string.
    /// * `action` - Target resource permission string.
    /// * `resource_type` - Structural resource category layout type.
    ///
    /// # Errors
    ///
    /// Returns an `AuthError` if gRPC streams crash during transit.
    pub async fn lookup_resources(
        &self,
        user_id: &str,
        action: &str,
        resource_type: &str,
    ) -> Result<Vec<String>, AuthError> {
        self.fail_closed_if_replication_broken()?;
        self.rebac
            .lookup_resources(user_id, action, resource_type)
            .await
    }

    /// Live updates Cedar ABAC engine evaluation rule profiles in memory across threads.
    ///
    /// # Arguments
    ///
    /// * `new_policies_dsl` - Optional replacement policy block string. Passing `None` turns off ABAC verification.
    ///
    /// # Errors
    ///
    /// Returns an `AuthError` if syntax compiling rules fail validation checks.
    pub fn update_cedar_policies(&self, new_policies_dsl: Option<&str>) -> Result<(), AuthError> {
        self.abac.update_policies(new_policies_dsl)
    }
}
