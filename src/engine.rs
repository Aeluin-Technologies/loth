//! Orchestrates SpiceDB ReBAC and Cedar ABAC.

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
/// Combines ReBAC (SpiceDB) with dynamic ABAC (Cedar) policies.
pub struct LothEngine {
    rebac: Rebac,
    abac: AbacEngine,
    zed_schema: String,
    fatal_replication: Option<FatalReplicationRx>,
}

/// Runtime parameters for schema verification and failure safety.
#[derive(Debug, Clone)]
pub struct EngineSettings {
    /// Strategy for schema validation during boot.
    pub schema_mode: SchemaMode,
    /// Whether to enforce fail-closed checks if replication trackers fault.
    pub enable_replication_fail_closed: bool,
}

impl Default for EngineSettings {
    /// Returns default policy: verify schemas and enable fail-closed safety.
    fn default() -> Self {
        Self {
            schema_mode: SchemaMode::VerifyOnly,
            enable_replication_fail_closed: true,
        }
    }
}

impl LothEngine {
    /// Initializes the engine, establishes connections, and synchronizes schemas.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if connection fails or schema/policy validation errors occur.
    pub async fn from_config(
        cfg: LothConfig<'_>,
        settings: EngineSettings,
    ) -> Result<(Self, Arc<SpiceDbClient>), AuthError> {
        let client = SpiceDbClient::connect(&cfg.spicedb_endpoint, &cfg.spicedb_token).await?;

        let zed_schema = match cfg.zed_schema {
            Some(src) => src.load_to_string()?,
            None => DEFAULT_SCHEMA_ZED.to_owned(),
        };

        // Ensure schema exists in the SpiceDB cluster.
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

    /// Attaches a watch channel to monitor replication health for fail-closed checks.
    pub fn with_replication_fail_closed(mut self, fatal_rx: FatalReplicationRx) -> Self {
        self.fatal_replication = Some(fatal_rx);
        self
    }

    /// Creates an unstarted transactional replication pipeline.
    pub fn create_replication(
        &self,
        client: Arc<SpiceDbClient>,
        queue_capacity: usize,
        settings: ReplicationSettings,
    ) -> (ReplicationHandle, crate::replication::ReplicationWorker) {
        replication_pipeline(client, queue_capacity, settings)
    }

    /// Returns a reference to the active Zed schema.
    pub fn zed_schema(&self) -> &str {
        &self.zed_schema
    }

    /// Enforces fail-closed logic if replication state is in a fatal error state.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if replication has faulted.
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

    /// Checks permission using ReBAC only.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` on connection failures or if replication is broken.
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

    /// Checks permission combining ReBAC and contextual Cedar ABAC.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` on connection, evaluation, or replication failures.
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

    /// Registers a new relationship tuple.
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

    /// Revokes an existing relationship tuple.
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

    /// Prunes relationships based on optional subject filters.
    ///
    /// Returns the number of deleted tuples.
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

    /// Retrieves all resources of a given type accessible to a user.
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

    /// Updates Cedar policies in memory.
    pub fn update_cedar_policies(&self, new_policies_dsl: Option<&str>) -> Result<(), AuthError> {
        self.abac.update_policies(new_policies_dsl)
    }
}
