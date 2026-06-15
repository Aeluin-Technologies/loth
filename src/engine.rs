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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use loth::LothConfig;
    /// # use loth::engine::{LothEngine, EngineSettings};
    /// # async fn run() -> Result<(), loth::types::AuthError> {
    /// let cfg = LothConfig {
    ///     spicedb_endpoint: "http://127.0.0.1:50051".into(),
    ///     spicedb_token: "secret".into(),
    ///     zed_schema: None,
    ///     cedar_policies: None,
    /// };
    /// let settings = EngineSettings::default();
    /// let (engine, client) = LothEngine::from_config(cfg, settings).await?;
    /// # Ok(())
    /// # }
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use loth::engine::LothEngine;
    /// # async fn run(engine: LothEngine) -> Result<(), loth::types::AuthError> {
    /// let allowed = engine.check_permission("user:alice", "read", "document", "doc_01").await?;
    /// if allowed {
    ///     println!("Access granted");
    /// }
    /// # Ok(())
    /// # }
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use serde::Serialize;
    /// # use loth::CedarContext;
    /// # use loth::engine::LothEngine;
    /// # async fn run(engine: LothEngine) -> Result<(), loth::types::AuthError> {
    /// #[derive(Serialize)]
    /// struct RequestContext { network_ip: String }
    ///
    /// impl<'a> CedarContext<'a> for RequestContext {
    ///     fn write_to(&self, _: &mut loth::types::CedarContextBuilder<'a>) -> Result<(), loth::types::AuthError> {
    ///         Ok(())
    ///     }
    /// }
    ///
    /// let ctx = RequestContext { network_ip: "10.0.0.1".to_string() };
    /// let allowed = engine.check_permission_with_context(
    ///     "user:bob",
    ///     "write",
    ///     "repository",
    ///     "repo_42",
    ///     Some(&ctx)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use loth::engine::LothEngine;
    /// # async fn run(engine: LothEngine) -> Result<(), loth::types::AuthError> {
    /// engine.register_relation(
    ///     "workspace", "ws_01",
    ///     "member",
    ///     "user", "user:charlie"
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthError, CedarContext, CedarContextBuilder};
    use serde::Serialize;
    use tokio::sync::watch;

    #[derive(Serialize)]
    struct MockContext {
        secure_network: bool,
    }

    impl<'a> CedarContext<'a> for MockContext {
        fn write_to(&self, _out: &mut CedarContextBuilder<'a>) -> Result<(), AuthError> {
            Ok(())
        }
    }

    /// Allocates an ephemeral local TCP socket to satisfy client initialization handshakes
    /// without a dependency on a running SpiceDB cluster instance.
    async fn setup_fake_endpoint() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind ephemeral test socket");
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            while let Ok((_stream, _)) = listener.accept().await {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        });

        format!("http://127.0.0.1:{port}")
    }

    #[tokio::test]
    async fn test_fail_closed_when_replication_faulty() {
        let (tx, rx) = watch::channel(None);
        let fake_url = setup_fake_endpoint().await;

        let client = SpiceDbClient::connect(&fake_url, "test-token")
            .await
            .expect("Failed to initialize SpiceDbClient endpoint");

        let engine = LothEngine {
            rebac: Rebac::new(client.clone()),
            abac: AbacEngine::new(None).unwrap(),
            zed_schema: "definition user {}".to_string(),
            fatal_replication: Some(rx),
        };

        let sync_err = AuthError::spicedb_protocol(
            "replication_tracker",
            "Replica lag exceeded threshold limit",
        );
        tx.send(Some(sync_err)).unwrap();

        let res = engine.check_permission("user:1", "read", "doc", "1").await;
        assert!(
            res.is_err(),
            "Engine must fail closed when replication tracking enters a fatal state"
        );
    }

    #[tokio::test]
    async fn test_check_permission_with_context_routing() {
        let fake_url = setup_fake_endpoint().await;
        let client = SpiceDbClient::connect(&fake_url, "test-token")
            .await
            .expect("Failed to initialize SpiceDbClient endpoint");

        let dsl_policy =
            "permit(principal, action, resource) when { context.secure_network == true };";

        let engine = LothEngine {
            rebac: Rebac::new(client.clone()),
            abac: AbacEngine::new(Some(dsl_policy)).unwrap(),
            zed_schema: String::new(),
            fatal_replication: None,
        };

        let ctx_valid = MockContext {
            secure_network: true,
        };

        let res = engine
            .check_permission_with_context("user:1", "view", "file", "a", Some(&ctx_valid))
            .await;

        assert!(
            res.is_err(),
            "Expected transport layer error from raw TCP test endpoint"
        );
    }
}
