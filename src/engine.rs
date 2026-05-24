//! Orchestrates SpiceDB ReBAC + Cedar ABAC.

use crate::cedar::abac::AbacEngine;
use crate::spicedb::client::SpiceDbClient;
use crate::spicedb::rebac::{Rebac, RebacDecision, RelationshipOp, SubjectFilter};
use crate::types::{AuthError, EvaluationContext};

pub struct LothEngine {
    rebac: Rebac,
    abac: AbacEngine,
}

impl LothEngine {
    /// Initializes the engine with SpiceDB credentials and initial Cedar policies.
    pub async fn new(
        spicedb_endpoint: &str,
        spicedb_token: &str,
        cedar_policies_dsl: &str,
    ) -> Result<Self, AuthError> {
        let client = SpiceDbClient::connect(spicedb_endpoint, spicedb_token).await?;
        let rebac = Rebac::new(client);
        let abac = AbacEngine::new(cedar_policies_dsl)?;
        Ok(Self { rebac, abac })
    }

    /// The main gateway gatekeeper. Combines SpiceDB structural check and Cedar contextual evaluation.
    pub async fn check_permission(
        &self,
        user_id: &str,
        action: &str,
        resource_type: &str,
        resource_id: &str,
        context: &EvaluationContext,
    ) -> Result<bool, AuthError> {
        // In the ontology model, action maps to a SpiceDB permission on the resource type.
        // Keep naming aligned: e.g. action="read" => permission "read".
        let decision = self
            .rebac
            .check_permission(user_id, action, resource_type, resource_id)
            .await?;

        let is_structural_allowed = matches!(
            decision,
            RebacDecision::Allowed | RebacDecision::Conditional
        );

        // Cedar is the final edge guardrail. It can deny even if ReBAC allows.
        self.abac.is_allowed(
            is_structural_allowed,
            user_id,
            action,
            resource_type,
            resource_id,
            context,
        )
    }

    /// Registers a security relationship tuple in SpiceDB.
    pub async fn register_relation(
        &self,
        resource_type: &str,
        resource_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<(), AuthError> {
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

    /// Evicts a security relationship tuple from SpiceDB.
    pub async fn revoke_relation(
        &self,
        resource_type: &str,
        resource_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<(), AuthError> {
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

    /// Robust revoke: delete by filter (delete all matching edges).
    ///
    /// Use this when deleting a resource or when you need to unlink unknown/many subjects.
    pub async fn revoke_by_filter(
        &self,
        resource_type: &str,
        resource_id: &str,
        relation: &str,
        subject_type: Option<&str>,
        subject_id: Option<&str>,
    ) -> Result<u64, AuthError> {
        let filter = subject_type.map(|st| SubjectFilter {
            subject_type: st,
            subject_id,
            relation: None,
        });

        self.rebac
            .delete_relationships(resource_type, resource_id, relation, filter)
            .await
    }

    /// Batch: list resource IDs of `resource_type` that `user_id` can perform `action` on.
    pub async fn lookup_resources(
        &self,
        user_id: &str,
        action: &str,
        resource_type: &str,
    ) -> Result<Vec<String>, AuthError> {
        self.rebac
            .lookup_resources(user_id, action, resource_type)
            .await
    }

    /// Dynamically updates Cedar policies.
    pub fn update_cedar_policies(&self, new_policies_dsl: &str) -> Result<(), AuthError> {
        self.abac.update_policies(new_policies_dsl)
    }
}
