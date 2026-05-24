//! Cedar ABAC policy engine wrapper.
//!
//! ABAC is used as the final contextual filter at the edge; ReBAC remains the
//! source of structural truth.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, RestrictedExpression,
};

use crate::types::{AuthError, EvaluationContext};

pub struct AbacEngine {
    policies: ArcSwap<PolicySet>,
    authorizer: Authorizer,
}

impl AbacEngine {
    pub fn new(initial_policies_dsl: &str) -> Result<Self, AuthError> {
        let policies = parse_policies(initial_policies_dsl)?;
        Ok(Self {
            policies: ArcSwap::from(Arc::new(policies)),
            authorizer: Authorizer::new(),
        })
    }

    pub fn update_policies(&self, new_policies_dsl: &str) -> Result<(), AuthError> {
        let next = parse_policies(new_policies_dsl)?;
        self.policies.store(Arc::new(next));
        Ok(())
    }

    pub fn is_allowed(
        &self,
        is_structural_allowed: bool,
        user_id: &str,
        action: &str,
        resource_type: &str,
        resource_id: &str,
        ctx: &EvaluationContext,
    ) -> Result<bool, AuthError> {
        let principal = parse_uid("User", user_id)?;
        let action_uid = parse_uid("Action", action)?;
        let resource = parse_uid(resource_type, resource_id)?;
        let mut context_map = HashMap::new();

        context_map.insert(
            "is_structural_allowed".to_string(),
            RestrictedExpression::new_bool(is_structural_allowed),
        );
        context_map.insert(
            "device_compliant".to_string(),
            RestrictedExpression::new_bool(ctx.device_compliant),
        );
        context_map.insert(
            "ip_address".to_string(),
            RestrictedExpression::new_string(ctx.ip_address.to_string()),
        );
        context_map.insert(
            "timestamp_rfc3339".to_string(),
            RestrictedExpression::new_string(ctx.timestamp.to_rfc3339()),
        );

        let cedar_ctx = Context::from_pairs(context_map).map_err(AuthError::cedar)?;

        let req = Request::new(principal, action_uid, resource, cedar_ctx, None)
            .map_err(AuthError::cedar)?;

        let policies = self.policies.load_full();
        let entities = Entities::empty();

        let resp = self
            .authorizer
            .is_authorized(&req, policies.as_ref(), &entities);
        Ok(matches!(resp.decision(), Decision::Allow))
    }
}

fn parse_policies(dsl: &str) -> Result<PolicySet, AuthError> {
    dsl.parse::<PolicySet>().map_err(AuthError::validation)
}

fn parse_uid(entity_type: &str, entity_id: &str) -> Result<EntityUid, AuthError> {
    let mut s = String::with_capacity(entity_type.len() + entity_id.len() + 6);
    s.push_str(entity_type);
    s.push_str("::\"");
    s.push_str(entity_id);
    s.push('"');
    s.parse::<EntityUid>().map_err(AuthError::validation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn abac_denies_when_policy_requires_structural_true() {
        let policies = r#"
          permit(principal, action, resource)
          when { context.is_structural_allowed == true };
        "#;

        let engine = AbacEngine::new(policies).expect("engine");

        let ctx = EvaluationContext {
            ip_address: "203.0.113.10".parse().expect("ip"),
            timestamp: chrono::Utc.with_ymd_and_hms(2026, 5, 24, 12, 0, 0).unwrap(),
            device_compliant: true,
        };

        let ok = engine
            .is_allowed(false, "u1", "read", "entity", "e1", &ctx)
            .expect("cedar");
        assert!(!ok);
    }
}
