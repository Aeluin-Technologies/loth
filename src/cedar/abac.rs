//! Cedar ABAC policy engine wrapper.
//!
//! ABAC acts as the final contextual filter; ReBAC serves as the structural truth.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, RestrictedExpression,
};

use crate::types::{AuthError, CedarContext, CedarContextBuilder, CedarValueRef};

/// ABAC engine powered by the Cedar policy language.
///
/// Combines structural ReBAC verdicts with dynamic context to make authorization decisions.
/// Supports thread-safe runtime policy hot-swapping.
pub struct AbacEngine {
    policies: ArcSwapOption<PolicySet>,
    authorizer: Authorizer,
}

impl AbacEngine {
    /// Initializes the engine with optional Cedar policies.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if policy syntax is invalid.
    pub fn new(initial_policies_dsl: Option<&str>) -> Result<Self, AuthError> {
        let policies = match initial_policies_dsl {
            Some(dsl) => Some(Arc::new(parse_policies(dsl)?)),
            None => None,
        };

        Ok(Self {
            policies: ArcSwapOption::from(policies),
            authorizer: Authorizer::new(),
        })
    }

    /// Hot-swaps the active policy set.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if the new policies fail compilation.
    pub fn update_policies(&self, new_policies_dsl: Option<&str>) -> Result<(), AuthError> {
        let next = match new_policies_dsl {
            Some(dsl) => Some(Arc::new(parse_policies(dsl)?)),
            None => None,
        };

        self.policies.store(next);
        Ok(())
    }

    /// Evaluates access based on ReBAC results and optional attributes.
    ///
    /// If no policies are loaded, returns `is_structural_allowed` directly (passthrough).
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if entity parsing or context building fails.
    pub fn is_allowed<'a, C>(
        &self,
        is_structural_allowed: bool,
        user_id: &str,
        action: &str,
        resource_type: &str,
        resource_id: &str,
        ctx: Option<&'a C>,
    ) -> Result<bool, AuthError>
    where
        C: CedarContext<'a>,
    {
        let Some(policies) = self.policies.load_full() else {
            return Ok(is_structural_allowed);
        };

        let principal = parse_uid("User", user_id)?;
        let action_uid = parse_uid("Action", action)?;
        let resource = parse_uid(resource_type, resource_id)?;

        let mut builder = CedarContextBuilder::with_capacity(8);
        builder.insert_bool("is_structural_allowed", is_structural_allowed);

        if let Some(ctx) = ctx {
            ctx.write_to(&mut builder)?;
        }

        let cedar_ctx = build_cedar_context(&builder)?;
        let req = Request::new(principal, action_uid, resource, cedar_ctx, None)
            .map_err(AuthError::cedar_eval)?;

        let entities = Entities::empty();
        let resp = self
            .authorizer
            .is_authorized(&req, policies.as_ref(), &entities);

        Ok(matches!(resp.decision(), Decision::Allow))
    }
}

/// Converts a `CedarContextBuilder` into a native Cedar `Context`.
fn build_cedar_context(b: &CedarContextBuilder<'_>) -> Result<Context, AuthError> {
    let mut map: HashMap<String, RestrictedExpression> = HashMap::with_capacity(b.entries.len());

    for (k, v) in b.entries.iter() {
        let expr = match v {
            CedarValueRef::Bool(x) => RestrictedExpression::new_bool(*x),
            CedarValueRef::I64(x) => RestrictedExpression::new_long(*x),
            CedarValueRef::Str(s) => RestrictedExpression::new_string((*s).to_owned()),
        };
        map.insert((*k).to_owned(), expr);
    }

    Context::from_pairs(map).map_err(AuthError::cedar_eval)
}

/// Parses raw Cedar DSL into a `PolicySet`.
fn parse_policies(dsl: &str) -> Result<PolicySet, AuthError> {
    dsl.parse::<PolicySet>()
        .map_err(AuthError::cedar_validation)
}

/// Parses an `EntityUid` from a type and ID string.
fn parse_uid(entity_type: &str, entity_id: &str) -> Result<EntityUid, AuthError> {
    let mut s = String::with_capacity(entity_type.len() + entity_id.len() + 6);
    s.push_str(entity_type);
    s.push_str("::\"");
    s.push_str(entity_id);
    s.push('"');
    s.parse::<EntityUid>().map_err(AuthError::cedar_validation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cedar_context_map,
        types::{AuthError, CedarContext},
    };

    #[derive(Debug)]
    struct DemoCtx<'a> {
        ip: &'a str,
        hour: i64,
    }

    impl<'a> CedarContext<'a> for DemoCtx<'a> {
        fn write_to(
            &self,
            out: &mut crate::types::CedarContextBuilder<'a>,
        ) -> Result<(), AuthError> {
            cedar_context_map!(out, self, {
                "ip" => str self.ip,
                "hour" => i64 self.hour,
            });
            Ok(())
        }
    }

    #[test]
    fn abac_disabled_passthrough() -> Result<(), AuthError> {
        let engine = AbacEngine::new(None)?;
        let ok = engine.is_allowed::<()>(true, "u1", "read", "entity", "e1", None)?;
        assert!(ok);
        Ok(())
    }

    #[test]
    fn abac_denies_when_policy_requires_structural_true() -> Result<(), AuthError> {
        let policies = r#"
          permit(principal, action, resource)
          when { context.is_structural_allowed == true };
        "#;

        let engine = AbacEngine::new(Some(policies))?;

        let ctx = DemoCtx {
            ip: "203.0.113.10",
            hour: 12,
        };

        let ok = engine.is_allowed(false, "u1", "read", "entity", "e1", Some(&ctx))?;
        assert!(!ok);
        Ok(())
    }
}
