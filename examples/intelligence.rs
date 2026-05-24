//! Example: "intel gateway" authorization + replication.

use std::borrow::Cow;
use std::env;
use std::sync::Arc;
use std::time::Duration;

use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;

use loth::cedar_context_map;
use loth::engine::{EngineSettings, LothEngine};
use loth::replication::{RelationshipTuple, ReplicationSettings};
use loth::spicedb::schema::SchemaMode;
use loth::types::{AuthError, CedarContext, CedarContextBuilder, LothConfig, TextSource};

#[derive(Debug)]
struct IntelAuthzContext<'a> {
    clearance: &'a str, // "confidential" | "secret" | "top_secret"
    country: &'a str,   // "US", "FR", ...
    is_onsite: bool,
    is_working_hours: bool,
}

impl<'a> CedarContext<'a> for IntelAuthzContext<'a> {
    fn write_to(&self, out: &mut CedarContextBuilder<'a>) -> Result<(), AuthError> {
        cedar_context_map!(out, self, {
            "clearance" => str self.clearance,
            "country" => str self.country,
            "is_onsite" => bool self.is_onsite,
            "is_working_hours" => bool self.is_working_hours,
        });
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), AuthError> {
    init_tracing();

    let endpoint = env::var("SPICEDB_ENDPOINT").expect("SPICEDB_ENDPOINT is required");
    let token = env::var("SPICEDB_TOKEN").expect("SPICEDB_TOKEN is required");

    let cedar_policy = Some(TextSource::from_path("examples/policies/intel.cedar"));

    let cfg = {
        let mut c = LothConfig::new(Cow::from(endpoint.clone()), Cow::from(token.clone()));
        if let Some(p) = cedar_policy {
            c = c.with_cedar_policies(p);
        }
        c
    };

    let settings = EngineSettings {
        schema_mode: SchemaMode::ApplyIfDifferent,
        enable_replication_fail_closed: true,
    };

    let (engine, client) = LothEngine::from_config(cfg, settings).await?;
    let (handle, worker) = engine.create_replication(
        Arc::clone(&client),
        4096,
        ReplicationSettings {
            max_batch: 256,
            flush_interval: Duration::from_millis(5),
            max_retries: 12,
            base_backoff: Duration::from_millis(25),
        },
    );

    let engine = engine.with_replication_fail_closed(handle.fatal_rx());

    tokio::spawn(async move {
        if let Err(e) = worker.run().await {
            eprintln!("replication worker stopped: {e}");
        }
    });

    let q = handle.queue();

    q.upsert_tuple(RelationshipTuple::new(
        "tenant", "t1", "member", "user", "alice",
    ))
    .await?;
    q.upsert_tuple(RelationshipTuple::new(
        "entity_state",
        "file-742",
        "parent",
        "tenant",
        "t1",
    ))
    .await?;
    q.upsert_tuple(RelationshipTuple::new(
        "entity_state",
        "file-742",
        "reader",
        "user",
        "alice",
    ))
    .await?;

    // Note: 'bob' is never given any relationship tuples targeting file-742.

    tokio::time::sleep(Duration::from_millis(50)).await;

    let valid_ctx = IntelAuthzContext {
        clearance: "secret",
        country: "US",
        is_onsite: true,
        is_working_hours: true, // she worked at 9:00am.
    };

    let allowed_success = engine
        .check_permission_with_context(
            "alice",
            "read",
            "entity_state",
            "file-742",
            Some(&valid_ctx),
        )
        .await?;

    info!(
        user = "alice",
        allowed = allowed_success,
        reason = "Valid ReBAC permissions and fully satisfying ABAC Cedar context",
        "CASE 1"
    );

    let invalid_ctx = IntelAuthzContext {
        clearance: "secret",
        country: "US",
        is_onsite: true,
        is_working_hours: false, // trigger Cedar policy failure.
    };

    let allowed_context_fail = engine
        .check_permission_with_context(
            "alice",
            "read",
            "entity_state",
            "file-742",
            Some(&invalid_ctx),
        )
        .await?;

    info!(
        user = "alice",
        allowed = allowed_context_fail,
        reason = "Has SpiceDB relationship permissions, but fails ABAC context criteria (is_working_hours = false)",
        "CASE 2"
    );

    // Bob has valid context variables, but no graph connection.
    let allowed_rebac_fail = engine
        .check_permission_with_context("bob", "read", "entity_state", "file-742", Some(&valid_ctx))
        .await?;

    info!(
        user = "bob",
        allowed = allowed_rebac_fail,
        reason = "Fails because user 'bob' has no reader or membership relation linked to this entity in SpiceDB",
        "CASE 3"
    );

    handle.shutdown();
    Ok(())
}

fn init_tracing() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}
