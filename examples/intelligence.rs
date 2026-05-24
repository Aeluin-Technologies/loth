//! Intelligence gateway with authorization and replication example.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use tracing::info;

use loth::cedar_context_map;
use loth::engine::{EngineSettings, LothEngine};
use loth::replication::{RelationshipTuple, ReplicationSettings};
use loth::spicedb::schema::SchemaMode;
use loth::types::{AuthError, CedarContext, CedarContextBuilder, LothConfig, TextSource};

/// Context attributes evaluated at the edge by the Cedar policy engine.
#[derive(Debug)]
struct IntelAuthzContext<'a> {
    clearance: &'a str,
    country: &'a str,
    is_onsite: bool,
    is_working_hours: bool,
}

impl<'a> CedarContext<'a> for IntelAuthzContext<'a> {
    /// Maps our application context structures directly into the Cedar dynamic evaluator.
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

/// The main orchestrator setting up our verified ReBAC + ABAC engine environment.
#[tokio::main]
async fn main() -> Result<(), AuthError> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let endpoint = env::var("SPICEDB_ENDPOINT").expect("SPICEDB_ENDPOINT environment variable is required");
    let token = env::var("SPICEDB_TOKEN").expect("SPICEDB_TOKEN environment variable is required");

    // Initialize configuration cleanly using modern idiom patterns
    let cfg = LothConfig::new(endpoint, token)
        .with_cedar_policies(TextSource::from_path("examples/policies/intel.cedar"));

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

    // Spawn the background worker task to process queued updates
    tokio::spawn(async move {
        if let Err(e) = worker.run().await {
            eprintln!("Replication worker encountered a critical error: {e}");
        }
    });

    let q = handle.queue();

    // Batch register structural relationship graphs
    q.upsert_tuple(RelationshipTuple::new("tenant", "t1", "member", "user", "alice")).await?;
    q.upsert_tuple(RelationshipTuple::new("entity_state", "file-742", "parent", "tenant", "t1")).await?;
    q.upsert_tuple(RelationshipTuple::new("entity_state", "file-742", "reader", "user", "alice")).await?;

    // Allow the replication batch task loop to flush to SpiceDB
    tokio::time::sleep(Duration::from_millis(50)).await;

    let valid_ctx = IntelAuthzContext {
        clearance: "secret",
        country: "US",
        is_onsite: true,
        is_working_hours: true,
    };

    // Case 1: Alice has correct structural ReBAC relationships and satisfies context ABAC rules
    let allowed_success = engine
        .check_permission_with_context("alice", "read", "entity_state", "file-742", Some(&valid_ctx))
        .await?;

    info!(user = "alice", allowed = allowed_success, "CASE 1: Valid ReBAC and ABAC context");

    let invalid_ctx = IntelAuthzContext {
        is_working_hours: false, // Fails Cedar criteria check
        ..valid_ctx
    };

    // Case 2: Alice has valid ReBAC structural rights, but is rejected by environmental edge filters
    let allowed_context_fail = engine
        .check_permission_with_context("alice", "read", "entity_state", "file-742", Some(&invalid_ctx))
        .await?;

    info!(user = "alice", allowed = allowed_context_fail, "CASE 2: ReBAC matches, but ABAC filters deny access");

    // Case 3: Bob presents valid environment context tokens, but does not exist on the structural tree path
    let allowed_rebac_fail = engine
        .check_permission_with_context("bob", "read", "entity_state", "file-742", Some(&valid_ctx))
        .await?;

    info!(user = "bob", allowed = allowed_rebac_fail, "CASE 3: ABAC matches, but ReBAC relationship graph denies access");

    handle.shutdown();
    Ok(())
}
