use chrono::Utc;
use std::net::IpAddr;

use loth::engine::LothEngine;
use loth::types::EvaluationContext;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cedar_policies = r#"
        permit(
            principal == User::"u_1",
            action == Action::"read",
            resource
        )
        when {
            context.is_structural_allowed == true &&
            context.device_compliant == true
        };
    "#;

    let spicedb_endpoint = "http://127.0.0.1:50051";
    let spicedb_token = "foobar_secret_token";

    println!("Initializing LothEngine...");

    let engine = LothEngine::new(spicedb_endpoint, spicedb_token, cedar_policies).await?;
    engine
        .register_relation("entity", "ent_7", "parent_project", "project", "p_42")
        .await?;
    engine
        .register_relation("project", "p_42", "member", "user", "u_1")
        .await?;

    let context_valid = EvaluationContext {
        ip_address: "192.168.1.50".parse::<IpAddr>()?,
        timestamp: Utc::now(),
        device_compliant: true, // Device is healthy
    };

    let context_compromised = EvaluationContext {
        ip_address: "192.168.1.99".parse::<IpAddr>()?,
        timestamp: Utc::now(),
        device_compliant: false, // Device compromised
    };

    println!("\n--- Evaluation Phase ---");

    let allowed_1 = engine
        .check_permission("u_1", "read", "entity", "ent_7", &context_valid)
        .await?;
    println!(
        "Result Case 1 (Compliant): {}",
        if allowed_1 {
            "GRANTED ✅"
        } else {
            "DENIED ❌"
        }
    );

    let allowed_2 = engine
        .check_permission("u_1", "read", "entity", "ent_7", &context_compromised)
        .await?;
    println!(
        "Result Case 2 (Compromised): {}",
        if allowed_2 {
            "GRANTED ✅"
        } else {
            "DENIED ❌"
        }
    );

    println!("\nRevoking project membership...");
    engine
        .revoke_relation("project", "p_42", "member", "user", "u_1")
        .await?;

    let allowed_3 = engine
        .check_permission("u_1", "read", "entity", "ent_7", &context_valid)
        .await?;
    println!(
        "Result Case 3 (After ReBAC Revocation): {}",
        if allowed_3 {
            "GRANTED ✅"
        } else {
            "DENIED ❌"
        }
    );

    Ok(())
}
