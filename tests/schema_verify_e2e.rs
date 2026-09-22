use loth::engine::{EngineSettings, LothEngine};
use loth::types::AuthError;
use loth::{LothConfig, SchemaManager, SchemaMode, TextSource};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, Instant, sleep};

const SPICEDB_TOKEN: &str = "loth-e2e-test-key";
const SPICEDB_GRPC_PORT: u16 = 50051;

const STORED_SCHEMA: &str = r#"
definition user {}

caveat enabled(flag bool) {
  flag
}

definition document {
  relation viewer: user with enabled
  relation editor: user

  permission view = viewer + editor
}
"#;

const EQUIVALENT_SCHEMA: &str = r#"
// Definitions, relations, and caveats deliberately use a different order.
definition document {
  relation editor: user

  // This comment is not present in the stored schema.
  relation viewer: user with enabled
  permission view = viewer + editor
}

caveat enabled(flag bool) { flag }

definition user {}
"#;

const FUNCTIONALLY_DIFFERENT_SCHEMA: &str = r#"
definition document {
  relation editor: user
  relation viewer: user with enabled

  permission view = viewer
}

caveat enabled(flag bool) { flag }
definition user {}
"#;

const FUNCTIONALLY_DIFFERENT_CAVEAT_SCHEMA: &str = r#"
definition document {
  relation editor: user
  relation viewer: user with enabled

  permission view = viewer + editor
}

caveat enabled(flag bool) { !flag }
definition user {}
"#;

#[tokio::test]
async fn verify_only_accepts_semantically_equivalent_schema_during_boot() {
    let container = GenericImage::new("authzed/spicedb", "v1.56.2")
        .with_exposed_port(SPICEDB_GRPC_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stderr("grpc server started serving"))
        .with_env_var("SPICEDB_GRPC_PRESHARED_KEY", SPICEDB_TOKEN)
        .with_env_var("SPICEDB_DATASTORE_ENGINE", "memory")
        .with_env_var("SPICEDB_TELEMETRY_ENDPOINT", "")
        .with_cmd(["serve"])
        .start()
        .await
        .expect("SpiceDB container should start");

    let host_port = container
        .get_host_port_ipv4(SPICEDB_GRPC_PORT.tcp())
        .await
        .expect("SpiceDB gRPC port should be mapped");
    wait_for_spicedb(host_port).await;
    let endpoint = format!("http://127.0.0.1:{host_port}");

    let apply_settings = EngineSettings {
        schema_mode: SchemaMode::ApplyIfDifferent,
        ..EngineSettings::default()
    };
    let (_, client) = LothEngine::from_config(config(&endpoint, STORED_SCHEMA), apply_settings)
        .await
        .expect("initial schema should be applied");
    let remote_schema = SchemaManager::new(client)
        .read_schema()
        .await
        .expect("applied schema should be readable");
    assert_ne!(
        remote_schema, EQUIVALENT_SCHEMA,
        "the test must compare textually distinct schemas"
    );

    LothEngine::from_config(
        config(&endpoint, EQUIVALENT_SCHEMA),
        EngineSettings::default(),
    )
    .await
    .expect("VerifyOnly boot should accept a semantically equivalent schema");

    assert_verify_only_rejects(&endpoint, FUNCTIONALLY_DIFFERENT_SCHEMA).await;
    assert_verify_only_rejects(&endpoint, FUNCTIONALLY_DIFFERENT_CAVEAT_SCHEMA).await;
}

async fn assert_verify_only_rejects(endpoint: &str, schema: &'static str) {
    let mismatch =
        LothEngine::from_config(config(endpoint, schema), EngineSettings::default()).await;
    let error = match mismatch {
        Err(error) => error,
        Ok(_) => panic!("VerifyOnly boot should reject a functional schema change"),
    };

    assert!(matches!(
        error,
        AuthError::SpiceDbProtocol {
            operation: "ensure_schema",
            message,
        } if message == "spicedb schema mismatch (VerifyOnly)"
    ));
}

fn config(endpoint: &str, schema: &'static str) -> LothConfig<'static> {
    LothConfig::new(endpoint.to_owned(), SPICEDB_TOKEN)
        .with_zed_schema(TextSource::from_inline(schema))
}

async fn wait_for_spicedb(host_port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);

    loop {
        match TcpStream::connect(("127.0.0.1", host_port)).await {
            Ok(_) => return,
            Err(_) if Instant::now() < deadline => {
                sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("SpiceDB did not accept connections before timeout: {error}"),
        }
    }
}
