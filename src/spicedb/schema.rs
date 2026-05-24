//! Schema management for SpiceDB.

use std::sync::Arc;

use tracing::{debug, instrument};

use crate::spicedb::client::SpiceDbClient;
use crate::spicedb::pb::authzed::api::v1::{ReadSchemaRequest, WriteSchemaRequest};
use crate::types::AuthError;

/// Defines how schema discrepancies are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaMode {
    /// Verify schema matches; fail on mismatch.
    VerifyOnly,
    /// Apply new schema if a mismatch is detected.
    ApplyIfDifferent,
}

/// Manages reading, writing, and validating SpiceDB schemas.
pub struct SchemaManager {
    client: Arc<SpiceDbClient>,
}

impl SchemaManager {
    /// Creates a new `SchemaManager`.
    pub fn new(client: Arc<SpiceDbClient>) -> Self {
        Self { client }
    }

    /// Ensures the remote SpiceDB schema matches the provided target.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if `VerifyOnly` fails or the update fails.
    #[instrument(level = "debug", skip(self, desired_schema))]
    pub async fn ensure_schema(
        &self,
        desired_schema: &str,
        mode: SchemaMode,
    ) -> Result<(), AuthError> {
        let existing = self.read_schema().await.unwrap_or_default();

        if normalize_schema(&existing) == normalize_schema(desired_schema) {
            debug!("spicedb schema already matches desired schema");
            return Ok(());
        }

        match mode {
            SchemaMode::VerifyOnly => Err(AuthError::spicedb_protocol(
                "ensure_schema",
                "spicedb schema mismatch (VerifyOnly)",
            )),
            SchemaMode::ApplyIfDifferent => self.write_schema(desired_schema).await,
        }
    }

    /// Fetches the active schema text from the SpiceDB instance.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if the gRPC call fails.
    #[instrument(level = "debug", skip(self))]
    pub async fn read_schema(&self) -> Result<String, AuthError> {
        let req = ReadSchemaRequest {};
        let mut client = self.client.schema_client().await;
        let resp = client
            .read_schema(req)
            .await
            .map_err(|s| AuthError::spicedb_status("read_schema", s))?
            .into_inner();

        Ok(resp.schema_text)
    }

    /// Overwrites the remote schema with the provided text.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if the schema is invalid or the write fails.
    #[instrument(level = "debug", skip(self, schema_text))]
    pub async fn write_schema(&self, schema_text: &str) -> Result<(), AuthError> {
        let req = WriteSchemaRequest {
            schema: schema_text.to_owned(),
        };

        let mut client = self.client.schema_client().await;
        client
            .write_schema(req)
            .await
            .map_err(|s| AuthError::spicedb_status("write_schema", s))?;

        Ok(())
    }
}

/// Normalizes schema by stripping trailing whitespace and removing empty lines.
fn normalize_schema(s: &str) -> String {
    s.lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_schema_removes_empty_lines_and_trailing_ws() {
        let a = "definition user {}\n\n  \n";
        let b = "definition user {}\n";
        assert_eq!(normalize_schema(a), normalize_schema(b));
    }
}
