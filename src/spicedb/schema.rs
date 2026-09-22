//! Schema management for SpiceDB.

use std::sync::Arc;

use tonic::Code;
use tracing::{debug, instrument};

use crate::spicedb::client::SpiceDbClient;
use crate::spicedb::pb::authzed::api::v1::consistency::Requirement;
use crate::spicedb::pb::authzed::api::v1::reflection_schema_diff::Diff;
use crate::spicedb::pb::authzed::api::v1::{
    Consistency, DiffSchemaRequest, ReadSchemaRequest, ReflectSchemaRequest, ReflectionCaveat,
    ReflectionSchemaDiff, WriteSchemaRequest,
};
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
    /// Returns `AuthError` if the semantic comparison fails, `VerifyOnly` finds
    /// a functional difference, or the update fails.
    #[instrument(level = "debug", skip(self, desired_schema))]
    pub async fn ensure_schema(
        &self,
        desired_schema: &str,
        mode: SchemaMode,
    ) -> Result<(), AuthError> {
        let req = DiffSchemaRequest {
            consistency: None,
            comparison_schema: desired_schema.to_owned(),
        };
        let mut client = self.client.schema_client().await;
        let has_functional_diff = match client.diff_schema(req).await {
            Ok(response) => {
                let response = response.into_inner();
                let remote_caveats = if has_caveat_expression_diff(&response.diffs) {
                    let consistency = response.read_at.map(|token| Consistency {
                        requirement: Some(Requirement::AtExactSnapshot(token)),
                    });
                    client
                        .reflect_schema(ReflectSchemaRequest {
                            consistency,
                            optional_filters: Vec::new(),
                        })
                        .await
                        .map_err(|status| AuthError::spicedb_status("reflect_schema", status))?
                        .into_inner()
                        .caveats
                } else {
                    Vec::new()
                };

                has_functional_schema_diff(&response.diffs, &remote_caveats)
            }
            Err(status) if status.code() == Code::NotFound => true,
            Err(status) => return Err(AuthError::spicedb_status("diff_schema", status)),
        };
        drop(client);

        if !has_functional_diff {
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

/// Returns whether a structural schema diff contains a functional change.
fn has_functional_schema_diff(
    diffs: &[ReflectionSchemaDiff],
    remote_caveats: &[ReflectionCaveat],
) -> bool {
    diffs.iter().any(|change| match &change.diff {
        Some(
            Diff::DefinitionDocCommentChanged(_)
            | Diff::RelationDocCommentChanged(_)
            | Diff::PermissionDocCommentChanged(_)
            | Diff::CaveatDocCommentChanged(_),
        ) => false,
        Some(Diff::CaveatExprChanged(candidate)) => remote_caveats
            .iter()
            .find(|current| current.name == candidate.name)
            .is_none_or(|current| current.expression != candidate.expression),
        Some(_) | None => true,
    })
}

fn has_caveat_expression_diff(diffs: &[ReflectionSchemaDiff]) -> bool {
    diffs
        .iter()
        .any(|change| matches!(change.diff, Some(Diff::CaveatExprChanged(_))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spicedb::pb::authzed::api::v1::{
        ReflectionDefinition, ReflectionPermission, ReflectionRelation,
    };

    #[test]
    fn semantic_diff_ignores_documentation_comments() {
        let diffs = [
            ReflectionSchemaDiff {
                diff: Some(Diff::DefinitionDocCommentChanged(ReflectionDefinition {
                    name: "document".to_owned(),
                    comment: "// documentation".to_owned(),
                    relations: Vec::new(),
                    permissions: Vec::new(),
                })),
            },
            ReflectionSchemaDiff {
                diff: Some(Diff::RelationDocCommentChanged(ReflectionRelation {
                    name: "reader".to_owned(),
                    comment: "// documentation".to_owned(),
                    parent_definition_name: "document".to_owned(),
                    subject_types: Vec::new(),
                })),
            },
            ReflectionSchemaDiff {
                diff: Some(Diff::PermissionDocCommentChanged(ReflectionPermission {
                    name: "read".to_owned(),
                    comment: "// documentation".to_owned(),
                    parent_definition_name: "document".to_owned(),
                })),
            },
            ReflectionSchemaDiff {
                diff: Some(Diff::CaveatDocCommentChanged(ReflectionCaveat {
                    name: "some_caveat".to_owned(),
                    comment: "// documentation".to_owned(),
                    parameters: Vec::new(),
                    expression: "true".to_owned(),
                })),
            },
        ];

        assert!(!has_functional_schema_diff(&diffs, &[]));
    }

    #[test]
    fn semantic_diff_detects_permission_expression_changes() {
        let diffs = [ReflectionSchemaDiff {
            diff: Some(Diff::PermissionExprChanged(ReflectionPermission {
                name: "read".to_owned(),
                comment: String::new(),
                parent_definition_name: "document".to_owned(),
            })),
        }];

        assert!(has_functional_schema_diff(&diffs, &[]));
    }

    #[test]
    fn semantic_diff_compares_reflected_caveat_expressions() {
        let changed_caveat = ReflectionCaveat {
            name: "enabled".to_owned(),
            comment: String::new(),
            parameters: Vec::new(),
            expression: "flag".to_owned(),
        };
        let diffs = [ReflectionSchemaDiff {
            diff: Some(Diff::CaveatExprChanged(changed_caveat.clone())),
        }];

        assert!(!has_functional_schema_diff(
            &diffs,
            std::slice::from_ref(&changed_caveat),
        ));

        let remote_caveat = ReflectionCaveat {
            expression: "!flag".to_owned(),
            ..changed_caveat
        };
        assert!(has_functional_schema_diff(&diffs, &[remote_caveat]));
    }
}
