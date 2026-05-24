//! High-level ReBAC API for SpiceDB (Authzed API).

use std::sync::Arc;

use tokio_stream::StreamExt;
use tracing::instrument;

use crate::spicedb::client::SpiceDbClient;
use crate::spicedb::pb::authzed::api::v1::{
    SubjectFilter as SubjectFilterProto, check_permission_response, relationship_update,
    subject_filter as proto_subject_filter, *,
};
use crate::types::AuthError;

/// Default schema for bootstrapping SpiceDB authorization models.
pub const DEFAULT_SCHEMA_ZED: &str = include_str!("../../schema.zed");

/// A high-level client wrapper for Relationship-Based Access Control (ReBAC) operations.
pub struct Rebac {
    client: Arc<SpiceDbClient>,
}

impl Rebac {
    /// Creates a new `Rebac` abstraction layer.
    pub fn new(client: Arc<SpiceDbClient>) -> Self {
        Self { client }
    }

    /// Writes a batch of relationship updates in a single RPC transaction.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if the RPC fails or updates conflict.
    #[instrument(level = "debug", skip(self, updates), fields(count = updates.len()))]
    pub async fn write_relationships_batch(
        &self,
        updates: Vec<RelationshipUpdate>,
    ) -> Result<(), AuthError> {
        if updates.is_empty() {
            return Ok(());
        }

        let req = WriteRelationshipsRequest {
            updates,
            optional_preconditions: Vec::new(),
            ..Default::default()
        };

        let mut client = self.client.permissions_client().await;
        client
            .write_relationships(req)
            .await
            .map_err(|s| AuthError::spicedb_status("write_relationships", s))?;
        Ok(())
    }

    /// Checks if a user has a specific permission on a resource.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if the gRPC interface fails or response status is unknown.
    #[instrument(
        level = "debug",
        skip(self),
        fields(resource_type, resource_id, permission, user_id)
    )]
    pub async fn check_permission(
        &self,
        user_id: &str,
        permission: &str,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<RebacDecision, AuthError> {
        let req = CheckPermissionRequest {
            resource: Some(ObjectReference {
                object_type: resource_type.to_owned(),
                object_id: resource_id.to_owned(),
            }),
            permission: permission.to_owned(),
            subject: Some(SubjectReference {
                object: Some(ObjectReference {
                    object_type: "user".to_owned(),
                    object_id: user_id.to_owned(),
                }),
                optional_relation: String::new(),
            }),
            consistency: None,
            context: None,
            with_tracing: false,
        };

        let mut client = self.client.permissions_client().await;
        let resp = client
            .check_permission(req)
            .await
            .map_err(|s| AuthError::spicedb_status("check_permission", s))?
            .into_inner();

        let membership = check_permission_response::Permissionship::try_from(resp.permissionship)
            .unwrap_or(check_permission_response::Permissionship::Unspecified);

        match membership {
            check_permission_response::Permissionship::HasPermission => Ok(RebacDecision::Allowed),
            check_permission_response::Permissionship::NoPermission => Ok(RebacDecision::Denied),
            check_permission_response::Permissionship::ConditionalPermission => {
                Ok(RebacDecision::Conditional)
            }
            check_permission_response::Permissionship::Unspecified => {
                Err(AuthError::spicedb_protocol(
                    "check_permission",
                    "unknown permissionship returned by server",
                ))
            }
        }
    }

    /// Creates or updates a single relationship tuple.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if the operation fails schema constraints or RPC communication.
    #[instrument(
        level = "debug",
        skip(self),
        fields(resource_type, resource_id, relation, subject_type, subject_id)
    )]
    pub async fn write_relationship(
        &self,
        op: RelationshipOp,
        resource_type: &str,
        resource_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<(), AuthError> {
        let relationship = Relationship {
            resource: Some(ObjectReference {
                object_type: resource_type.to_owned(),
                object_id: resource_id.to_owned(),
            }),
            relation: relation.to_owned(),
            subject: Some(SubjectReference {
                object: Some(ObjectReference {
                    object_type: subject_type.to_owned(),
                    object_id: subject_id.to_owned(),
                }),
                optional_relation: String::new(),
            }),
            optional_caveat: None,
            optional_expires_at: None,
        };

        let update = RelationshipUpdate {
            operation: op.to_proto_i32(),
            relationship: Some(relationship),
        };

        self.write_relationships_batch(vec![update]).await
    }

    /// Deletes relationships matching the specified resource and filters.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if the backend query engine fails.
    #[instrument(
        level = "debug",
        skip(self),
        fields(resource_type, resource_id, relation)
    )]
    pub async fn delete_relationships(
        &self,
        resource_type: &str,
        resource_id: &str,
        relation: &str,
        subject_filter: Option<SubjectFilter<'_>>,
    ) -> Result<u64, AuthError> {
        let filter = RelationshipFilter {
            resource_type: resource_type.to_owned(),
            optional_resource_id: resource_id.to_owned(),
            optional_relation: relation.to_owned(),
            optional_resource_id_prefix: String::new(),
            optional_subject_filter: subject_filter.map(|sf| SubjectFilterProto {
                subject_type: sf.subject_type.to_owned(),
                optional_subject_id: sf.subject_id.unwrap_or_default().to_owned(),
                optional_relation: sf.relation.map(|r| proto_subject_filter::RelationFilter {
                    relation: r.to_owned(),
                }),
            }),
        };

        let req = DeleteRelationshipsRequest {
            relationship_filter: Some(filter),
            optional_preconditions: Vec::new(),
            ..Default::default()
        };

        let mut client = self.client.permissions_client().await;
        let resp = client
            .delete_relationships(req)
            .await
            .map_err(|s| AuthError::spicedb_status("delete_relationships", s))?
            .into_inner();

        Ok(resp.relationships_deleted_count as u64)
    }

    /// Returns all resource IDs of a specific type accessible to a user.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if the server stream encounters transit errors.
    #[instrument(
        level = "debug",
        skip(self),
        fields(resource_type, permission, user_id)
    )]
    pub async fn lookup_resources(
        &self,
        user_id: &str,
        permission: &str,
        resource_type: &str,
    ) -> Result<Vec<String>, AuthError> {
        let req = LookupResourcesRequest {
            resource_object_type: resource_type.to_owned(),
            permission: permission.to_owned(),
            subject: Some(SubjectReference {
                object: Some(ObjectReference {
                    object_type: "user".to_owned(),
                    object_id: user_id.to_owned(),
                }),
                optional_relation: String::new(),
            }),
            consistency: None,
            ..Default::default()
        };

        let mut client = self.client.permissions_client().await;
        let mut stream = client
            .lookup_resources(req)
            .await
            .map_err(|s| AuthError::spicedb_status("lookup_resources", s))?
            .into_inner();

        let mut out = Vec::new();
        while let Some(item) = stream.next().await {
            let msg = item.map_err(|s| AuthError::spicedb_status("lookup_resources(stream)", s))?;
            out.push(msg.resource_object_id);
        }

        Ok(out)
    }
}

/// Evaluation result for a permission request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebacDecision {
    /// Explicitly granted.
    Allowed,
    /// Explicitly denied.
    Denied,
    /// Depends on dynamic context/caveats.
    Conditional,
}

/// Operation for mutating relationship tuples.
#[derive(Debug, Clone, Copy)]
pub enum RelationshipOp {
    /// Create, fail if exists.
    Create,
    /// Create or update.
    Touch,
    /// Delete.
    Delete,
}

impl RelationshipOp {
    /// Maps the internal variant to the Protobuf `i32` representation.
    fn to_proto_i32(self) -> i32 {
        match self {
            RelationshipOp::Create => relationship_update::Operation::Create as i32,
            RelationshipOp::Touch => relationship_update::Operation::Touch as i32,
            RelationshipOp::Delete => relationship_update::Operation::Delete as i32,
        }
    }
}

/// Filter for narrowing down relationships by subject attributes.
#[derive(Debug, Clone, Copy)]
pub struct SubjectFilter<'a> {
    /// Namespace category of the subject.
    pub subject_type: &'a str,
    /// Optional specific subject ID to match.
    pub subject_id: Option<&'a str>,
    /// Optional specific relation to match.
    pub relation: Option<&'a str>,
}
