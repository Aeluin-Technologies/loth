//! High-level ReBAC API over SpiceDB (Authzed API).

use std::sync::Arc;

use tokio_stream::StreamExt;
use tonic::Status;
use tracing::instrument;

use crate::spicedb::client::SpiceDbClient;
use crate::spicedb::pb::authzed::api::v1::{
    SubjectFilter as ProtoSubjectFilter, subject_filter as proto_subject_filter, *,
};
use crate::types::AuthError;

pub const EXAMPLE_SCHEMA_ZED: &str = include_str!("../../schema.zed");

pub struct Rebac {
    client: Arc<SpiceDbClient>,
}

impl Rebac {
    pub fn new(client: Arc<SpiceDbClient>) -> Self {
        Self { client }
    }

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
            .map_err(AuthError::spicedb)?
            .into_inner();

        let membership = check_permission_response::Permissionship::try_from(resp.permissionship)
            .unwrap_or(check_permission_response::Permissionship::Unspecified);

        Ok(match membership {
            check_permission_response::Permissionship::HasPermission => RebacDecision::Allowed,
            check_permission_response::Permissionship::NoPermission => RebacDecision::Denied,
            check_permission_response::Permissionship::ConditionalPermission => {
                RebacDecision::Conditional
            }
            check_permission_response::Permissionship::Unspecified => {
                return Err(AuthError::spicedb("unknown permissionship from server"));
            }
        })
    }

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

        let req = WriteRelationshipsRequest {
            updates: vec![update],
            optional_preconditions: Vec::new(),
            ..Default::default()
        };

        let mut client = self.client.permissions_client().await;
        client
            .write_relationships(req)
            .await
            .map_err(AuthError::spicedb)?;
        Ok(())
    }

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
            optional_subject_filter: subject_filter.map(|sf| ProtoSubjectFilter {
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
            .map_err(AuthError::spicedb)?
            .into_inner();

        Ok(resp.relationships_deleted_count as u64)
    }

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
            .map_err(AuthError::spicedb)?
            .into_inner();

        let mut out = Vec::new();

        while let Some(item) = stream.next().await {
            let msg = item.map_err(map_stream_status)?;
            out.push(msg.resource_object_id);
        }

        Ok(out)
    }
}

fn map_stream_status(e: Status) -> AuthError {
    AuthError::spicedb(e)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebacDecision {
    Allowed,
    Denied,
    Conditional,
}

#[derive(Debug, Clone, Copy)]
pub enum RelationshipOp {
    Create,
    Touch,
    Delete,
}

impl RelationshipOp {
    fn to_proto_i32(self) -> i32 {
        match self {
            RelationshipOp::Create => relationship_update::Operation::Create as i32,
            RelationshipOp::Touch => relationship_update::Operation::Touch as i32,
            RelationshipOp::Delete => relationship_update::Operation::Delete as i32,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SubjectFilter<'a> {
    pub subject_type: &'a str,
    pub subject_id: Option<&'a str>,
    pub relation: Option<&'a str>,
}
