//! Raw Authzed (SpiceDB) gRPC clients.

use std::sync::Arc;

use tokio::sync::Mutex;
use tonic::metadata::{MetadataKey, MetadataValue};
use tonic::service::Interceptor;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Status};

use crate::spicedb::pb::authzed::api::v1::permissions_service_client::PermissionsServiceClient;
use crate::spicedb::pb::authzed::api::v1::schema_service_client::SchemaServiceClient;
use crate::types::AuthError;

/// Tonic gRPC interceptor that injects a Bearer token into request metadata.
#[derive(Clone)]
pub(crate) struct BearerTokenInterceptor {
    header_key: MetadataKey<tonic::metadata::Ascii>,
    header_value: MetadataValue<tonic::metadata::Ascii>,
}

impl Interceptor for BearerTokenInterceptor {
    /// Injects the Authorization header into outbound requests.
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        req.metadata_mut()
            .insert(self.header_key.clone(), self.header_value.clone());
        Ok(req)
    }
}

/// Thread-safe manager for authenticated SpiceDB gRPC connections.
pub struct SpiceDbClient {
    endpoint: String,
    permissions: Mutex<
        PermissionsServiceClient<
            tonic::service::interceptor::InterceptedService<Channel, BearerTokenInterceptor>,
        >,
    >,
    schema: Mutex<
        SchemaServiceClient<
            tonic::service::interceptor::InterceptedService<Channel, BearerTokenInterceptor>,
        >,
    >,
}

impl SpiceDbClient {
    /// Connects to a SpiceDB cluster using the provided endpoint and bearer token.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if the endpoint is invalid, the token is malformed,
    /// or the initial connection handshake fails.
    pub async fn connect(endpoint: &str, token: &str) -> Result<Arc<Self>, AuthError> {
        let ep = Endpoint::from_shared(endpoint.to_owned()).map_err(AuthError::validation)?;

        let channel = ep
            .connect()
            .await
            .map_err(|e| AuthError::SpiceDbTransport {
                operation: "connecting to SpiceDB",
                endpoint: endpoint.to_owned(),
                source: e,
            })?;

        let header_key = MetadataKey::from_static("authorization");
        let header_value =
            MetadataValue::try_from(format!("Bearer {token}")).map_err(AuthError::validation)?;

        let interceptor = BearerTokenInterceptor {
            header_key,
            header_value,
        };

        let permissions =
            PermissionsServiceClient::with_interceptor(channel.clone(), interceptor.clone());
        let schema = SchemaServiceClient::with_interceptor(channel, interceptor);

        Ok(Arc::new(Self {
            endpoint: endpoint.to_owned(),
            permissions: Mutex::new(permissions),
            schema: Mutex::new(schema),
        }))
    }

    /// Returns the remote instance destination URI.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Acquires a lock on the permissions service client stub.
    pub(crate) async fn permissions_client(
        &self,
    ) -> tokio::sync::MutexGuard<
        '_,
        PermissionsServiceClient<
            tonic::service::interceptor::InterceptedService<Channel, BearerTokenInterceptor>,
        >,
    > {
        self.permissions.lock().await
    }

    /// Acquires a lock on the schema service client stub.
    pub(crate) async fn schema_client(
        &self,
    ) -> tokio::sync::MutexGuard<
        '_,
        SchemaServiceClient<
            tonic::service::interceptor::InterceptedService<Channel, BearerTokenInterceptor>,
        >,
    > {
        self.schema.lock().await
    }
}
