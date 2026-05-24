//! Raw Authzed (SpiceDB) gRPC client compiled from vendored protos.

use std::sync::Arc;

use tokio::sync::Mutex;
use tonic::metadata::{MetadataKey, MetadataValue};
use tonic::service::Interceptor;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Status};

use crate::spicedb::pb::authzed::api::v1::permissions_service_client::PermissionsServiceClient;
use crate::types::AuthError;

#[derive(Clone)]
pub(crate) struct BearerTokenInterceptor {
    header_key: MetadataKey<tonic::metadata::Ascii>,
    header_value: MetadataValue<tonic::metadata::Ascii>,
}

impl Interceptor for BearerTokenInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        req.metadata_mut()
            .insert(self.header_key.clone(), self.header_value.clone());
        Ok(req)
    }
}

/// Thread-safe client holder.
pub struct SpiceDbClient {
    permissions: Mutex<
        PermissionsServiceClient<
            tonic::service::interceptor::InterceptedService<Channel, BearerTokenInterceptor>,
        >,
    >,
}

impl SpiceDbClient {
    /// Creates a SpiceDB client connected to `endpoint` and authenticated by `token`.
    pub async fn connect(endpoint: &str, token: &str) -> Result<Arc<Self>, AuthError> {
        let channel = Endpoint::from_shared(endpoint.to_owned())
            .map_err(AuthError::validation)?
            .connect()
            .await
            .map_err(AuthError::spicedb)?;

        let header_key = MetadataKey::from_static("authorization");
        let header_value =
            MetadataValue::try_from(format!("Bearer {token}")).map_err(AuthError::validation)?;

        let interceptor = BearerTokenInterceptor {
            header_key,
            header_value,
        };

        let client = PermissionsServiceClient::with_interceptor(channel, interceptor);

        Ok(Arc::new(Self {
            permissions: Mutex::new(client),
        }))
    }

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
}
