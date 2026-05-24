//! Domain types shared across modules.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct EvaluationContext {
    pub ip_address: IpAddr,
    pub timestamp: DateTime<Utc>,
    pub device_compliant: bool,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("SpiceDB gRPC communication error: {0}")]
    SpiceDbFailure(String),

    #[error("Cedar evaluation error: {0}")]
    CedarFailure(String),

    #[error("Serialization or schema validation error: {0}")]
    ValidationError(String),
}

impl AuthError {
    pub(crate) fn spicedb<E: std::fmt::Display>(e: E) -> Self {
        Self::SpiceDbFailure(e.to_string())
    }

    pub(crate) fn cedar<E: std::fmt::Display>(e: E) -> Self {
        Self::CedarFailure(e.to_string())
    }

    pub(crate) fn validation<E: std::fmt::Display>(e: E) -> Self {
        Self::ValidationError(e.to_string())
    }
}
