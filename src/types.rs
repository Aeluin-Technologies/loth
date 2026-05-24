//! Domain types shared across modules.

use std::borrow::Cow;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use thiserror::Error;

/// Runtime evaluation context containing environment metadata.
#[derive(Debug, Clone)]
pub struct EvaluationContext {
    /// Remote client IP address.
    pub ip_address: IpAddr,
    /// Timestamp of the authorization evaluation.
    pub timestamp: DateTime<Utc>,
    /// Whether the originating device passes MDM compliance.
    pub device_compliant: bool,
}

/// Provider source for policy or schema definitions.
#[derive(Debug, Clone)]
pub enum TextSource<'a> {
    /// In-memory string literal.
    Inline(Cow<'a, str>),
    /// Path to a file on the filesystem.
    Path(PathBuf),
}

impl<'a> TextSource<'a> {
    /// Loads the source content into an owned String.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::Io` if file reading fails.
    pub fn load_to_string(&self) -> Result<String, AuthError> {
        match self {
            TextSource::Inline(s) => Ok(s.to_string()),
            TextSource::Path(p) => {
                std::fs::read_to_string(p).map_err(|e| AuthError::io("read_to_string", p, e))
            }
        }
    }

    /// Creates a source from a file system path.
    pub fn from_path(path: impl AsRef<Path>) -> Self {
        Self::Path(path.as_ref().to_path_buf())
    }

    /// Creates a source from an inline string or reference.
    pub fn from_inline(s: impl Into<Cow<'a, str>>) -> Self {
        Self::Inline(s.into())
    }
}

/// Configuration payload used to initialize the authorization engine.
#[derive(Debug, Clone)]
pub struct LothConfig<'a> {
    /// Remote SpiceDB cluster endpoint.
    pub spicedb_endpoint: Cow<'a, str>,
    /// Secure bearer token for SpiceDB authentication.
    pub spicedb_token: Cow<'a, str>,
    /// Optional schema definitions; uses defaults if None.
    pub zed_schema: Option<TextSource<'a>>,
    /// Optional Cedar policies; disables ABAC if None.
    pub cedar_policies: Option<TextSource<'a>>,
}

impl<'a> LothConfig<'a> {
    /// Initializes a new configuration with required connection credentials.
    pub fn new(endpoint: impl Into<Cow<'a, str>>, token: impl Into<Cow<'a, str>>) -> Self {
        Self {
            spicedb_endpoint: endpoint.into(),
            spicedb_token: token.into(),
            zed_schema: None,
            cedar_policies: None,
        }
    }

    /// Configures the structural schema rules for the engine.
    pub fn with_zed_schema(mut self, src: TextSource<'a>) -> Self {
        self.zed_schema = Some(src);
        self
    }

    /// Configures the dynamic Cedar policy set for evaluation.
    pub fn with_cedar_policies(mut self, src: TextSource<'a>) -> Self {
        self.cedar_policies = Some(src);
        self
    }
}

/// Comprehensive errors representing system, protocol, and evaluation failures.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Physical transport layer connection failure.
    #[error("SpiceDB transport error while {operation} (endpoint={endpoint})")]
    SpiceDbTransport {
        operation: &'static str,
        endpoint: String,
        #[source]
        source: tonic::transport::Error,
    },

    /// gRPC failure returned by the SpiceDB server.
    #[error("SpiceDB gRPC status while {operation}: {status}")]
    SpiceDbStatus {
        operation: &'static str,
        status: tonic::Status,
    },

    /// Protocol violation or schema invariant failure.
    #[error("SpiceDB protocol/validation error while {operation}: {message}")]
    SpiceDbProtocol {
        operation: &'static str,
        message: String,
    },

    /// Cedar policy compilation or syntax error.
    #[error("Cedar validation/parsing error: {message}")]
    CedarValidation {
        message: String,
    },

    /// Runtime error during Cedar policy evaluation.
    #[error("Cedar evaluation error: {message}")]
    CedarEvaluation {
        message: String,
    },

    /// User input formatting or validation failure.
    #[error("Invalid input: {message}")]
    ValidationError {
        message: String,
    },

    /// Filesystem I/O interaction failure.
    #[error("I/O error while {operation} ({path}): {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl AuthError {
    /// Creates a new validation error.
    pub(crate) fn validation<E: fmt::Display>(message: E) -> Self {
        Self::ValidationError {
            message: message.to_string(),
        }
    }

    /// Creates a new Cedar validation error.
    pub(crate) fn cedar_validation<E: fmt::Display>(e: E) -> Self {
        Self::CedarValidation {
            message: e.to_string(),
        }
    }

    /// Creates a new Cedar evaluation error.
    pub(crate) fn cedar_eval<E: fmt::Display>(e: E) -> Self {
        Self::CedarEvaluation {
            message: e.to_string(),
        }
    }

    /// Wraps a tonic status as a SpiceDB status error.
    pub(crate) fn spicedb_status(operation: &'static str, status: tonic::Status) -> Self {
        Self::SpiceDbStatus { operation, status }
    }

    /// Creates a new protocol/invariant error.
    pub(crate) fn spicedb_protocol(operation: &'static str, message: impl Into<String>) -> Self {
        Self::SpiceDbProtocol {
            operation,
            message: message.into(),
        }
    }

    /// Wraps an I/O error with context.
    pub(crate) fn io(operation: &'static str, path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            operation,
            path: path.to_path_buf(),
            source,
        }
    }
}

/// Trait to transform data structures into Cedar context attributes.
pub trait CedarContext<'a> {
    /// Serializes struct data into the provided context builder.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if runtime serialization fails.
    fn write_to(&self, out: &mut CedarContextBuilder<'a>) -> Result<(), AuthError>;
}

impl<'a> CedarContext<'a> for () {
    /// Implementation for empty contexts (no-op).
    fn write_to(&self, _out: &mut CedarContextBuilder<'a>) -> Result<(), AuthError> {
        Ok(())
    }
}

/// Supported scalar types for Cedar evaluation.
#[derive(Debug, Clone, Copy)]
pub enum CedarValueRef<'a> {
    /// Boolean conditional value.
    Bool(bool),
    /// 64-bit integer value.
    I64(i64),
    /// String slice value.
    Str(&'a str),
}

/// Accumulation builder for generating Cedar context attributes.
pub struct CedarContextBuilder<'a> {
    /// The collected key-value entries.
    pub(crate) entries: Vec<(&'a str, CedarValueRef<'a>)>,
}

impl<'a> CedarContextBuilder<'a> {
    /// Creates a new builder with the specified capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            entries: Vec::with_capacity(cap),
        }
    }

    /// Appends a boolean attribute to the context.
    pub fn insert_bool(&mut self, key: &'a str, value: bool) {
        self.entries.push((key, CedarValueRef::Bool(value)));
    }

    /// Appends an integer attribute to the context.
    pub fn insert_i64(&mut self, key: &'a str, value: i64) {
        self.entries.push((key, CedarValueRef::I64(value)));
    }

    /// Appends a string attribute to the context.
    pub fn insert_str(&mut self, key: &'a str, value: &'a str) {
        self.entries.push((key, CedarValueRef::Str(value)));
    }
}

/// Maps struct fields into a `CedarContextBuilder` with specified types.
#[macro_export]
macro_rules! cedar_context_map {
    ($out:expr, $self_:expr, { $($key:literal => $ty:ident $expr:expr),* $(,)? }) => {{
        $(
            $crate::cedar_context_map!(@insert $out, $key, $ty, $expr);
        )*
    }};

    (@insert $out:expr, $key:literal, bool, $expr:expr) => {
        $crate::types::CedarContextBuilder::insert_bool($out, $key, $expr);
    };
    (@insert $out:expr, $key:literal, i64, $expr:expr) => {
        $crate::types::CedarContextBuilder::insert_i64($out, $key, $expr);
    };
    (@insert $out:expr, $key:literal, str, $expr:expr) => {
        $crate::types::CedarContextBuilder::insert_str($out, $key, $expr);
    };
    (@insert $out:expr, $key:literal, $unsupported:ident, $expr:expr) => {
        return Err($crate::types::AuthError::validation(
            concat!("unsupported cedar_context_map type: ", stringify!($unsupported))
        ));
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct DemoCtx<'a> {
        ok: bool,
        hour: i64,
        ip: &'a str,
    }

    // Bind the struct lifetime 'a directly to the CedarContext trait lifetime
    impl<'a> CedarContext<'a> for DemoCtx<'a> {
        fn write_to(&self, out: &mut CedarContextBuilder<'a>) -> Result<(), AuthError> {
            cedar_context_map!(out, self, {
                "ok" => bool self.ok,
                "hour" => i64 self.hour,
                "ip" => str self.ip,
            });
            Ok(())
        }
    }

    #[test]
    fn cedar_context_builder_collects_entries() -> Result<(), AuthError> {
        let ctx = DemoCtx {
            ok: true,
            hour: 9,
            ip: "203.0.113.10",
        };

        let mut b = CedarContextBuilder::with_capacity(3);
        ctx.write_to(&mut b)?;

        assert_eq!(b.entries.len(), 3);
        assert_eq!(b.entries[0].0, "ok");
        Ok(())
    }
}
