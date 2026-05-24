//! Domain types shared across modules.

use std::borrow::Cow;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use thiserror::Error;

/// Runtime evaluation context that many applications may want.
///
/// This remains as a convenience type; the ABAC layer is generic and can accept app-defined contexts.
#[derive(Debug, Clone)]
pub struct EvaluationContext {
    /// The remote client or originating caller identity IP address.
    pub ip_address: IpAddr,
    /// The exact timestamp milestone of the authorization challenge evaluation.
    pub timestamp: DateTime<Utc>,
    /// Flags indicating whether the originating client endpoint satisfies MDM compliance checks.
    pub device_compliant: bool,
}

/// A policy or schema data text provider source variant.
#[derive(Debug, Clone)]
pub enum TextSource<'a> {
    /// In-memory literal string configuration values.
    Inline(Cow<'a, str>),
    /// A target file path pointing to a system file resource containing definitions.
    Path(PathBuf),
}

impl<'a> TextSource<'a> {
    /// Loads the underlying source configuration into an owned string.
    ///
    /// # Errors
    ///
    /// Returns an `AuthError` containing the underlying standard system I/O error
    /// if the target storage system path cannot be accessed or successfully parsed.
    pub fn load_to_string(&self) -> Result<String, AuthError> {
        match self {
            TextSource::Inline(s) => Ok(s.to_string()),
            TextSource::Path(p) => {
                std::fs::read_to_string(p).map_err(|e| AuthError::io("read_to_string", p, e))
            }
        }
    }

    /// Factory method to assemble a new filesystem storage reference link.
    pub fn from_path(path: impl AsRef<Path>) -> Self {
        Self::Path(path.as_ref().to_path_buf())
    }

    /// Factory method to capture an explicit or borrowed inline literal configuration.
    pub fn from_inline(s: impl Into<Cow<'a, str>>) -> Self {
        Self::Inline(s.into())
    }
}

/// Configuration payload used to initialize and bootstrap authorization engine instances.
///
/// - If `zed_schema` is `None`, the built-in default schema is used.
/// - If `cedar_policies` is `None`, ABAC is disabled and Cedar context is ignored.
#[derive(Debug, Clone)]
pub struct LothConfig<'a> {
    /// Network connection endpoint string pointing to the core SpiceDB cluster.
    pub spicedb_endpoint: Cow<'a, str>,
    /// Secure preshared authorization API bearer token credential.
    pub spicedb_token: Cow<'a, str>,
    /// Optional field housing the structural schema rules to ensure on connection.
    pub zed_schema: Option<TextSource<'a>>,
    /// Optional field housing the dynamic Cedar policies to evaluate.
    pub cedar_policies: Option<TextSource<'a>>,
}

impl<'a> LothConfig<'a> {
    /// Instantiates a new base `LothConfig` requiring target cluster connection attributes.
    pub fn new(endpoint: impl Into<Cow<'a, str>>, token: impl Into<Cow<'a, str>>) -> Self {
        Self {
            spicedb_endpoint: endpoint.into(),
            spicedb_token: token.into(),
            zed_schema: None,
            cedar_policies: None,
        }
    }

    /// Sets the target schema definition block.
    pub fn with_zed_schema(mut self, src: TextSource<'a>) -> Self {
        self.zed_schema = Some(src);
        self
    }

    /// Sets the target Cedar policy set definitions block.
    pub fn with_cedar_policies(mut self, src: TextSource<'a>) -> Self {
        self.cedar_policies = Some(src);
        self
    }
}

/// Comprehensive, structured tracking errors complete with semantic operation tracing and source chaining.
#[derive(Debug, Error)]
pub enum AuthError {
    /// The physical connection transport layer or connection pool faulted during execution.
    #[error("SpiceDB transport error while {operation} (endpoint={endpoint})")]
    SpiceDbTransport {
        /// Label describing the physical engine action running during the crash.
        operation: &'static str,
        /// Remote address endpoint path target.
        endpoint: String,
        /// The raw underlying network stack transport source problem wrapper.
        #[source]
        source: tonic::transport::Error,
    },

    /// The remote SpiceDB cluster returned an explicit unhandled gRPC failure status flag.
    #[error("SpiceDB gRPC status while {operation}: {status}")]
    SpiceDbStatus {
        /// Label describing the core functional method block active during the fault.
        operation: &'static str,
        /// The raw Tonic gRPC engine response metadata payload status structure.
        status: tonic::Status,
    },

    /// A functional invariant or schema model definition boundary was broken during runtime execution.
    #[error("SpiceDB protocol/validation error while {operation}: {message}")]
    SpiceDbProtocol {
        /// Label capturing the exact location triggering the validation fallback path.
        operation: &'static str,
        /// Detail context capturing exact schema layout bugs or semantic protocol conflicts.
        message: String,
    },

    /// Cedar compilation and schema parsing validation checks failed to compile.
    #[error("Cedar validation/parsing error: {message}")]
    CedarValidation {
        /// The raw compiled description error message generated by the Cedar policy engine.
        message: String,
    },

    /// The Cedar authorizer engine dropped processing routines due to runtime data schema exceptions.
    #[error("Cedar evaluation error: {message}")]
    CedarEvaluation {
        /// Description of the runtime context or parameter matching data problem.
        message: String,
    },

    /// User input parameters failed simple format verification patterns.
    #[error("Invalid input: {message}")]
    ValidationError {
        /// Detailed description outlining formatting parameter conflicts.
        message: String,
    },

    /// Local hardware filesystem interaction operations were blocked or interrupted.
    #[error("I/O error while {operation} ({path}): {source}")]
    Io {
        /// The precise local input method executed during the system crash.
        operation: &'static str,
        /// File storage path location identifier target.
        path: PathBuf,
        /// Raw file system standard library descriptor error payload.
        #[source]
        source: std::io::Error,
    },
}

impl AuthError {
    /// Assembles an input parameter tracking exception.
    pub(crate) fn validation<E: fmt::Display>(message: E) -> Self {
        Self::ValidationError {
            message: message.to_string(),
        }
    }

    /// Assembles a structural Cedar syntax parser check exception.
    pub(crate) fn cedar_validation<E: fmt::Display>(e: E) -> Self {
        Self::CedarValidation {
            message: e.to_string(),
        }
    }

    /// Assembles an evaluation exception outputting from Cedar engine runtime steps.
    pub(crate) fn cedar_eval<E: fmt::Display>(e: E) -> Self {
        Self::CedarEvaluation {
            message: e.to_string(),
        }
    }

    /// Maps a raw Tonic status payload error across to local representations.
    pub(crate) fn spicedb_status(operation: &'static str, status: tonic::Status) -> Self {
        Self::SpiceDbStatus { operation, status }
    }

    /// Assembles a functional invariant protocol tracking conflict payload.
    pub(crate) fn spicedb_protocol(operation: &'static str, message: impl Into<String>) -> Self {
        Self::SpiceDbProtocol {
            operation,
            message: message.into(),
        }
    }

    /// Maps a system standard I/O storage issue across into a local engine representations block.
    pub(crate) fn io(operation: &'static str, path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            operation,
            path: path.to_path_buf(),
            source,
        }
    }
}

/// A generic transformation trait that flattens struct scopes into Cedar attribute key-value pairs.
pub trait CedarContext<'a> {
    /// serializes property attributes out into an initialized context builder wrapper container.
    ///
    /// # Errors
    ///
    /// Returns an `AuthError` variant if runtime values violate internal conversion expectations.
    fn write_to(&self, out: &mut CedarContextBuilder<'a>) -> Result<(), AuthError>;
}

impl<'a> CedarContext<'a> for () {
    /// Passthrough mock stub implementation facilitating seamless execution paths for empty contexts.
    fn write_to(&self, _out: &mut CedarContextBuilder<'a>) -> Result<(), AuthError> {
        Ok(())
    }
}

/// Strongly typed scalar value reference wrappers mapped into the Cedar evaluation runtime environment.
#[derive(Debug, Clone, Copy)]
pub enum CedarValueRef<'a> {
    /// A standard boolean conditional switch value statement.
    Bool(bool),
    /// A signed 64-bit numerical integer value statement.
    I64(i64),
    /// A clean ASCII or UTF-8 compliant character string reference.
    Str(&'a str),
}

/// An allocation-conscious accumulation builder used to serialize metadata profiles into Cedar contexts.
///
/// Internally, Cedar expects owned string identifiers and complex restricted evaluation expressions.
/// This builder acts as an intermediate storage block allowing zero-copy slice collection
/// up until final compilation boundaries are crossed.
pub struct CedarContextBuilder<'a> {
    pub(crate) entries: Vec<(&'a str, CedarValueRef<'a>)>,
}

impl<'a> CedarContextBuilder<'a> {
    /// Assembles an empty storage builder allocating fixed initialization capacity thresholds up front.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            entries: Vec::with_capacity(cap),
        }
    }

    /// Appends a scalar boolean property onto the processing context track collection.
    pub fn insert_bool(&mut self, key: &'a str, value: bool) {
        self.entries.push((key, CedarValueRef::Bool(value)));
    }

    /// Appends a scalar signed 64-bit integer property onto the processing context track collection.
    pub fn insert_i64(&mut self, key: &'a str, value: i64) {
        self.entries.push((key, CedarValueRef::I64(value)));
    }

    /// Appends a borrowed string slice value onto the processing context track collection.
    pub fn insert_str(&mut self, key: &'a str, value: &'a str) {
        self.entries.push((key, CedarValueRef::Str(value)));
    }
}

/// Helper macro to map struct fields into Cedar keys with minimal boilerplate.
///
/// # Examples
///
/// ```ignore
/// impl CedarContext for MyCtx {
///   fn write_to(&self, out: &mut CedarContextBuilder<'_>) -> Result<(), AuthError> {
///     loth::cedar_context_map!(out, self, {
///       "device_compliant" => bool self.device_compliant,
///       "ip_address" => str self.ip.as_str(),
///     });
///     Ok(())
///   }
/// }
/// ```
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
