//! Galadril hybrid authorization engine:
//! - SpiceDB (Authzed API) for structural ReBAC (core security index).
//! - Cedar for optional contextual ABAC guardrails at the edge.

pub mod cedar;
pub mod engine;
pub mod replication;
pub mod spicedb;
pub mod types;

pub use crate::spicedb::schema::{SchemaManager, SchemaMode};
pub use crate::types::{CedarContext, CedarContextBuilder, LothConfig, TextSource};
