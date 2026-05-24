//! Galadril hybrid authorization engine:
//! - SpiceDB (Authzed API) for structural ReBAC (core security index).
//! - Cedar for contextual ABAC guardrails at the edge.

pub mod cedar;
pub mod engine;
pub mod spicedb;
pub mod types;
