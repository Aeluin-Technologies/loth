# Loth

Loth is a high-performance authorization engine that combines ReBAC using
SpiceDB and ABAC using Cedar. It provides a secure, contextual, and scalable
gateway guardrail for distributed systems.

## Architecture

- **ReBAC Layer**: Uses [SpiceDB](https://authzed.com/) as the structural
    source of truth for ontology relationships.
- **ABAC Layer**: Uses [Cedar](https://www.cedarpolicy.com/) for final
    contextual edge-filtering (device compliance, IP, timestamps).
- **Hybrid Orchestrator**: Fuses structural permissions and dynamic context
    into a single boolean decision.
