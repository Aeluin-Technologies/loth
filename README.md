# Loth 🌳

> *"I perceive the Dark Lord and know his mind, or all of his mind that
> concerns the Elves. And he gropes ever to see me and my thought. But still
> the door is closed!"*"

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

It supports basic dual-writing between database and SpiceDB. But for strict
replication, you must pair `ReplicationWorker` with a Postgres outbox.
