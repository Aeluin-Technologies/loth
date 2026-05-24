//! Dual-writing / replication support.
//!
//! Strict QoS mode:
//! - bounded queue + `.send().await` backpressure
//! - retry on transient failures
//! - fail-close if replication cannot be applied
//!
//! This module does NOT guarantee durability across process restarts.
//! For strict "Postgres == SpiceDB" correctness, pair this with a Postgres outbox.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, sleep};
use tracing::{debug, error, instrument, warn};

use crate::spicedb::pb::authzed::api::v1::{Relationship, RelationshipUpdate};
use crate::spicedb::rebac::{Rebac, RelationshipOp};
use crate::types::AuthError;

/// An immutable representation of a SpiceDB relationship tuple graph edge.
///
/// Uses reference-counted atomic string slices (`Arc<str>`) to minimize memory allocations
/// and facilitate cheap serialization across concurrent thread boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationshipTuple {
    /// The object namespace type of the target resource.
    pub resource_type: Arc<str>,
    /// The unique identifier of the target resource instance.
    pub resource_id: Arc<str>,
    /// The name of the relation or permission connecting the resource and subject.
    pub relation: Arc<str>,
    /// The object namespace type of the target subject.
    pub subject_type: Arc<str>,
    /// The unique identifier of the target subject instance.
    pub subject_id: Arc<str>,
}

impl RelationshipTuple {
    /// Creates a new `RelationshipTuple` from types convertible into an `Arc<str>`.
    pub fn new(
        resource_type: impl Into<Arc<str>>,
        resource_id: impl Into<Arc<str>>,
        relation: impl Into<Arc<str>>,
        subject_type: impl Into<Arc<str>>,
        subject_id: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            relation: relation.into(),
            subject_type: subject_type.into(),
            subject_id: subject_id.into(),
        }
    }
}

/// Mutating operations emitted down the replication pipeline to align remote clusters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicationEvent {
    /// Atomically updates or inserts the specified tuple edge.
    Upsert(RelationshipTuple),
    /// Removes the designated tuple edge configuration.
    Delete(RelationshipTuple),
}

/// Dynamic batching and backoff threshold limits driving the background replication worker.
#[derive(Debug, Clone)]
pub struct ReplicationSettings {
    /// The maximum number of elements accumulated before a batch flush is forced.
    pub max_batch: usize,
    /// The maximum duration to wait before flushing an incomplete event buffer.
    pub flush_interval: Duration,
    /// The absolute count of retries permitted for a failing batch before triggering a fail-closed crash.
    pub max_retries: usize,
    /// The base duration utilized as the initial stepping milestone for exponential backoff calculations.
    pub base_backoff: Duration,
}

impl Default for ReplicationSettings {
    /// Provides cautious performance thresholds designed to balance latency overhead against heavy load pressures.
    fn default() -> Self {
        Self {
            max_batch: 256,
            flush_interval: Duration::from_millis(10),
            max_retries: 8,
            base_backoff: Duration::from_millis(25),
        }
    }
}

/// A handle for dispatching authorization adjustments into the async replication pipeline.
#[derive(Clone)]
pub struct ReplicationQueue {
    tx: mpsc::Sender<ReplicationEvent>,
}

impl ReplicationQueue {
    /// Submits a replication event payload to the queue.
    ///
    /// This method enforces strict backpressure by waiting if the bounded queue is full.
    ///
    /// # Arguments
    ///
    /// * `ev` - The target `ReplicationEvent` payload to enqueue.
    ///
    /// # Errors
    ///
    /// Returns an `AuthError` if the underlying replication processing channel has terminated.
    pub async fn enqueue(&self, ev: ReplicationEvent) -> Result<(), AuthError> {
        self.tx
            .send(ev)
            .await
            .map_err(|_| AuthError::validation("replication queue closed"))
    }

    /// Helper to enqueue an upsert mutation event.
    ///
    /// # Errors
    ///
    /// Returns an `AuthError` if the replication receiver loop is dead.
    pub async fn upsert_tuple(&self, t: RelationshipTuple) -> Result<(), AuthError> {
        self.enqueue(ReplicationEvent::Upsert(t)).await
    }

    /// Helper to enqueue a delete mutation event.
    ///
    /// # Errors
    ///
    /// Returns an `AuthError` if the replication receiver loop is dead.
    pub async fn delete_tuple(&self, t: RelationshipTuple) -> Result<(), AuthError> {
        self.enqueue(ReplicationEvent::Delete(t)).await
    }
}

/// A watch channel receiver tracking fatal pipeline faults used to enforce fail-closed checks.
///
/// Contains `None` under healthy operating environments and transitions to `Some(AuthError)`
/// if a batch fails permanently.
pub type FatalReplicationRx = watch::Receiver<Option<AuthError>>;

/// A control handle allowing application orchestration layers to access queues or request shutdowns.
pub struct ReplicationHandle {
    queue: ReplicationQueue,
    fatal_rx: FatalReplicationRx,
    shutdown_tx: oneshot::Sender<()>,
}

impl ReplicationHandle {
    /// Returns a cloned instance of the underlying thread-safe `ReplicationQueue`.
    pub fn queue(&self) -> ReplicationQueue {
        self.queue.clone()
    }

    /// Returns a cloned instance of the active fail-closed watch receiver.
    pub fn fatal_rx(&self) -> FatalReplicationRx {
        self.fatal_rx.clone()
    }

    /// Issues an explicit termination interrupt signal across to the linked background worker thread.
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

/// A background worker loop responsible for gathering, batching, and flushing replication events.
pub struct ReplicationWorker {
    rebac: Rebac,
    rx: mpsc::Receiver<ReplicationEvent>,
    settings: ReplicationSettings,
    shutdown: oneshot::Receiver<()>,
    fatal_tx: watch::Sender<Option<AuthError>>,
}

/// Assembles a complete, decoupled replication channel pipeline infrastructure block.
///
/// # Arguments
///
/// * `client` - The explicit reference-counted gRPC client wrapper targeting the remote SpiceDB instance.
/// * `queue_capacity` - The total item threshold limit allocated to the bounded channel buffer before backpressure is hit.
/// * `settings` - Execution constraints determining maximum retry attempts and interval flushes.
pub fn replication_pipeline(
    client: Arc<crate::spicedb::client::SpiceDbClient>,
    queue_capacity: usize,
    settings: ReplicationSettings,
) -> (ReplicationHandle, ReplicationWorker) {
    let (tx, rx) = mpsc::channel(queue_capacity);
    let (shutdown_tx, shutdown) = oneshot::channel();
    let (fatal_tx, fatal_rx) = watch::channel(None);

    let queue = ReplicationQueue { tx };
    let rebac = Rebac::new(client);

    let handle = ReplicationHandle {
        queue,
        fatal_rx,
        shutdown_tx,
    };

    let worker = ReplicationWorker {
        rebac,
        rx,
        settings,
        shutdown,
        fatal_tx,
    };

    (handle, worker)
}

impl ReplicationWorker {
    /// Spawns the main asynchronous processing worker task loop.
    ///
    /// Periodically drains collected events or pushes full collections when the internal
    /// layout hits configured capacity barriers.
    ///
    /// # Errors
    ///
    /// Returns an `AuthError` validation message if any flush batch hits terminal connection
    /// boundaries and exhausts all configured retry loops.
    #[instrument(level = "debug", skip(self))]
    pub async fn run(mut self) -> Result<(), AuthError> {
        let mut buf: Vec<ReplicationEvent> = Vec::with_capacity(self.settings.max_batch);
        let mut next_flush = Instant::now() + self.settings.flush_interval;

        loop {
            tokio::select! {
                _ = &mut self.shutdown => {
                    debug!("replication worker shutdown requested");
                    self.flush(&mut buf).await?;
                    return Ok(());
                }
                maybe_ev = self.rx.recv() => {
                    match maybe_ev {
                        Some(ev) => {
                            buf.push(ev);
                            if buf.len() >= self.settings.max_batch {
                                self.flush(&mut buf).await?;
                                next_flush = Instant::now() + self.settings.flush_interval;
                            }
                        }
                        None => {
                            debug!("replication queue sender dropped; draining remaining events");
                            self.flush(&mut buf).await?;
                            return Ok(());
                        }
                    }
                }
                _ = sleep_until(next_flush) => {
                    if !buf.is_empty() {
                        self.flush(&mut buf).await?;
                    }
                    next_flush = Instant::now() + self.settings.flush_interval;
                }
            }
        }
    }

    /// Dispatches accumulated buffer payloads via a single batched transactional gRPC request.
    ///
    /// Utilizes exponential backoff algorithms if transient cluster errors manifest. If it exhausts
    /// all configured retries, it triggers a permanent fail-closed broadcast.
    ///
    /// # Errors
    ///
    /// Returns a fatal validation error if it fails to write to SpiceDB.
    async fn flush(&mut self, buf: &mut Vec<ReplicationEvent>) -> Result<(), AuthError> {
        if buf.is_empty() {
            return Ok(());
        }

        let updates = build_updates(buf.drain(..))?;

        // Retry loop: fail-close on exhaustion.
        let mut attempt = 0usize;
        loop {
            match self.rebac.write_relationships_batch(updates.clone()).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    attempt += 1;

                    if attempt > self.settings.max_retries {
                        error!(error = %e, "replication failed permanently; failing closed");
                        let _ = self.fatal_tx.send(Some(e));
                        return Err(AuthError::validation(
                            "replication failed permanently (fail-closed)",
                        ));
                    }

                    let backoff = self.settings.base_backoff * (1u32 << (attempt.min(10) as u32));
                    warn!(
                        attempt,
                        backoff_ms = backoff.as_millis(),
                        "replication failed; retrying"
                    );
                    sleep(backoff).await;
                }
            }
        }
    }
}

/// Converts an iterator of internal replication events into a formatted list of Protobuf updates.
///
/// # Errors
///
/// Returns an `AuthError` if any structural data conversions violate backend boundaries.
fn build_updates(
    drained: impl IntoIterator<Item = ReplicationEvent>,
) -> Result<Vec<RelationshipUpdate>, AuthError> {
    let mut out = Vec::new();

    for ev in drained {
        let (op, t) = match ev {
            ReplicationEvent::Upsert(t) => (RelationshipOp::Touch, t),
            ReplicationEvent::Delete(t) => (RelationshipOp::Delete, t),
        };

        let relationship = Relationship {
            resource: Some(crate::spicedb::pb::authzed::api::v1::ObjectReference {
                object_type: t.resource_type.to_string(),
                object_id: t.resource_id.to_string(),
            }),
            relation: t.relation.to_string(),
            subject: Some(crate::spicedb::pb::authzed::api::v1::SubjectReference {
                object: Some(crate::spicedb::pb::authzed::api::v1::ObjectReference {
                    object_type: t.subject_type.to_string(),
                    object_id: t.subject_id.to_string(),
                }),
                optional_relation: String::new(),
            }),
            optional_caveat: None,
            optional_expires_at: None,
        };

        out.push(RelationshipUpdate {
            operation: match op {
                RelationshipOp::Create => {
                    crate::spicedb::pb::authzed::api::v1::relationship_update::Operation::Create
                        as i32
                }
                RelationshipOp::Touch => {
                    crate::spicedb::pb::authzed::api::v1::relationship_update::Operation::Touch
                        as i32
                }
                RelationshipOp::Delete => {
                    crate::spicedb::pb::authzed::api::v1::relationship_update::Operation::Delete
                        as i32
                }
            },
            relationship: Some(relationship),
        });
    }

    Ok(out)
}

/// Suspends the current execution thread until the given target instant milestone is breached.
async fn sleep_until(t: Instant) {
    let now = Instant::now();
    if t > now {
        sleep(t - now).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tuple_uses_arc_str() {
        let t = RelationshipTuple::new("tenant", "t1", "member", "user", "u1");
        assert_eq!(&*t.resource_type, "tenant");
        assert_eq!(&*t.subject_id, "u1");
    }
}
