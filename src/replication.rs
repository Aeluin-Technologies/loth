//! Dual-writing support for SpiceDB.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, sleep};
use tracing::{debug, error, instrument, warn};

use crate::spicedb::pb::authzed::api::v1::{Relationship, RelationshipUpdate};
use crate::spicedb::rebac::{Rebac, RelationshipOp};
use crate::types::AuthError;

/// Immutable representation of a SpiceDB relationship.
///
/// Uses `Arc<str>` to reduce allocations and enable cheap sharing across thread boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationshipTuple {
    /// Object namespace type.
    pub resource_type: Arc<str>,
    /// Unique ID of the resource instance.
    pub resource_id: Arc<str>,
    /// Relation or permission string.
    pub relation: Arc<str>,
    /// Subject namespace type.
    pub subject_type: Arc<str>,
    /// Unique ID of the subject instance.
    pub subject_id: Arc<str>,
}

impl RelationshipTuple {
    /// Creates a new `RelationshipTuple` from types convertible to `Arc<str>`.
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

/// Replication mutations for the background pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicationEvent {
    /// Inserts or updates a tuple.
    Upsert(RelationshipTuple),
    /// Deletes a tuple.
    Delete(RelationshipTuple),
}

/// Configuration thresholds for the replication worker.
#[derive(Debug, Clone)]
pub struct ReplicationSettings {
    /// Max events to buffer before a forced flush.
    pub max_batch: usize,
    /// Max wait time before flushing an incomplete batch.
    pub flush_interval: Duration,
    /// Max retries per batch before triggering fail-close.
    pub max_retries: usize,
    /// Base duration for exponential backoff.
    pub base_backoff: Duration,
}

impl Default for ReplicationSettings {
    /// Returns default conservative performance thresholds.
    fn default() -> Self {
        Self {
            max_batch: 256,
            flush_interval: Duration::from_millis(10),
            max_retries: 8,
            base_backoff: Duration::from_millis(25),
        }
    }
}

/// Handle for dispatching events to the replication pipeline.
#[derive(Clone)]
pub struct ReplicationQueue {
    tx: mpsc::Sender<ReplicationEvent>,
}

impl ReplicationQueue {
    /// Submits a replication event, applying backpressure if the queue is full.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if the receiver has been dropped.
    pub async fn enqueue(&self, ev: ReplicationEvent) -> Result<(), AuthError> {
        self.tx
            .send(ev)
            .await
            .map_err(|_| AuthError::validation("replication queue closed"))
    }

    /// Enqueues an Upsert operation.
    pub async fn upsert_tuple(&self, t: RelationshipTuple) -> Result<(), AuthError> {
        self.enqueue(ReplicationEvent::Upsert(t)).await
    }

    /// Enqueues a Delete operation.
    pub async fn delete_tuple(&self, t: RelationshipTuple) -> Result<(), AuthError> {
        self.enqueue(ReplicationEvent::Delete(t)).await
    }
}

/// Watch channel tracking fatal replication errors.
///
/// Contains `None` if healthy, or `Some(AuthError)` if the pipeline failed permanently.
pub type FatalReplicationRx = watch::Receiver<Option<AuthError>>;

/// Orchestration handle for replication worker control.
pub struct ReplicationHandle {
    queue: ReplicationQueue,
    fatal_rx: FatalReplicationRx,
    shutdown_tx: oneshot::Sender<()>,
}

impl ReplicationHandle {
    /// Returns a clone of the `ReplicationQueue`.
    pub fn queue(&self) -> ReplicationQueue {
        self.queue.clone()
    }

    /// Returns the fail-closed error state.
    pub fn fatal_rx(&self) -> FatalReplicationRx {
        self.fatal_rx.clone()
    }

    /// Signals the background worker to shut down.
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

/// Background worker responsible for batching and flushing events.
pub struct ReplicationWorker {
    rebac: Rebac,
    rx: mpsc::Receiver<ReplicationEvent>,
    settings: ReplicationSettings,
    shutdown: oneshot::Receiver<()>,
    fatal_tx: watch::Sender<Option<AuthError>>,
}

/// Initializes a replication pipeline, returning a handle and worker.
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
    /// Starts the asynchronous worker loop.
    ///
    /// # Errors
    ///
    /// Returns `AuthError` if batch processing exhausts retry limits.
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

    /// Dispatches batched updates via gRPC, implementing exponential backoff.
    async fn flush(&mut self, buf: &mut Vec<ReplicationEvent>) -> Result<(), AuthError> {
        if buf.is_empty() {
            return Ok(());
        }

        let updates = build_updates(buf.drain(..))?;

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

/// Converts replication events into Protobuf-compatible updates.
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

/// Suspends execution until the specified instant.
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
