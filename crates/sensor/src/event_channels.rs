//! Spec 069 follow-up #1 — multi-lane event channels (Option C).
//!
//! ## The invariant
//!
//! The eBPF kernel-ring **drain thread must never block**. When it blocks
//! on a full channel, the kernel `RingBuf` fills behind it and drops the
//! *next* event — blindly, uncounted, possibly a kill or a credential
//! read. Everything here exists to keep that drain loop non-blocking while
//! still never silently losing a security event.
//!
//! ## The three lanes
//!
//! Between the eBPF collector and the consumer:
//!
//! - **prio** — security-relevant events (kill / ptrace / credential read /
//!   setuid / LSM deny / outbound connect / module load / mount / memfd).
//! - **emergency** — a compact [`SecuritySignal`] spillover taken when
//!   `prio` is full. It carries the minimum needed to raise an incident, so
//!   the security *signal* survives even when the full payload had to be
//!   dropped to keep the ring draining.
//! - **bulk** — high-volume telemetry (exit / clone / truncate / prctl /
//!   accept / dup). Droppable under load.
//!
//! The consumer drains **prio → emergency → bulk** (biased).
//!
//! ## Backpressure policy (never blocks the drain loop)
//!
//! ```text
//! emit(ev):
//!   prio event:
//!     try_send(prio)            -> Ok
//!     full -> brownout=on; try_send(emergency compact)
//!                                 -> Ok  (emergency_used++)
//!             full -> count prio_dropped + SATURATION incident path
//!   bulk event:
//!     brownout -> shed (bulk_dropped++)         # free consumer for prio
//!     else try_send(bulk) -> Ok / full -> bulk_dropped++
//! ```
//!
//! Every drop is **counted** — today the sensor loses events 100% silently.
//! Brownout (proactive bulk shedding) engages when the prio backlog crosses
//! a high watermark and lifts once prio has fully drained (wide hysteresis).
//!
//! Deferred to follow-ups (tracked in the PR): routing non-eBPF collectors
//! through the same classifier, a kernel-side `reserve`-fail counter map,
//! and Option D (two separate kernel rings).

// The producer side (`EbpfTx::emit` + classification + compact signal) is
// exercised only when the crate is built `--features ebpf` (the eBPF ring
// reader is its sole non-test caller) and in unit tests. In the default
// no-`ebpf` build the consumer half is live but the producer half is dead,
// so — same convention as `collectors::ebpf_syscall` — allow it module-wide.
#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use innerwarden_core::event::{Event, Severity};
use innerwarden_core::incident::Incident;
use tokio::sync::mpsc;

/// Priority lane depth. Security events are rare relative to telemetry, so
/// this is sized to absorb a large burst before the emergency lane is ever
/// touched.
pub const PRIO_CAP: usize = 16_384;
/// Bulk telemetry lane depth.
pub const BULK_CAP: usize = 8_192;
/// Emergency compact-signal lane depth (spillover when prio is full).
pub const EMERGENCY_CAP: usize = 4_096;

/// Which lane an event routes to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lane {
    Prio,
    Bulk,
}

/// Classify an event into a lane. Security-relevant → `Prio`.
///
/// High/Critical severity is always priority. Some security signals are
/// Medium/Low (a credential `file.read_access`, a `privilege.setuid`) — an
/// explicit kind list catches those so they are never stuck behind bulk
/// telemetry under load.
pub fn classify(ev: &Event) -> Lane {
    if matches!(ev.severity, Severity::High | Severity::Critical) {
        return Lane::Prio;
    }
    let k = ev.kind.as_str();
    let prio = k.starts_with("process.signal")
        || k.starts_with("process.ptrace")
        || k.starts_with("privilege.")
        || k.starts_with("lsm.")
        || k.starts_with("kernel.module")
        || k.starts_with("filesystem.mount")
        || k.starts_with("process.memfd")
        || k == "network.outbound_connect"
        || k == "file.read_access"
        || k == "process.injection";
    if prio {
        Lane::Prio
    } else {
        Lane::Bulk
    }
}

/// Compact security signal carried on the emergency lane. Preserves the
/// minimum needed to raise an incident when the full [`Event`] payload had
/// to be dropped under saturation.
#[derive(Clone, Debug)]
pub struct SecuritySignal {
    pub ts: chrono::DateTime<chrono::Utc>,
    pub host: String,
    pub kind: String,
    pub severity: Severity,
    pub pid: u64,
    pub ppid: u64,
    pub uid: u64,
    pub comm: String,
    pub target_pid: u64,
    pub exe: String,
    pub container: String,
    pub seq: u64,
}

impl SecuritySignal {
    /// Extract the compact signal from a full event.
    pub fn from_event(ev: &Event, seq: u64) -> Self {
        let d = &ev.details;
        let num = |k: &str| d.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        let txt = |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let exe = {
            let p = txt("path");
            if p.is_empty() {
                txt("filename")
            } else {
                p
            }
        };
        SecuritySignal {
            ts: ev.ts,
            host: ev.host.clone(),
            kind: ev.kind.clone(),
            severity: ev.severity.clone(),
            pid: num("pid"),
            ppid: num("ppid"),
            uid: num("uid"),
            comm: txt("comm"),
            target_pid: num("target_pid"),
            exe,
            container: txt("container_id"),
            seq,
        }
    }

    /// Reconstruct a minimal incident so the response path still fires even
    /// though the full event payload was dropped under saturation.
    pub fn to_incident(&self) -> Incident {
        let severity = if matches!(self.severity, Severity::Critical) {
            Severity::Critical
        } else {
            Severity::High
        };
        Incident {
            ts: self.ts,
            host: self.host.clone(),
            incident_id: format!("saturation:{}:{}:{}", self.kind, self.pid, self.seq),
            severity,
            title: format!(
                "Security event under saturation: {} (PID {})",
                self.kind, self.pid
            ),
            summary: format!(
                "{} (PID {}, comm {}) was captured via the emergency overflow lane while the priority \
                 channel was saturated. The full payload was dropped to keep the kernel ring draining; \
                 this compact signal preserves the security event. target_pid={} uid={} exe={} container={}",
                self.kind, self.pid, self.comm, self.target_pid, self.uid, self.exe, self.container
            ),
            evidence: serde_json::json!([{
                "kind": self.kind,
                "pid": self.pid,
                "ppid": self.ppid,
                "uid": self.uid,
                "comm": self.comm,
                "target_pid": self.target_pid,
                "exe": self.exe,
                "container": self.container,
                "seq": self.seq,
                "lane": "emergency",
            }]),
            recommended_checks: vec![
                "Detection ran under saturation — investigate the load source (possible noise-flood evasion)"
                    .to_string(),
                format!("Inspect PID {} ({}) directly", self.pid, self.comm),
            ],
            tags: vec![
                "ebpf".to_string(),
                "saturation".to_string(),
                "emergency_lane".to_string(),
            ],
            entities: vec![],
        }
    }
}

/// Lifetime drop/saturation counters. Today the sensor loses events 100%
/// silently; these make saturation visible to operators.
#[derive(Default, Debug)]
pub struct DropCounters {
    /// Security events lost even after the emergency lane (alarm-worthy).
    pub prio_dropped: AtomicU64,
    /// Bulk telemetry shed or dropped under load.
    pub bulk_dropped: AtomicU64,
    /// Prio-full spillovers caught by the emergency compact lane.
    pub emergency_used: AtomicU64,
    /// Number of times brownout engaged.
    pub brownout_activations: AtomicU64,
}

impl DropCounters {
    /// `(prio_dropped, bulk_dropped, emergency_used, brownout_activations)`.
    pub fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.prio_dropped.load(Ordering::Relaxed),
            self.bulk_dropped.load(Ordering::Relaxed),
            self.emergency_used.load(Ordering::Relaxed),
            self.brownout_activations.load(Ordering::Relaxed),
        )
    }
}

/// Outcome of a single [`EbpfTx::emit`] call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EmitOutcome {
    Prio,
    Bulk,
    Emergency,
    DroppedPrio,
    DroppedBulk,
    Sampled,
}

/// Producer handle for the eBPF ring reader. Cloneable, lock-free, and
/// **never blocks** — every method is synchronous and non-awaiting.
#[derive(Clone)]
pub struct EbpfTx {
    prio: mpsc::Sender<Event>,
    bulk: mpsc::Sender<Event>,
    emergency: mpsc::Sender<SecuritySignal>,
    pub counters: Arc<DropCounters>,
    brownout: Arc<AtomicBool>,
    seq: Arc<AtomicU64>,
    /// Prio backlog depth that proactively engages brownout (3/4 of cap).
    brownout_watermark: usize,
}

impl EbpfTx {
    /// Non-blocking emit. The kernel-ring drain loop calls this; it must
    /// never await. Returns the routing outcome (for metrics/tests).
    pub fn emit(&self, ev: Event) -> EmitOutcome {
        match classify(&ev) {
            Lane::Prio => self.emit_prio(ev),
            Lane::Bulk => self.emit_bulk(ev),
        }
    }

    /// True while shedding bulk telemetry to protect the prio lane.
    pub fn in_brownout(&self) -> bool {
        self.brownout.load(Ordering::Relaxed)
    }

    /// True once the consumer has dropped every receiver — the collector
    /// should stop.
    pub fn is_closed(&self) -> bool {
        self.prio.is_closed() && self.bulk.is_closed() && self.emergency.is_closed()
    }

    fn engage_brownout(&self) {
        if !self.brownout.swap(true, Ordering::Relaxed) {
            self.counters
                .brownout_activations
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn emit_prio(&self, ev: Event) -> EmitOutcome {
        match self.prio.try_send(ev) {
            Ok(()) => {
                // Proactively shed bulk once the prio backlog is high, so we
                // free consumer headroom *before* prio overflows to emergency.
                let depth = self
                    .prio
                    .max_capacity()
                    .saturating_sub(self.prio.capacity());
                if depth >= self.brownout_watermark {
                    self.engage_brownout();
                }
                EmitOutcome::Prio
            }
            Err(mpsc::error::TrySendError::Full(ev)) => {
                // Prio saturated → brownout + spill the compact signal to the
                // emergency lane. Never block the drain loop.
                self.engage_brownout();
                let seq = self.seq.fetch_add(1, Ordering::Relaxed);
                let sig = SecuritySignal::from_event(&ev, seq);
                match self.emergency.try_send(sig) {
                    Ok(()) => {
                        self.counters.emergency_used.fetch_add(1, Ordering::Relaxed);
                        EmitOutcome::Emergency
                    }
                    Err(_) => {
                        self.counters.prio_dropped.fetch_add(1, Ordering::Relaxed);
                        EmitOutcome::DroppedPrio
                    }
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => EmitOutcome::DroppedPrio,
        }
    }

    fn emit_bulk(&self, ev: Event) -> EmitOutcome {
        // Brownout sheds low-value telemetry to free the consumer for prio.
        if self.brownout.load(Ordering::Relaxed) {
            self.counters.bulk_dropped.fetch_add(1, Ordering::Relaxed);
            return EmitOutcome::Sampled;
        }
        match self.bulk.try_send(ev) {
            Ok(()) => EmitOutcome::Bulk,
            Err(_) => {
                self.counters.bulk_dropped.fetch_add(1, Ordering::Relaxed);
                EmitOutcome::DroppedBulk
            }
        }
    }
}

/// One drained item from the consumer side.
pub enum Drained {
    Event(Event),
    Security(SecuritySignal),
}

/// Consumer handle. [`recv`](EventRx::recv) drains **prio → emergency →
/// bulk** (biased) and clears brownout once the prio backlog has cleared.
pub struct EventRx {
    prio: mpsc::Receiver<Event>,
    emergency: mpsc::Receiver<SecuritySignal>,
    bulk: mpsc::Receiver<Event>,
    brownout: Arc<AtomicBool>,
    prio_open: bool,
    emergency_open: bool,
    bulk_open: bool,
}

impl EventRx {
    /// Drain the next item, preferring security lanes. Returns `None` only
    /// once **all three** lanes are closed (every producer dropped).
    pub async fn recv(&mut self) -> Option<Drained> {
        loop {
            // Wide-hysteresis brownout release: once prio has fully drained,
            // stop shedding bulk telemetry.
            if self.prio.is_empty() {
                self.brownout.store(false, Ordering::Relaxed);
            }

            tokio::select! {
                biased;
                ev = self.prio.recv(), if self.prio_open => match ev {
                    Some(e) => return Some(Drained::Event(e)),
                    None => self.prio_open = false,
                },
                sig = self.emergency.recv(), if self.emergency_open => match sig {
                    Some(s) => return Some(Drained::Security(s)),
                    None => self.emergency_open = false,
                },
                ev = self.bulk.recv(), if self.bulk_open => match ev {
                    Some(e) => return Some(Drained::Event(e)),
                    None => self.bulk_open = false,
                },
                else => return None,
            }
        }
    }
}

/// Build the producer + consumer halves plus the shared counters.
pub fn channels() -> (EbpfTx, EventRx, Arc<DropCounters>) {
    channels_with_caps(PRIO_CAP, BULK_CAP, EMERGENCY_CAP)
}

/// Like [`channels`] but with explicit lane depths. Used by tests to drive
/// overflow/brownout behaviour with tiny channels.
pub fn channels_with_caps(
    prio_cap: usize,
    bulk_cap: usize,
    emer_cap: usize,
) -> (EbpfTx, EventRx, Arc<DropCounters>) {
    let (prio_tx, prio_rx) = mpsc::channel(prio_cap);
    let (bulk_tx, bulk_rx) = mpsc::channel(bulk_cap);
    let (emer_tx, emer_rx) = mpsc::channel(emer_cap);
    let counters = Arc::new(DropCounters::default());
    let brownout = Arc::new(AtomicBool::new(false));
    let tx = EbpfTx {
        prio: prio_tx,
        bulk: bulk_tx,
        emergency: emer_tx,
        counters: Arc::clone(&counters),
        brownout: Arc::clone(&brownout),
        seq: Arc::new(AtomicU64::new(0)),
        brownout_watermark: (prio_cap * 3 / 4).max(1),
    };
    let rx = EventRx {
        prio: prio_rx,
        emergency: emer_rx,
        bulk: bulk_rx,
        brownout,
        prio_open: true,
        emergency_open: true,
        bulk_open: true,
    };
    (tx, rx, counters)
}

/// The plain bulk `Sender` for non-eBPF collectors (low-rate file readers).
/// They keep their existing blocking `tx.send(ev).await` call shape and
/// always land on the bulk lane; routing them through the classifier is a
/// tracked follow-up.
impl EbpfTx {
    pub fn bulk_sender(&self) -> mpsc::Sender<Event> {
        self.bulk.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: &str, sev: Severity, details: serde_json::Value) -> Event {
        Event {
            ts: chrono::Utc::now(),
            host: "h".into(),
            source: "ebpf".into(),
            kind: kind.into(),
            severity: sev,
            summary: "s".into(),
            details,
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn classify_routes_security_to_prio_and_telemetry_to_bulk() {
        // High/Critical → prio regardless of kind.
        assert_eq!(
            classify(&ev("anything", Severity::High, serde_json::json!({}))),
            Lane::Prio
        );
        assert_eq!(
            classify(&ev("anything", Severity::Critical, serde_json::json!({}))),
            Lane::Prio
        );
        // Medium/Low security kinds → prio via the explicit list.
        for k in [
            "process.signal",
            "process.ptrace",
            "privilege.setuid",
            "lsm.exec_blocked",
            "kernel.module_load",
            "filesystem.mount",
            "process.memfd_create",
            "network.outbound_connect",
            "file.read_access",
            "process.injection",
        ] {
            assert_eq!(
                classify(&ev(k, Severity::Medium, serde_json::json!({}))),
                Lane::Prio,
                "{k} should be prio"
            );
        }
        // Bulk telemetry.
        for k in [
            "process.exit",
            "process.clone",
            "file.truncate",
            "process.prctl",
        ] {
            assert_eq!(
                classify(&ev(k, Severity::Info, serde_json::json!({}))),
                Lane::Bulk,
                "{k} should be bulk"
            );
        }
    }

    #[test]
    fn emit_happy_path_routes_each_lane_without_drops() {
        let (tx, _rx, counters) = channels_with_caps(8, 8, 8);
        assert_eq!(
            tx.emit(ev(
                "process.signal",
                Severity::High,
                serde_json::json!({"pid":1})
            )),
            EmitOutcome::Prio
        );
        assert_eq!(
            tx.emit(ev(
                "process.exit",
                Severity::Info,
                serde_json::json!({"pid":2})
            )),
            EmitOutcome::Bulk
        );
        assert_eq!(counters.snapshot(), (0, 0, 0, 0));
        assert!(!tx.in_brownout());
    }

    #[test]
    fn prio_full_spills_to_emergency_then_drops_counted() {
        // cap 1 each: 1 prio fits, 2nd spills to emergency, 3rd is dropped.
        let (tx, _rx, counters) = channels_with_caps(1, 4, 1);
        assert_eq!(
            tx.emit(ev(
                "process.signal",
                Severity::High,
                serde_json::json!({"pid":1})
            )),
            EmitOutcome::Prio
        );
        // prio full → compact spill to emergency
        assert_eq!(
            tx.emit(ev(
                "process.signal",
                Severity::High,
                serde_json::json!({"pid":2})
            )),
            EmitOutcome::Emergency
        );
        // prio AND emergency full → counted prio drop (NEVER blocks)
        assert_eq!(
            tx.emit(ev(
                "process.signal",
                Severity::High,
                serde_json::json!({"pid":3})
            )),
            EmitOutcome::DroppedPrio
        );
        let (prio_dropped, _bulk, emergency_used, brownouts) = counters.snapshot();
        assert_eq!(prio_dropped, 1);
        assert_eq!(emergency_used, 1);
        assert!(brownouts >= 1, "prio saturation must engage brownout");
        assert!(tx.in_brownout());
    }

    #[test]
    fn brownout_sheds_bulk_telemetry() {
        // watermark = max(1*3/4,1) = 1 → first prio send engages brownout.
        let (tx, _rx, counters) = channels_with_caps(1, 8, 1);
        assert_eq!(
            tx.emit(ev(
                "privilege.setuid",
                Severity::High,
                serde_json::json!({"pid":1})
            )),
            EmitOutcome::Prio
        );
        assert!(tx.in_brownout(), "high prio backlog must engage brownout");
        // bulk is now shed to free the consumer for prio.
        assert_eq!(
            tx.emit(ev(
                "process.exit",
                Severity::Info,
                serde_json::json!({"pid":2})
            )),
            EmitOutcome::Sampled
        );
        let (_p, bulk_dropped, _e, _b) = counters.snapshot();
        assert_eq!(bulk_dropped, 1);
    }

    #[test]
    fn security_signal_extracts_and_rebuilds_incident() {
        let e = ev(
            "process.signal",
            Severity::High,
            serde_json::json!({"pid":4242,"ppid":7,"uid":1000,"comm":"perl","target_pid":91919}),
        );
        let sig = SecuritySignal::from_event(&e, 5);
        assert_eq!(sig.pid, 4242);
        assert_eq!(sig.ppid, 7);
        assert_eq!(sig.uid, 1000);
        assert_eq!(sig.comm, "perl");
        assert_eq!(sig.target_pid, 91919);
        assert_eq!(sig.seq, 5);

        let inc = sig.to_incident();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.incident_id.contains("saturation"));
        assert!(inc.tags.contains(&"emergency_lane".to_string()));
        // evidence preserves the pid for the dedup/response path.
        let pid = inc.evidence.as_array().unwrap()[0]["pid"].as_u64().unwrap();
        assert_eq!(pid, 4242);
    }

    #[tokio::test]
    async fn recv_drains_prio_before_bulk_and_then_emergency() {
        let (tx, mut rx, _c) = channels_with_caps(1, 8, 4);
        // bulk first, then a prio that fits, then a prio that spills to emergency.
        assert_eq!(
            tx.emit(ev(
                "process.exit",
                Severity::Info,
                serde_json::json!({"pid":10})
            )),
            EmitOutcome::Bulk
        );
        assert_eq!(
            tx.emit(ev(
                "process.signal",
                Severity::High,
                serde_json::json!({"pid":20})
            )),
            EmitOutcome::Prio
        );
        assert_eq!(
            tx.emit(ev(
                "process.signal",
                Severity::High,
                serde_json::json!({"pid":30})
            )),
            EmitOutcome::Emergency
        );

        // Biased order: prio (pid 20) first.
        match rx.recv().await.unwrap() {
            Drained::Event(e) => assert_eq!(e.details["pid"], 20),
            Drained::Security(_) => panic!("expected prio event first"),
        }
        // Then emergency (pid 30) before bulk.
        match rx.recv().await.unwrap() {
            Drained::Security(s) => assert_eq!(s.pid, 30),
            Drained::Event(e) => panic!("expected emergency before bulk, got {}", e.details["pid"]),
        }
        // Then bulk (pid 10).
        match rx.recv().await.unwrap() {
            Drained::Event(e) => assert_eq!(e.details["pid"], 10),
            Drained::Security(_) => panic!("expected bulk event"),
        }
        // All producers dropped → recv returns None.
        drop(tx);
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn brownout_lifts_once_prio_drains() {
        let (tx, mut rx, _c) = channels_with_caps(1, 8, 4);
        assert_eq!(
            tx.emit(ev(
                "process.signal",
                Severity::High,
                serde_json::json!({"pid":1})
            )),
            EmitOutcome::Prio
        );
        assert!(tx.in_brownout());
        // Drain the one prio event.
        let _ = rx.recv().await.unwrap();
        // Next recv runs the loop top (prio now empty → clears brownout) then
        // blocks; the timeout cancels it but the side effect persists.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(30), rx.recv()).await;
        assert!(!tx.in_brownout(), "brownout must lift after prio drains");
    }
}
