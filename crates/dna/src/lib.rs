// Migrated from standalone repo — suppress cosmetic clippy lints.
#![allow(
    clippy::vec_init_then_push,
    clippy::needless_range_loop,
    clippy::manual_swap,
    clippy::single_match,
    clippy::collapsible_if
)]

//! innerwarden-dna — Behavioral threat fingerprinting engine.
//!
//! Identifies attackers by how they act, not their IP address.
//! Fingerprints behavior via atom sequences, enabling attribution
//! across VPN/Tor/proxy switching.
//!
//! # Core components
//!
//! - [`sequence`] — Behavioral atom primitives and classification
//! - [`fingerprint`] — Exact + fuzzy DNA hashing
//! - [`classifier`] — Threat type classification from atom patterns
//! - [`store`] — Persistent DNA storage with LRU eviction
//! - [`anomaly`] — Process behavior anomaly detection (cosine distance, rate spikes)
//! - [`attack_chain`] — MITRE ATT&CK chain tracking per IP

pub mod anomaly;
pub mod attack_chain;
pub mod classifier;
pub mod fingerprint;
pub mod sequence;
pub mod store;
