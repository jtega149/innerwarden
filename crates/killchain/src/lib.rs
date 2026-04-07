//! innerwarden-killchain — Kill chain detection engine.
//!
//! Detects multi-step attack patterns (reverse shell, bind shell, code injection,
//! etc.) by tracking per-PID syscall accumulation against 8 bitmask patterns.
//!
//! # Usage as library
//!
//! ```rust,ignore
//! use innerwarden_killchain::tracker::PidTracker;
//!
//! let mut tracker = PidTracker::new();
//! let incidents = tracker.process_event(&event_json);
//! ```

pub mod bridge;
pub mod detector;
pub mod metrics;
pub mod patterns;
pub mod tracker;
pub mod types;
