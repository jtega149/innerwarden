//! Store error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("connection pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("backpressure: {pending} pending events (max {max})")]
    Backpressure { pending: u64, max: u64 },

    #[error("disk full: database exceeds {max_bytes} bytes")]
    DiskFull { max_bytes: u64 },

    #[error("hash chain broken at seq {seq}")]
    HashChainBroken { seq: i64 },

    #[error("migration error: {0}")]
    Migration(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;
