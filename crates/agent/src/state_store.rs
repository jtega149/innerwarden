//! Persistent state store backed by SQLite (via `innerwarden_store`).
//!
//! Replaces the previous redb implementation. Data lives in the unified
//! `innerwarden.db` SQLite database using KV namespaces.
//!
//! Namespaces:
//!   - ip_reputations:          IP → JSON (LocalIpReputation)
//!   - decision_cooldowns:      key → timestamp_ms (i64 LE bytes)
//!   - notification_cooldowns:  key → timestamp_ms (i64 LE bytes)
//!   - block_counts:            IP → count (u32 LE bytes)
//!   - xdp_block_times:         IP → JSON { blocked_at_ms, ttl_secs }
//!   - trust_rules:             "detector:action" → [1u8]
//!   - attacker_profiles:       IP → JSON (AttackerProfile)

use anyhow::{Context, Result};
use innerwarden_store::Store;
use std::path::Path;
use tracing::{info, warn};

/// Namespace constants
const NS_IP_REPUTATIONS: &str = "ip_reputations";
const NS_DECISION_COOLDOWNS: &str = "decision_cooldowns";
const NS_NOTIFICATION_COOLDOWNS: &str = "notification_cooldowns";
const NS_BLOCK_COUNTS: &str = "block_counts";
const NS_XDP_BLOCK_TIMES: &str = "xdp_block_times";
const NS_TRUST_RULES: &str = "trust_rules";
const NS_ATTACKER_PROFILES: &str = "attacker_profiles";

/// Persistent state store for the agent.
pub struct StateStore {
    store: Store,
}

#[allow(dead_code)]
impl StateStore {
    /// Open or create the state database at `data_dir/innerwarden.db`.
    pub fn open(data_dir: &Path) -> Result<Self> {
        let store = Store::open(data_dir)
            .with_context(|| format!("failed to open state store: {}", data_dir.display()))?;

        info!(path = %data_dir.display(), "state store opened (sqlite)");
        Ok(Self { store })
    }

    // ── IP Reputations ──────────────────────────────────────────────

    pub fn get_ip_reputation(&self, ip: &str) -> Option<serde_json::Value> {
        match self.store.kv_get(NS_IP_REPUTATIONS, ip) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
            Ok(None) => None,
            Err(e) => {
                warn!(error = %e, "get_ip_reputation failed");
                None
            }
        }
    }

    pub fn set_ip_reputation(&self, ip: &str, value: &serde_json::Value) {
        let data = serde_json::to_vec(value).unwrap_or_default();
        if let Err(e) = self.store.kv_set(NS_IP_REPUTATIONS, ip, &data) {
            warn!(error = %e, "set_ip_reputation failed");
        }
    }

    pub fn all_ip_reputations(&self) -> Vec<(String, serde_json::Value)> {
        match self.store.kv_list(NS_IP_REPUTATIONS) {
            Ok(entries) => entries
                .into_iter()
                .filter_map(|(k, v)| {
                    serde_json::from_slice::<serde_json::Value>(&v)
                        .ok()
                        .map(|val| (k, val))
                })
                .collect(),
            Err(e) => {
                warn!(error = %e, "all_ip_reputations failed");
                Vec::new()
            }
        }
    }

    pub fn ip_reputations_len(&self) -> usize {
        self.store.kv_count(NS_IP_REPUTATIONS).unwrap_or(0)
    }

    /// Remove entries beyond `max` by keeping the most recently seen.
    /// Called during slow-loop cleanup.
    pub fn trim_ip_reputations(&self, max: usize) {
        let len = self.ip_reputations_len();
        if len <= max {
            return;
        }
        // Collect all, sort by last_seen, keep top `max`
        let mut all = self.all_ip_reputations();
        all.sort_by(|a, b| {
            let ts_a = a.1["last_seen"].as_str().unwrap_or("");
            let ts_b = b.1["last_seen"].as_str().unwrap_or("");
            ts_b.cmp(ts_a) // newest first
        });
        let to_remove: Vec<String> = all.into_iter().skip(max).map(|(k, _)| k).collect();
        for ip in &to_remove {
            if let Err(e) = self.store.kv_delete(NS_IP_REPUTATIONS, ip) {
                warn!(error = %e, ip = %ip, "trim_ip_reputations delete failed");
            }
        }
    }

    // ── Cooldowns (decision + notification) ─────────────────────────

    pub fn get_cooldown(
        &self,
        table_def: CooldownTable,
        key: &str,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        let ns = table_def.namespace();
        match self.store.kv_get(ns, key) {
            Ok(Some(bytes)) => {
                if bytes.len() == 8 {
                    let ms = i64::from_le_bytes(bytes.try_into().ok()?);
                    chrono::DateTime::from_timestamp_millis(ms)
                } else {
                    None
                }
            }
            Ok(None) => None,
            Err(e) => {
                warn!(error = %e, "get_cooldown failed");
                None
            }
        }
    }

    pub fn set_cooldown(
        &self,
        table_def: CooldownTable,
        key: &str,
        ts: chrono::DateTime<chrono::Utc>,
    ) {
        let ns = table_def.namespace();
        let bytes = ts.timestamp_millis().to_le_bytes();
        if let Err(e) = self.store.kv_set(ns, key, &bytes) {
            warn!(error = %e, "set_cooldown failed");
        }
    }

    pub fn has_cooldown(&self, table_def: CooldownTable, key: &str) -> bool {
        self.get_cooldown(table_def, key).is_some()
    }

    /// Remove entries older than `cutoff`.
    pub fn retain_cooldowns(
        &self,
        table_def: CooldownTable,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) {
        let ns = table_def.namespace();
        let cutoff_ms = cutoff.timestamp_millis();
        let entries = match self.store.kv_list(ns) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "retain_cooldowns list failed");
                return;
            }
        };
        for (key, bytes) in entries {
            if bytes.len() == 8 {
                let ms = i64::from_le_bytes(bytes.try_into().unwrap());
                if ms <= cutoff_ms {
                    if let Err(e) = self.store.kv_delete(ns, &key) {
                        warn!(error = %e, key = %key, "retain_cooldowns delete failed");
                    }
                }
            }
        }
    }

    // ── Block Counts ────────────────────────────────────────────────

    pub fn get_block_count(&self, ip: &str) -> u32 {
        match self.store.kv_get(NS_BLOCK_COUNTS, ip) {
            Ok(Some(bytes)) if bytes.len() == 4 => {
                u32::from_le_bytes(bytes.try_into().unwrap())
            }
            Ok(_) => 0,
            Err(e) => {
                warn!(error = %e, "get_block_count failed");
                0
            }
        }
    }

    pub fn increment_block_count(&self, ip: &str) -> u32 {
        let current = self.get_block_count(ip);
        let new_count = current + 1;
        let bytes = new_count.to_le_bytes();
        if let Err(e) = self.store.kv_set(NS_BLOCK_COUNTS, ip, &bytes) {
            warn!(error = %e, "increment_block_count failed");
        }
        new_count
    }

    pub fn clear_block_counts(&self) {
        if let Err(e) = self.store.kv_clear(NS_BLOCK_COUNTS) {
            warn!(error = %e, "clear_block_counts failed");
        }
    }

    pub fn block_counts_len(&self) -> usize {
        self.store.kv_count(NS_BLOCK_COUNTS).unwrap_or(0)
    }

    // ── XDP Block Times ─────────────────────────────────────────────

    pub fn get_xdp_block_time(&self, ip: &str) -> Option<(chrono::DateTime<chrono::Utc>, i64)> {
        match self.store.kv_get(NS_XDP_BLOCK_TIMES, ip) {
            Ok(Some(bytes)) => {
                let val: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
                let blocked_at = val["blocked_at_ms"].as_i64()?;
                let ttl = val["ttl_secs"].as_i64().unwrap_or(0);
                Some((chrono::DateTime::from_timestamp_millis(blocked_at)?, ttl))
            }
            Ok(None) => None,
            Err(e) => {
                warn!(error = %e, "get_xdp_block_time failed");
                None
            }
        }
    }

    pub fn set_xdp_block_time(
        &self,
        ip: &str,
        blocked_at: chrono::DateTime<chrono::Utc>,
        ttl_secs: i64,
    ) {
        let val = serde_json::json!({
            "blocked_at_ms": blocked_at.timestamp_millis(),
            "ttl_secs": ttl_secs,
        });
        let data = serde_json::to_vec(&val).unwrap_or_default();
        if let Err(e) = self.store.kv_set(NS_XDP_BLOCK_TIMES, ip, &data) {
            warn!(error = %e, "set_xdp_block_time failed");
        }
    }

    pub fn remove_xdp_block_time(&self, ip: &str) {
        if let Err(e) = self.store.kv_delete(NS_XDP_BLOCK_TIMES, ip) {
            warn!(error = %e, "remove_xdp_block_time failed");
        }
    }

    pub fn all_xdp_block_times(&self) -> Vec<(String, chrono::DateTime<chrono::Utc>, i64)> {
        match self.store.kv_list(NS_XDP_BLOCK_TIMES) {
            Ok(entries) => entries
                .into_iter()
                .filter_map(|(k, v)| {
                    let val: serde_json::Value = serde_json::from_slice(&v).ok()?;
                    let ms = val["blocked_at_ms"].as_i64()?;
                    let ttl = val["ttl_secs"].as_i64()?;
                    let dt = chrono::DateTime::from_timestamp_millis(ms)?;
                    Some((k, dt, ttl))
                })
                .collect(),
            Err(e) => {
                warn!(error = %e, "all_xdp_block_times failed");
                Vec::new()
            }
        }
    }

    // ── Trust Rules ─────────────────────────────────────────────────

    pub fn has_trust_rule(&self, key: &str) -> bool {
        match self.store.kv_get(NS_TRUST_RULES, key) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                warn!(error = %e, "has_trust_rule failed");
                false
            }
        }
    }

    pub fn add_trust_rule(&self, key: &str) {
        if let Err(e) = self.store.kv_set(NS_TRUST_RULES, key, &[1u8]) {
            warn!(error = %e, "add_trust_rule failed");
        }
    }

    // ── Attacker Profiles ────────────────────────────────────────────

    pub fn get_attacker_profile(&self, ip: &str) -> Option<serde_json::Value> {
        match self.store.kv_get(NS_ATTACKER_PROFILES, ip) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
            Ok(None) => None,
            Err(e) => {
                warn!(error = %e, "get_attacker_profile failed");
                None
            }
        }
    }

    pub fn set_attacker_profile(&self, ip: &str, value: &serde_json::Value) {
        let data = serde_json::to_vec(value).unwrap_or_default();
        if let Err(e) = self.store.kv_set(NS_ATTACKER_PROFILES, ip, &data) {
            warn!(error = %e, "set_attacker_profile failed");
        }
    }

    pub fn all_attacker_profiles(&self) -> Vec<(String, serde_json::Value)> {
        match self.store.kv_list(NS_ATTACKER_PROFILES) {
            Ok(entries) => entries
                .into_iter()
                .filter_map(|(k, v)| {
                    serde_json::from_slice::<serde_json::Value>(&v)
                        .ok()
                        .map(|val| (k, val))
                })
                .collect(),
            Err(e) => {
                warn!(error = %e, "all_attacker_profiles failed");
                Vec::new()
            }
        }
    }

    pub fn remove_attacker_profile(&self, ip: &str) {
        if let Err(e) = self.store.kv_delete(NS_ATTACKER_PROFILES, ip) {
            warn!(error = %e, "remove_attacker_profile failed");
        }
    }

    pub fn attacker_profiles_len(&self) -> usize {
        self.store.kv_count(NS_ATTACKER_PROFILES).unwrap_or(0)
    }

    /// Remove entries beyond `max` by keeping those with the highest risk_score.
    pub fn trim_attacker_profiles(&self, max: usize) {
        let len = self.attacker_profiles_len();
        if len <= max {
            return;
        }
        let mut all = self.all_attacker_profiles();
        // Sort by risk_score descending, then last_seen descending
        all.sort_by(|a, b| {
            let score_a = a.1["risk_score"].as_u64().unwrap_or(0);
            let score_b = b.1["risk_score"].as_u64().unwrap_or(0);
            score_b.cmp(&score_a).then_with(|| {
                let ts_a = a.1["last_seen"].as_str().unwrap_or("");
                let ts_b = b.1["last_seen"].as_str().unwrap_or("");
                ts_b.cmp(ts_a)
            })
        });
        let to_remove: Vec<String> = all.into_iter().skip(max).map(|(k, _)| k).collect();
        for ip in &to_remove {
            if let Err(e) = self.store.kv_delete(NS_ATTACKER_PROFILES, ip) {
                warn!(error = %e, ip = %ip, "trim_attacker_profiles delete failed");
            }
        }
    }

    /// Checkpoint the WAL (replaces redb compact).
    pub fn compact(&mut self) {
        if let Err(e) = self.store.wal_checkpoint() {
            warn!(error = %e, "state store WAL checkpoint failed");
        }
    }
}

/// Which cooldown table to operate on.
#[derive(Clone, Copy)]
pub enum CooldownTable {
    Decision,
    Notification,
}

impl CooldownTable {
    fn namespace(&self) -> &'static str {
        match self {
            CooldownTable::Decision => NS_DECISION_COOLDOWNS,
            CooldownTable::Notification => NS_NOTIFICATION_COOLDOWNS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_store() -> (TempDir, StateStore) {
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn cooldown_insert_and_get() {
        let (_dir, store) = make_store();
        let now = chrono::Utc::now();
        store.set_cooldown(CooldownTable::Decision, "test:key", now);
        assert!(store.has_cooldown(CooldownTable::Decision, "test:key"));
        assert!(!store.has_cooldown(CooldownTable::Decision, "other:key"));
    }

    #[test]
    fn block_count_increment() {
        let (_dir, store) = make_store();
        assert_eq!(store.get_block_count("1.2.3.4"), 0);
        store.increment_block_count("1.2.3.4");
        assert_eq!(store.get_block_count("1.2.3.4"), 1);
        store.increment_block_count("1.2.3.4");
        assert_eq!(store.get_block_count("1.2.3.4"), 2);
    }

    #[test]
    fn ip_reputation_roundtrip() {
        let (_dir, store) = make_store();
        let val = serde_json::json!({"score": 42, "last_seen": "2026-01-01T00:00:00Z"});
        store.set_ip_reputation("10.0.0.1", &val);
        let got = store.get_ip_reputation("10.0.0.1").unwrap();
        assert_eq!(got["score"], 42);
        assert_eq!(store.ip_reputations_len(), 1);
    }

    #[test]
    fn trust_rule_add_and_check() {
        let (_dir, store) = make_store();
        assert!(!store.has_trust_rule("ssh:block"));
        store.add_trust_rule("ssh:block");
        assert!(store.has_trust_rule("ssh:block"));
    }

    #[test]
    fn xdp_block_time_roundtrip() {
        let (_dir, store) = make_store();
        let now = chrono::Utc::now();
        store.set_xdp_block_time("5.6.7.8", now, 3600);
        let (dt, ttl) = store.get_xdp_block_time("5.6.7.8").unwrap();
        assert_eq!(ttl, 3600);
        assert!((dt - now).num_seconds().abs() < 1);
    }

    #[test]
    fn retain_cooldowns_removes_old() {
        let (_dir, store) = make_store();
        let old = chrono::Utc::now() - chrono::Duration::hours(3);
        let recent = chrono::Utc::now();
        store.set_cooldown(CooldownTable::Decision, "old:key", old);
        store.set_cooldown(CooldownTable::Decision, "new:key", recent);
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(2);
        store.retain_cooldowns(CooldownTable::Decision, cutoff);
        assert!(!store.has_cooldown(CooldownTable::Decision, "old:key"));
        assert!(store.has_cooldown(CooldownTable::Decision, "new:key"));
    }

    #[test]
    fn attacker_profile_roundtrip() {
        let (_dir, store) = make_store();
        let val = serde_json::json!({"ip": "10.0.0.1", "risk_score": 75, "last_seen": "2026-03-29T00:00:00Z"});
        store.set_attacker_profile("10.0.0.1", &val);
        let got = store.get_attacker_profile("10.0.0.1").unwrap();
        assert_eq!(got["risk_score"], 75);
        assert_eq!(store.attacker_profiles_len(), 1);
    }

    #[test]
    fn trim_attacker_profiles_keeps_highest_risk() {
        let (_dir, store) = make_store();
        for i in 0..5u64 {
            let val =
                serde_json::json!({"risk_score": i * 10, "last_seen": "2026-01-01T00:00:00Z"});
            store.set_attacker_profile(&format!("10.0.0.{i}"), &val);
        }
        assert_eq!(store.attacker_profiles_len(), 5);
        store.trim_attacker_profiles(3);
        assert_eq!(store.attacker_profiles_len(), 3);
        // Lowest risk (0, 10) should be removed
        assert!(store.get_attacker_profile("10.0.0.4").is_some()); // risk 40
        assert!(store.get_attacker_profile("10.0.0.0").is_none()); // risk 0
    }

    #[test]
    fn trim_ip_reputations_keeps_newest() {
        let (_dir, store) = make_store();
        for i in 0..5 {
            let val = serde_json::json!({"last_seen": format!("2026-01-0{}T00:00:00Z", i + 1)});
            store.set_ip_reputation(&format!("10.0.0.{i}"), &val);
        }
        assert_eq!(store.ip_reputations_len(), 5);
        store.trim_ip_reputations(3);
        assert_eq!(store.ip_reputations_len(), 3);
    }
}
