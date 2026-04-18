use crate::{abuseipdb, AgentState};

const ABUSEIPDB_CACHE_NS: &str = "abuseipdb_cache";

/// Lookup AbuseIPDB reputation for the incident primary IP.
///
/// Consults the SQLite cache populated by `incident_enrichment::backfill_enrichment`
/// before falling back to the live API. This avoids an unnecessary HTTP round-trip
/// on every incident for IPs we already rated in the last 24h and removes the
/// "no API key → always None" gap — cached entries work regardless of whether
/// the client is currently configured.
pub(crate) async fn lookup_abuseipdb_reputation(
    incident: &innerwarden_core::incident::Incident,
    state: &AgentState,
) -> Option<abuseipdb::IpReputation> {
    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str())?;

    if let Some(ref sq) = state.sqlite_store {
        if let Ok(Some(json)) = sq.kv_get_str(ABUSEIPDB_CACHE_NS, primary_ip) {
            if let Ok(rep) = serde_json::from_str::<abuseipdb::IpReputation>(&json) {
                return Some(rep);
            }
        }
    }

    let client = state.abuseipdb.as_ref()?;
    client.check(primary_ip).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn lookup_abuseipdb_reputation_returns_none_without_ip_entity() {
        let dir = TempDir::new().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let mut incident = crate::tests::test_incident("203.0.113.12");
        incident.entities.clear();

        let rep = lookup_abuseipdb_reputation(&incident, &state).await;
        assert!(rep.is_none());
    }

    #[tokio::test]
    async fn lookup_abuseipdb_reputation_prefers_cached_reputation() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let store = crate::tests::test_sqlite_store(dir.path());
        state.sqlite_store = Some(store.clone());

        let ip = "203.0.113.45";
        let incident = crate::tests::test_incident(ip);
        let cached = abuseipdb::IpReputation {
            confidence_score: 72,
            total_reports: 11,
            distinct_users: 4,
            country_code: Some("US".to_string()),
            isp: Some("Cache ISP".to_string()),
            is_tor: false,
        };
        let cached_json = serde_json::to_string(&cached).expect("cache json");
        store
            .kv_set(ABUSEIPDB_CACHE_NS, ip, cached_json.as_bytes())
            .expect("set cache");

        let rep = lookup_abuseipdb_reputation(&incident, &state)
            .await
            .expect("cached reputation");

        assert_eq!(rep.confidence_score, 72);
        assert_eq!(rep.total_reports, 11);
        assert_eq!(rep.distinct_users, 4);
        assert_eq!(rep.country_code.as_deref(), Some("US"));
        assert_eq!(rep.isp.as_deref(), Some("Cache ISP"));
        assert!(!rep.is_tor);
    }

    #[tokio::test]
    async fn lookup_abuseipdb_reputation_falls_back_when_cache_json_is_invalid() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let store = crate::tests::test_sqlite_store(dir.path());
        state.sqlite_store = Some(store.clone());
        state.abuseipdb = Some(abuseipdb::AbuseIpDbClient::new(String::new(), 30));

        let ip = "203.0.113.46";
        let incident = crate::tests::test_incident(ip);
        store
            .kv_set(ABUSEIPDB_CACHE_NS, ip, br#"{"not":"ip-reputation"}"#)
            .expect("set invalid cache json");

        // Empty API key means check() short-circuits to None without network I/O.
        let rep = lookup_abuseipdb_reputation(&incident, &state).await;
        assert!(rep.is_none());
    }
}
