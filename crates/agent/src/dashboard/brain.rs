// Auto-extracted from mod.rs — dashboard brain handlers

use super::*;

/// `GET /api/defender-brain/recent` - recent brain suggestions with AI comparison.
pub(super) async fn api_brain_recent(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let entries: Vec<serde_json::Value> = safe_read_data_file(&state.data_dir, "brain-log.json")
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    Json(serde_json::json!({ "entries": entries }))
}

/// `GET /api/defender-brain/stats` - brain performance statistics.
pub(super) async fn api_brain_stats(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let entries: Vec<serde_json::Value> = safe_read_data_file(&state.data_dir, "brain-log.json")
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let total = entries.len();
    let agreed = entries
        .iter()
        .filter(|e| e.get("agreed").and_then(|v| v.as_bool()).unwrap_or(false))
        .count();
    let tp = entries
        .iter()
        .filter(|e| e.get("feedback") == Some(&serde_json::json!(true)))
        .count();
    let fp = entries
        .iter()
        .filter(|e| e.get("feedback") == Some(&serde_json::json!(false)))
        .count();
    let unreviewed = entries
        .iter()
        .filter(|e| {
            e.get("feedback").is_none() || e.get("feedback") == Some(&serde_json::json!(null))
        })
        .count();
    let model_exists = true; // embedded in binary since v0.9.4

    // Load retrain stats from brain-stats.json
    let brain_stats: serde_json::Value = safe_read_data_file(&state.data_dir, "brain-stats.json")
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::json!({}));

    Json(serde_json::json!({
        "loaded": model_exists,
        "total_suggestions": total,
        "agreement_rate": if total > 0 { format!("{:.1}%", agreed as f32 / total as f32 * 100.0) } else { "N/A".to_string() },
        "tp_count": tp,
        "fp_count": fp,
        "unreviewed": unreviewed,
        "last_retrain": brain_stats.get("last_retrain"),
        "last_retrain_accuracy": brain_stats.get("last_retrain_accuracy"),
        "last_retrain_entries": brain_stats.get("last_retrain_entries"),
        "daily_agreement": brain_stats.get("daily_agreement"),
    }))
}

/// `POST /api/defender-brain/feedback` - mark a brain suggestion as TP or FP.
pub(super) async fn api_brain_feedback(
    State(state): State<DashboardState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let incident_id = body
        .get("incident_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let correct = body
        .get("correct")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Read, update, write back — using safe_read + validated write
    let mut entries: Vec<serde_json::Value> =
        safe_read_data_file(&state.data_dir, "brain-log.json")
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

    let mut found = false;
    for entry in entries.iter_mut().rev() {
        if entry.get("incident_id").and_then(|v| v.as_str()) == Some(incident_id) {
            entry
                .as_object_mut()
                .unwrap()
                .insert("feedback".into(), serde_json::json!(correct));
            found = true;
            break;
        }
    }
    if found {
        safe_write_data_file(
            &state.data_dir,
            "brain-log.json",
            &serde_json::to_string_pretty(&entries).unwrap_or_default(),
        );
    }

    Json(serde_json::json!({
        "ok": found,
        "incident_id": incident_id,
        "feedback": if correct { "tp" } else { "fp" },
    }))
}
