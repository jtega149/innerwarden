// Auto-extracted from mod.rs — dashboard push handlers

use super::*;

// ---------------------------------------------------------------------------
// Web Push handlers
// ---------------------------------------------------------------------------

/// GET /sw.js - Service Worker that handles incoming push events.
pub(super) async fn service_worker_js() -> impl IntoResponse {
pub(super) const SW: &str = r#"
self.addEventListener('push', function(event) {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (_) {}
pub(super) const title = data.title || 'InnerWarden Alert';
pub(super) const options = {
    body: data.body || 'A new security incident was detected.',
    icon: '/favicon.ico',
    badge: '/favicon.ico',
    requireInteraction: true,
    data: data,
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  event.waitUntil(clients.openWindow('/'));
});
"#;
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        SW,
    )
}

/// GET /api/push/vapid-key - return the VAPID public key for browser subscription.
pub(super) async fn api_push_vapid_key(State(state): State<DashboardState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "publicKey": state.web_push_vapid_public_key,
        "enabled": !state.web_push_vapid_public_key.is_empty(),
    }))
}

#[derive(Deserialize)]
pub(super) struct PushSubscribeBody {
    endpoint: String,
    keys: PushSubscribeKeys,
}

#[derive(Deserialize)]
pub(super) struct PushSubscribeKeys {
    p256dh: String,
    auth: String,
}

#[derive(Deserialize)]
pub(super) struct PushUnsubscribeBody {
    endpoint: String,
}

/// POST /api/push/subscribe - register a new browser push subscription.
pub(super) async fn api_push_subscribe(
    State(state): State<DashboardState>,
    Json(body): Json<PushSubscribeBody>,
) -> impl IntoResponse {
    if state.web_push_vapid_public_key.is_empty() {
        return Json(serde_json::json!({
            "success": false,
            "message": "web push is not configured - run `innerwarden notify web-push setup`",
        }));
    }

    let sub = crate::web_push::WebPushSubscription {
        endpoint: body.endpoint.clone(),
        keys: crate::web_push::WebPushKeys {
            p256dh: body.keys.p256dh,
            auth: body.keys.auth,
        },
    };

    // Deduplicate by endpoint before saving
    let mut subs = crate::web_push::load_subscriptions(&state.data_dir);
    subs.retain(|s| s.endpoint != body.endpoint);
    subs.push(sub);

    match crate::web_push::save_subscriptions(&state.data_dir, &subs) {
        Ok(()) => Json(serde_json::json!({ "success": true })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "message": format!("failed to save subscription: {e:#}"),
        })),
    }
}

/// DELETE /api/push/subscribe - remove a push subscription by endpoint.
pub(super) async fn api_push_unsubscribe(
    State(state): State<DashboardState>,
    Json(body): Json<PushUnsubscribeBody>,
) -> impl IntoResponse {
    match crate::web_push::remove_subscription(&state.data_dir, &body.endpoint) {
        Ok(_) => Json(serde_json::json!({ "success": true })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "message": format!("failed to remove subscription: {e:#}"),
        })),
    }
}
