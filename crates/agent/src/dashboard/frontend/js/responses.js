// ── Enforcement health section (2026-05-15) ─────────────────────
// Replaces the standalone Responses tab. Renders into the Health tab:
//   - lifetime totals (counters, monotonic since boot)
//   - gauges (current state)
//   - orphan diagnostic panel (when orphans > 0)
// Used by status.js::loadStatus to mount under the existing Health tab.
//
// The per-attacker enforcement view + cross-attacker audit modal live
// in journey.js (renderEnforcementBlock) and threats.js
// (openEnforcementModal) respectively — both consume /api/responses too.

async function renderEnforcementHealthSection(mountSelector) {
  var mount = typeof mountSelector === 'string'
    ? document.getElementById(mountSelector)
    : mountSelector;
  if (!mount) return;
  mount.innerHTML = '<div style="color:var(--muted);font-size:0.78rem">Loading enforcement stats…</div>';
  try {
    const r = await loadJson('/api/responses');
    let html = '<h3 class="status-section-title" style="margin-top:18px;">Enforcement</h3>';

    // PR #425 Wave 4d: gauges (now) vs counters (lifetime) explicit.
    // Pre-Wave-4d the dashboard banner read totals.orphaned (counter,
    // monotonic), which gaslit the operator into seeing "17 orphaned
    // (rule may still be active)" months after the entries had been
    // GC'd. Now the banner / drift warning use only `gauges.orphaned`
    // (count of entries that really are orphaned right now). Lifetime
    // counters move to a clearly-labeled row below.
    const gOrphans   = r.gauges?.orphaned ?? r.state_counts?.revert_failed ?? 0;
    const gPending   = r.gauges?.pending  ?? r.state_counts?.revert_pending ?? 0;
    const gInRetry   = r.gauges?.in_retry ?? r.state_counts?.revert_failed ?? 0;
    const gActive    = r.gauges?.active   ?? r.active_count ?? 0;
    const tOrphaned  = r.totals?.orphaned       || 0;
    const tFailures  = r.totals?.revert_failures|| 0;
    const tAlreadyAbsent = r.totals?.already_absent || 0;
    const tExpired   = r.totals?.expired   || 0;
    const tManual    = r.totals?.reverted  || 0;
    const tRegistered= r.totals?.registered|| 0;

    // Row 1 — current state (gauges). What's happening right now.
    html += `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:8px;">
      <div class="kpi-card">
        <div class="kpi-value">${gActive}</div>
        <div class="kpi-label" title="Number of responses currently active in the kernel/firewall.">Active <span style="color:var(--dim);font-weight:400">(now)</span></div>
      </div>
      <div class="kpi-card" style="${gOrphans > 0 ? 'border-color:#e74c3c;background:#e74c3c10;' : ''}">
        <div class="kpi-value" style="${gOrphans > 0 ? 'color:#e74c3c' : ''}">${gOrphans}</div>
        <div class="kpi-label" title="Orphaned responses still pending operator review (history entries with reason='orphaned:' plus any active entry stuck in revert_failed). Excludes orphans that PR #408's GC has already pruned.">Orphaned <span style="color:var(--dim);font-weight:400">(now)</span></div>
      </div>
      <div class="kpi-card" style="${gInRetry > 0 ? 'border-color:#f39c12;' : ''}">
        <div class="kpi-value" style="${gInRetry > 0 ? 'color:#f39c12' : ''}">${gInRetry}</div>
        <div class="kpi-label" title="Entries currently mid-retry (transient revert failures).">In Retry <span style="color:var(--dim);font-weight:400">(now)</span></div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value">${gPending}</div>
        <div class="kpi-label" title="Revert command dispatched to executor, awaiting result.">Pending <span style="color:var(--dim);font-weight:400">(now)</span></div>
      </div>
    </div>`;

    // Row 2 — lifetime totals (counters). Monotonic, never decrement.
    // Operator sees these to understand the system's overall track
    // record, not to act on them. Visually separated from gauges
    // above so the difference is unambiguous.
    html += `<div style="font-size:0.7rem;color:var(--dim);letter-spacing:0.05em;text-transform:uppercase;margin:4px 0 6px;">Lifetime totals (cumulative since boot)</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:16px;">
      <div class="kpi-card"><div class="kpi-value">${tRegistered}</div><div class="kpi-label" title="Every response action ever registered.">Total Registered</div></div>
      <div class="kpi-card"><div class="kpi-value">${tExpired}</div><div class="kpi-label" title="Reverteds that expired naturally via TTL. Counts as success.">Expired</div></div>
      <div class="kpi-card"><div class="kpi-value">${tManual}</div><div class="kpi-label" title="Reverteds explicitly removed via the dashboard. Most reverteds expire naturally and count as 'Expired', not here.">Manual Reverts</div></div>
      <div class="kpi-card"><div class="kpi-value">${tAlreadyAbsent}</div><div class="kpi-label" title="Reverteds that resolved because the rule was already gone (success).">Already Gone</div></div>
      <div class="kpi-card"><div class="kpi-value">${tFailures}</div><div class="kpi-label" title="Lifetime count of individual failed revert attempts (most are retried successfully).">Revert Failures</div></div>
      <div class="kpi-card"><div class="kpi-value">${tOrphaned}</div><div class="kpi-label" title="Lifetime count of entries that exhausted retries and were marked orphaned. The 'Orphaned (now)' card above is the actionable subset.">Orphaned (lifetime)</div></div>
    </div>`;

    // Drift warning banner — fires only on CURRENT-state drift, not
    // historical counters. Pre-Wave-4d this used the lifetime counter,
    // which screamed "17 orphans, rule may still be active" months
    // after PR #408's GC had pruned every entry.
    const hasDrift = gOrphans > 0 || gInRetry > 0;
    if (hasDrift) {
      html += `<div style="padding:10px 14px;margin-bottom:14px;border-left:3px solid #e74c3c;background:#e74c3c10;border-radius:3px;font-size:0.85rem;">
        <strong style="color:#e74c3c;display:inline-flex;align-items:center;gap:4px">${lucideIcon('alert-triangle',{size:14})} State drift detected.</strong>
        ${gOrphans > 0 ? `<span>${gOrphans} orphaned response(s) currently pending operator review — rule may still be active in kernel/firewall. Check WARN logs for stderr.</span>` : ''}
        ${gInRetry > 0 ? `<span>${gInRetry} response(s) mid-retry.</span>` : ''}
      </div>`;
    }

    // 2026-05-03 (PR #419 Wave 2): if orphans exist, append a
    // collapsible "Diagnose orphans" panel that lazy-loads the
    // /api/responses/orphans endpoint with clear / mark-already-gone
    // actions behind 2FA.
    if (gOrphans > 0) {
      html += renderOrphanDiagnosticPanel();
    } else {
      html += '<p style="color:var(--dim);margin:10px 0 0;font-size:0.78rem">No orphaned responses. All revert flows are reconciled with the kernel.</p>';
    }

    // 2026-05-15: footnote pointing the operator at the where-each-piece-went map.
    html += '<p style="color:var(--dim);font-size:0.7rem;margin-top:14px;">'
      + 'Per-attacker enforcement detail lives on the journey panel (open any attacker on Cases). '
      + 'Cross-attacker audit: "View all enforcement" link on the Cases sidebar. '
      + 'Historical reverts: <code>innerwarden responses history</code>.'
      + '</p>';

    mount.innerHTML = html;
  } catch(e) {
    mount.innerHTML = '<p style="color:#e74c3c">Failed to load enforcement stats: ' + esc(e.message || String(e)) + '</p>';
  }
}

// ── 2026-05-03 (PR #419 Wave 2) — orphan diagnostic ────────────────
//
// Read-only panel surfaced when there are >0 orphaned responses.
// Fetches /api/responses/orphans which returns:
//   - orphans: array of per-orphan diagnostic (last_error, cluster,
//     revert_command, kernel_state, etc.)
//   - clusters: array of {cluster, count, suggested_fix}
//   - probe_available: bool — whether ufw/iptables probe ran
// Renders a cluster summary at the top + per-orphan card below.
// Wave 3 adds the remediation buttons; for now the operator sees
// the diagnostic and acts via SSH if needed.

const ORPHAN_CLUSTER_LABELS = {
  ipv6_mismatch: { icon: '🌐', label: 'IPv6 / IPv4 mismatch' },
  nftables_handle_missing: { icon: '🔧', label: 'nftables handle missing' },
  rule_already_absent: { icon: '✅', label: 'Rule already gone (false orphan)' },
  permission_denied: { icon: '🔒', label: 'Permission / sudo' },
  external_mutation: { icon: '🌀', label: 'External mutation' },
  unknown: { icon: '❓', label: 'Unclassified' },
};

const ORPHAN_KERNEL_STATE_BADGE = {
  still_blocked: { color: '#f39c12', label: 'Rule still active in kernel' },
  already_gone: { color: '#27ae60', label: 'Rule already removed' },
  probe_failed: { color: 'var(--dim)', label: 'Could not probe kernel state' },
};

function renderOrphanDiagnosticPanel() {
  return `
    <details id="orphanDiagnosticPanel" class="orphan-diag-panel" style="margin-top:18px;border:1px solid var(--border);border-radius:8px;background:rgba(231,76,60,0.04);">
      <summary onclick="loadOrphanDiagnostics()" style="padding:12px 14px;cursor:pointer;font-weight:600;font-size:0.9rem;color:var(--text);list-style:none;">
        ▸ Diagnose orphaned responses
        <span style="font-weight:400;font-size:0.78rem;color:var(--dim);margin-left:8px;">(read + clear / mark-already-gone with 2FA)</span>
      </summary>
      <div id="orphanDiagBody" style="padding:14px;border-top:1px solid var(--border);">
        <p style="color:var(--dim);font-size:0.82rem;">Loading diagnostic…</p>
      </div>
    </details>`;
}

let _orphanDiagLoaded = false;
async function loadOrphanDiagnostics() {
  if (_orphanDiagLoaded) return;
  _orphanDiagLoaded = true;
  const body = document.getElementById('orphanDiagBody');
  if (!body) return;
  try {
    const data = await loadJson('/api/responses/orphans');
    const orphans = Array.isArray(data.orphans) ? data.orphans : [];
    const clusters = Array.isArray(data.clusters) ? data.clusters : [];
    if (orphans.length === 0) {
      body.innerHTML = '<p style="color:var(--dim);font-size:0.82rem;">No orphans to diagnose right now.</p>';
      return;
    }
    let html = '';
    // Cluster summary header.
    if (clusters.length > 0) {
      html += '<div style="margin-bottom:14px;">';
      html += '<div style="font-size:0.78rem;font-weight:700;color:var(--accent);letter-spacing:0.05em;text-transform:uppercase;margin-bottom:8px;">Root cause clusters</div>';
      // Sort: highest count first.
      const sorted = clusters.slice().sort((a, b) => b.count - a.count);
      sorted.forEach((c) => {
        const meta = ORPHAN_CLUSTER_LABELS[c.cluster] || { icon: '❓', label: c.cluster };
        html += `
          <div class="orphan-cluster-card" style="padding:10px 12px;border-radius:6px;background:var(--card-bg);margin-bottom:6px;border-left:3px solid var(--accent);">
            <div style="display:flex;align-items:baseline;gap:8px;margin-bottom:4px;">
              <span style="font-size:1.1rem;line-height:1;">${meta.icon}</span>
              <strong style="font-size:0.88rem;">${esc(meta.label)}</strong>
              <span style="font-size:0.72rem;color:var(--dim);">${c.count} ${c.count === 1 ? 'orphan' : 'orphans'}</span>
            </div>
            <div style="font-size:0.78rem;color:var(--dim);line-height:1.5;">${esc(c.suggested_fix)}</div>
          </div>`;
      });
      html += '</div>';
    }

    // Probe-availability hint.
    if (!data.probe_available) {
      html += `
        <div style="padding:8px 12px;margin-bottom:12px;background:rgba(243,156,18,0.08);border:1px solid rgba(243,156,18,0.2);border-radius:4px;font-size:0.78rem;color:var(--dim);">
          ${lucideIcon('alert-triangle',{size:13})}
          Could not probe live ufw/iptables state — agent likely lacks sudo for status commands. Rule-state column will show "—".
        </div>`;
    }

    // Per-orphan cards.
    html += '<div style="font-size:0.78rem;font-weight:700;color:var(--accent);letter-spacing:0.05em;text-transform:uppercase;margin-bottom:8px;">Per-orphan diagnostic</div>';
    orphans.forEach((o) => { html += renderOrphanCard(o); });

    body.innerHTML = html;
  } catch (e) {
    body.innerHTML = `<p style="color:#e74c3c;font-size:0.82rem;">Failed to load diagnostic: ${esc(e.message)}</p>`;
    _orphanDiagLoaded = false;  // allow retry on next open
  }
}

function renderOrphanCard(o) {
  const cluster = ORPHAN_CLUSTER_LABELS[o.cluster] || { icon: '❓', label: o.cluster };
  const state = ORPHAN_KERNEL_STATE_BADGE[o.kernel_state] || { color: 'var(--dim)', label: o.kernel_state };
  const ageMin = Math.max(0, Math.floor((Date.now() - new Date(o.reverted_at).getTime()) / 60000));
  const ageStr = ageMin < 60
    ? `${ageMin}m ago`
    : ageMin < 1440
      ? `${Math.floor(ageMin / 60)}h ago`
      : `${Math.floor(ageMin / 1440)}d ago`;
  // PR #420 Wave 3: when an operator has already resolved this orphan,
  // show their decision and date in place of the action buttons.
  const resolvedBlock = o.resolution
    ? `<div style="margin-top:8px;padding:6px 10px;border-radius:4px;background:rgba(39,174,96,0.08);border:1px solid rgba(39,174,96,0.25);font-size:0.74rem;color:var(--text);">
         ${lucideIcon('check-circle',{size:13})}
         Resolved as <strong>${esc(o.resolution.kind)}</strong>
         by <code>${esc(o.resolution.operator)}</code>
         · ${new Date(o.resolution.resolved_at).toLocaleString()}
         <div style="font-size:0.7rem;color:var(--dim);margin-top:2px;">${esc(o.resolution.reason)}</div>
       </div>`
    : `<div class="orphan-actions" style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;">
         <button type="button" class="btn-orphan-clear" data-orphan-id="${esc(o.id)}"
           onclick="openOrphanResolveModal('${esc(o.id)}','cleared','${esc(o.target)}')"
           style="padding:4px 10px;font-size:0.78rem;border-radius:4px;border:1px solid var(--border);background:var(--card-bg);color:var(--text);cursor:pointer;">
           Clear orphan
         </button>
         <button type="button" class="btn-orphan-mark-already-gone" data-orphan-id="${esc(o.id)}"
           onclick="openOrphanResolveModal('${esc(o.id)}','already_gone','${esc(o.target)}')"
           style="padding:4px 10px;font-size:0.78rem;border-radius:4px;border:1px solid var(--border);background:var(--card-bg);color:var(--text);cursor:pointer;">
           Mark already gone
         </button>
       </div>`;
  return `
    <div class="orphan-card" style="padding:12px 14px;border-radius:6px;background:var(--card-bg);margin-bottom:8px;border:1px solid var(--border);">
      <div style="display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin-bottom:6px;">
        <code style="font-family:monospace;font-size:0.82rem;font-weight:600;color:var(--text);">${esc(o.target)}</code>
        <span style="font-size:0.72rem;padding:1px 6px;border-radius:3px;background:rgba(127,231,255,0.08);color:var(--accent);text-transform:uppercase;">${esc(o.backend)}</span>
        <span style="font-size:0.72rem;color:${state.color};">${state.label}</span>
        <span style="font-size:0.72rem;color:var(--dim);">${ageStr}</span>
      </div>
      <div style="font-size:0.78rem;color:var(--text);margin-bottom:6px;line-height:1.5;">
        <span style="font-weight:600;">${cluster.icon} ${esc(cluster.label)}</span>
      </div>
      <div style="font-size:0.74rem;color:var(--dim);font-family:monospace;background:rgba(0,0,0,0.15);padding:6px 8px;border-radius:3px;margin-bottom:6px;word-break:break-all;">
        ${esc(o.revert_command)}
      </div>
      <details>
        <summary style="font-size:0.74rem;color:var(--dim);cursor:pointer;">stderr from last attempt</summary>
        <pre style="font-size:0.72rem;color:var(--dim);background:rgba(0,0,0,0.15);padding:6px 8px;border-radius:3px;margin-top:4px;overflow-x:auto;white-space:pre-wrap;">${esc(o.last_error || '(empty)')}</pre>
      </details>
      ${o.incident_id ? `<div style="font-size:0.7rem;color:var(--dim);margin-top:4px;">incident: <code>${esc(o.incident_id)}</code></div>` : ''}
      ${resolvedBlock}
    </div>`;
}

// ─── PR #420 Wave 3 — orphan resolution modal + POST helpers ─────
//
// Buttons on each orphan card open a modal that collects the reason
// + (optional) TOTP code, then POSTs to the matching endpoint with
// the X-Requested-With header that the CSRF middleware requires.
// On success, the panel reloads so the operator sees the resolved
// state immediately.

const ORPHAN_KIND_LABEL = {
  cleared: 'Clear orphan',
  already_gone: 'Mark already gone',
};

function openOrphanResolveModal(orphanId, kind, target) {
  const existing = document.getElementById('orphanResolveModal');
  if (existing) existing.remove();
  const modal = document.createElement('div');
  modal.id = 'orphanResolveModal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:9999;';
  modal.innerHTML = `
    <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:18px;max-width:440px;width:90%;">
      <h3 style="margin:0 0 4px;font-size:1rem;color:var(--text);">${ORPHAN_KIND_LABEL[kind] || kind}</h3>
      <p style="margin:0 0 12px;font-size:0.78rem;color:var(--dim);">Target: <code>${esc(target)}</code></p>
      <label style="display:block;font-size:0.78rem;color:var(--text);margin-bottom:4px;">Reason (required)</label>
      <textarea id="orphanResolveReason" rows="3" style="width:100%;box-sizing:border-box;padding:6px;border:1px solid var(--border);border-radius:4px;background:var(--card-bg);color:var(--text);font-family:inherit;font-size:0.82rem;margin-bottom:10px;" placeholder="Brief operator note for the audit trail"></textarea>
      <label style="display:block;font-size:0.78rem;color:var(--text);margin-bottom:4px;">TOTP code <span style="color:var(--dim);">(if 2FA enabled — leave blank otherwise)</span></label>
      <input id="orphanResolveTotp" type="text" inputmode="numeric" maxlength="6" autocomplete="one-time-code" style="width:120px;padding:6px;border:1px solid var(--border);border-radius:4px;background:var(--card-bg);color:var(--text);font-family:monospace;font-size:0.9rem;letter-spacing:0.2em;" placeholder="000000" />
      <div id="orphanResolveError" style="color:#e74c3c;font-size:0.78rem;margin-top:8px;display:none;"></div>
      <div style="margin-top:14px;display:flex;justify-content:flex-end;gap:8px;">
        <button type="button" onclick="closeOrphanResolveModal()" style="padding:6px 12px;font-size:0.82rem;border-radius:4px;border:1px solid var(--border);background:var(--card-bg);color:var(--text);cursor:pointer;">Cancel</button>
        <button type="button" id="orphanResolveSubmit" onclick="submitOrphanResolve('${esc(orphanId)}','${esc(kind)}')" style="padding:6px 12px;font-size:0.82rem;border-radius:4px;border:1px solid var(--accent);background:var(--accent);color:#000;cursor:pointer;font-weight:600;">Confirm</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
  document.getElementById('orphanResolveReason')?.focus();
}

function closeOrphanResolveModal() {
  const el = document.getElementById('orphanResolveModal');
  if (el) el.remove();
}

async function submitOrphanResolve(orphanId, kind) {
  const reasonEl = document.getElementById('orphanResolveReason');
  const totpEl = document.getElementById('orphanResolveTotp');
  const errEl = document.getElementById('orphanResolveError');
  const btn = document.getElementById('orphanResolveSubmit');
  const reason = (reasonEl?.value || '').trim();
  const totp = (totpEl?.value || '').trim();
  if (errEl) { errEl.style.display = 'none'; errEl.textContent = ''; }
  if (!reason) {
    if (errEl) { errEl.textContent = 'Reason is required.'; errEl.style.display = 'block'; }
    return;
  }
  if (btn) { btn.disabled = true; btn.textContent = 'Submitting…'; }
  const path = kind === 'cleared'
    ? `/api/responses/orphans/${encodeURIComponent(orphanId)}/clear`
    : `/api/responses/orphans/${encodeURIComponent(orphanId)}/mark-already-gone`;
  try {
    const resp = await fetch(path, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        // Required by the CSRF middleware (audit I-14). Browsers will
        // not let a cross-origin <form> set this header, so requiring
        // it blocks form-based CSRF without per-session tokens.
        'x-requested-with': 'XMLHttpRequest',
      },
      body: JSON.stringify({ reason, totp }),
      credentials: 'include',
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => `HTTP ${resp.status}`);
      throw new Error(text || `HTTP ${resp.status}`);
    }
    closeOrphanResolveModal();
    // Reload diagnostic so the resolved card flips to the read-only
    // "Resolved by ..." block.
    _orphanDiagLoaded = false;
    const body = document.getElementById('orphanDiagBody');
    if (body) body.innerHTML = '<p style="color:var(--dim);font-size:0.82rem;">Reloading…</p>';
    loadOrphanDiagnostics();
  } catch (e) {
    if (errEl) { errEl.textContent = e.message || String(e); errEl.style.display = 'block'; }
    if (btn) { btn.disabled = false; btn.textContent = 'Confirm'; }
  }
}

