// ── Responses tab ────────────────────────────────────────────────
async function loadResponses() {
  const status = document.getElementById('responsesViewStatus');
  const content = document.getElementById('responsesContent');
  if (status) status.textContent = 'Loading…';
  try {
    const r = await loadJson('/api/responses');
    let html = '';

    // KPI cards — row 1: lifetime totals
    html += `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:10px;">
      <div class="kpi-card"><div class="kpi-value">${r.active_count||0}</div><div class="kpi-label">Active</div></div>
      <div class="kpi-card"><div class="kpi-value">${r.totals?.registered||0}</div><div class="kpi-label">Total</div></div>
      <div class="kpi-card"><div class="kpi-value">${r.totals?.expired||0}</div><div class="kpi-label">Expired</div></div>
      <div class="kpi-card"><div class="kpi-value">${r.totals?.reverted||0}</div><div class="kpi-label">Reverted</div></div>
    </div>`;

    // KPI cards — row 2: state machine health indicators. Orphaned is the
    // one that matters most — it means the system admits a rule may still
    // be active in the kernel/firewall even though we gave up reverting.
    const orphaned = r.totals?.orphaned || 0;
    const revertFailures = r.totals?.revert_failures || 0;
    const alreadyAbsent = r.totals?.already_absent || 0;
    const pending = r.state_counts?.revert_pending || 0;
    const failed = r.state_counts?.revert_failed || 0;
    const hasDrift = orphaned > 0 || failed > 0;
    html += `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:16px;">
      <div class="kpi-card" style="${orphaned > 0 ? 'border-color:#e74c3c;background:#e74c3c10;' : ''}">
        <div class="kpi-value" style="${orphaned > 0 ? 'color:#e74c3c' : ''}">${orphaned}</div>
        <div class="kpi-label" title="Reverts given up on after retries. Rule may still be active in kernel/firewall.">Orphaned</div>
      </div>
      <div class="kpi-card" style="${failed > 0 ? 'border-color:#f39c12;' : ''}">
        <div class="kpi-value" style="${failed > 0 ? 'color:#f39c12' : ''}">${failed}</div>
        <div class="kpi-label" title="Entries currently mid-retry (transient revert failures).">In Retry</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value">${pending}</div>
        <div class="kpi-label" title="Revert command dispatched to executor, awaiting result.">Pending</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value">${revertFailures}</div>
        <div class="kpi-label" title="Lifetime count of individual failed revert attempts.">Failures</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value">${alreadyAbsent}</div>
        <div class="kpi-label" title="Reverts that resolved because the rule was already gone (success).">Already Gone</div>
      </div>
    </div>`;

    // Drift warning banner when we know state is out of sync with kernel.
    if (hasDrift) {
      html += `<div style="padding:10px 14px;margin-bottom:14px;border-left:3px solid #e74c3c;background:#e74c3c10;border-radius:3px;font-size:0.85rem;">
        <strong style="color:#e74c3c">⚠ State drift detected.</strong>
        ${orphaned > 0 ? `<span>${orphaned} orphaned response(s) — rule may still be active in kernel/firewall. Check WARN logs for stderr.</span>` : ''}
        ${failed > 0 ? `<span>${failed} response(s) mid-retry.</span>` : ''}
      </div>`;
    }

    // Active responses table
    if (r.active?.length > 0) {
      html += `<h3 style="margin:12px 0 8px;">Active Responses</h3>
        <table style="width:100%;border-collapse:collapse;font-size:0.8rem;">
        <thead><tr style="border-bottom:2px solid var(--border);text-align:left;">
          <th style="padding:6px;">Target</th><th style="padding:6px;">Backend</th>
          <th style="padding:6px;">State</th>
          <th style="padding:6px;">Type</th><th style="padding:6px;">TTL</th>
          <th style="padding:6px;">Remaining</th><th style="padding:6px;">Incident</th>
        </tr></thead><tbody>`;
      r.active.forEach(a => {
        const mins = Math.floor((a.remaining_secs||0)/60);
        const hrs = Math.floor(mins/60);
        const remaining = hrs > 0 ? `${hrs}h ${mins%60}m` : `${mins}m`;
        const ttlH = Math.floor((a.ttl_secs||0)/3600);
        const backendColor = {xdp:'#e74c3c',iptables:'#f39c12',nftables:'#f39c12',ufw:'#3498db',cloudflare:'#f39c12',container:'#9b59b6',nginx:'#27ae60',sudo:'#e67e22'}[a.backend]||'var(--dim)';
        const backendTip = {xdp:'Kernel-level firewall (fastest)',iptables:'Linux packet filter',nftables:'Modern Linux firewall',ufw:'Ubuntu firewall',cloudflare:'Cloudflare edge rules',container:'Container runtime isolation',nginx:'Web server access control',sudo:'Privilege management'}[a.backend]||'';

        // State badge: Active (green), RevertPending (blue), RevertFailed (red)
        const stateKind = a.state?.kind || 'active';
        let stateBadge = '';
        let rowStyle = '';
        if (stateKind === 'active') {
          stateBadge = `<span style="padding:2px 6px;border-radius:3px;background:#27ae6020;color:#27ae60;font-size:0.7rem;">active</span>`;
        } else if (stateKind === 'revert_pending') {
          const trigger = a.state?.trigger || '';
          stateBadge = `<span title="Revert command dispatched (${trigger}), awaiting result" style="padding:2px 6px;border-radius:3px;background:#3498db20;color:#3498db;font-size:0.7rem;">pending · ${trigger}</span>`;
          rowStyle = 'background:#3498db08;';
        } else if (stateKind === 'revert_failed') {
          const attempts = a.state?.attempts || 0;
          const errShort = (a.state?.last_error || '').substring(0, 80);
          stateBadge = `<span title="${errShort.replace(/"/g,'&quot;')}" style="padding:2px 6px;border-radius:3px;background:#e74c3c20;color:#e74c3c;font-size:0.7rem;font-weight:600;cursor:help">retry ${attempts}/3</span>`;
          rowStyle = 'background:#e74c3c0c;';
        }

        html += `<tr style="border-bottom:1px solid var(--border);${rowStyle}">
          <td style="padding:6px;font-family:monospace;font-weight:600;">${a.target}</td>
          <td style="padding:6px;"><span title="${backendTip}" style="padding:2px 6px;border-radius:3px;background:${backendColor}20;color:${backendColor};font-size:0.7rem;cursor:help">${a.backend}</span></td>
          <td style="padding:6px;">${stateBadge}</td>
          <td style="padding:6px;">${a.type}</td>
          <td style="padding:6px;">${ttlH}h</td>
          <td style="padding:6px;font-weight:600;color:${mins < 10 ? '#e74c3c' : 'var(--text)'};">${remaining}</td>
          <td style="padding:6px;font-size:0.7rem;color:var(--dim);">${(a.incident_id||'').substring(0,40)}</td>
        </tr>`;
      });
      html += '</tbody></table>';
    } else {
      html += '<p style="color:var(--dim);margin:20px 0;">No active responses. All blocks have expired or been reverted.</p>';
    }

    // History
    if (r.history?.length > 0) {
      html += `<h3 style="margin:20px 0 8px;">Recent History (${r.history.length})</h3>
        <table style="width:100%;border-collapse:collapse;font-size:0.75rem;">
        <thead><tr style="border-bottom:2px solid var(--border);text-align:left;">
          <th style="padding:4px 6px;">Target</th><th style="padding:4px 6px;">Backend</th>
          <th style="padding:4px 6px;">Reason</th><th style="padding:4px 6px;">Reverted At</th>
        </tr></thead><tbody>`;
      r.history.forEach(h => {
        // Color-code reason: expired/manual green-blue (normal), already_absent
        // teal (success-but-gone), orphaned red (state drift admitted).
        let reasonColor = 'var(--dim)';
        let reasonLabel = h.reason || '';
        let reasonTitle = '';
        if (reasonLabel === 'expired') {
          reasonColor = '#27ae60';
        } else if (reasonLabel === 'manual') {
          reasonColor = '#3498db';
        } else if (reasonLabel === 'already_absent') {
          reasonColor = '#1abc9c';
          reasonTitle = 'Rule was already removed before we got to it — treated as success';
        } else if (reasonLabel.startsWith && reasonLabel.startsWith('orphaned')) {
          reasonColor = '#e74c3c';
          reasonTitle = reasonLabel; // full stderr is in the reason string
          reasonLabel = 'orphaned';
        }
        html += `<tr style="border-bottom:1px solid var(--border);">
          <td style="padding:4px 6px;font-family:monospace;">${h.target}</td>
          <td style="padding:4px 6px;">${h.backend}</td>
          <td style="padding:4px 6px;"><span title="${reasonTitle.replace(/"/g,'&quot;')}" style="color:${reasonColor};${reasonTitle?'cursor:help;':''}">${reasonLabel}</span></td>
          <td style="padding:4px 6px;color:var(--dim);">${new Date(h.reverted_at).toLocaleString()}</td>
        </tr>`;
      });
      html += '</tbody></table>';
    }

    content.innerHTML = html;
    if (status) {
      const parts = [`${r.active_count||0} active`];
      if (failed > 0) parts.push(`${failed} retrying`);
      if (orphaned > 0) parts.push(`${orphaned} orphaned`);
      status.textContent = parts.join(' · ');
    }
  } catch(e) {
    content.innerHTML = `<p style="color:#e74c3c">Failed to load responses: ${e.message}</p>`;
    if (status) status.textContent = 'Error';
  }
}

