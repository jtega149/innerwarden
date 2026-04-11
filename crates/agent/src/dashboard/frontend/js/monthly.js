// ── Monthly Report tab ────────────────────────────────────────────
let monthlyMonthsLoaded = false;

async function loadMonthly() {
  const status = document.getElementById('monthlyViewStatus');
  const content = document.getElementById('monthlyContent');
  const picker = document.getElementById('monthlyPicker');

  // Load available months on first visit
  if (!monthlyMonthsLoaded && picker) {
    try {
      const months = await loadJson('/api/threat-report/months');
      picker.innerHTML = (months||[]).map(m => `<option value="${m}">${m}</option>`).join('');
      if (!months || months.length === 0) {
        picker.innerHTML = '<option value="">No data</option>';
        content.innerHTML = '<p style="color:var(--dim);">No monthly data available yet. Reports are generated on the 1st of each month, or you can trigger one manually.</p>';
        return;
      }
      monthlyMonthsLoaded = true;
    } catch(e) {
      content.innerHTML = `<p style="color:#e74c3c">Failed to load months: ${e.message}</p>`;
      return;
    }
  }

  const month = picker?.value;
  if (!month) return;
  if (status) status.textContent = 'Loading…';

  try {
    const r = await loadJson(`/api/threat-report?month=${month}`);
    if (!r || r.error) { content.innerHTML = `<p style="color:#e74c3c">${r?.error || 'Failed to generate report'}</p>`; return; }
    const s = r.executive_summary || {};

    let html = `<h2 style="margin:0 0 16px;">Threat Report — ${r.month}</h2>
      <div style="font-size:0.75rem;color:var(--dim);margin-bottom:16px;">Generated: ${r.generated_at ? new Date(r.generated_at).toLocaleString() : '—'}</div>`;

    // KPIs
    html += `<div class="kpi-grid" style="grid-template-columns:repeat(5,1fr);margin-bottom:20px;">
      <div class="kpi-card"><div class="kpi-value">${s.total_events?.toLocaleString()||0}</div><div class="kpi-label">Events</div></div>
      <div class="kpi-card"><div class="kpi-value">${s.total_incidents?.toLocaleString()||0}</div><div class="kpi-label">Incidents</div></div>
      <div class="kpi-card"><div class="kpi-value">${s.total_blocks||0}</div><div class="kpi-label">Blocks</div></div>
      <div class="kpi-card"><div class="kpi-value">${s.unique_attackers||0}</div><div class="kpi-label">Attackers</div></div>
      <div class="kpi-card"><div class="kpi-value">${s.unique_countries||0}</div><div class="kpi-label">Countries</div></div>
    </div>`;

    // Top Attackers
    if (r.top_attackers?.length > 0) {
      html += `<h3 style="margin:16px 0 8px;">Top Attackers</h3>
        <table style="width:100%;border-collapse:collapse;font-size:0.8rem;">
        <thead><tr style="border-bottom:2px solid var(--border);text-align:left;">
          <th style="padding:4px 6px;">#</th><th style="padding:4px 6px;">IP</th><th style="padding:4px 6px;">Risk</th>
          <th style="padding:4px 6px;">Country</th><th style="padding:4px 6px;">Incidents</th>
          <th style="padding:4px 6px;">Pattern</th><th style="padding:4px 6px;">Action</th>
        </tr></thead><tbody>`;
      r.top_attackers.forEach((a,i) => {
        const rc = a.risk_score >= 70 ? '#e74c3c' : a.risk_score >= 40 ? '#f39c12' : '#27ae60';
        html += `<tr style="border-bottom:1px solid var(--border);">
          <td style="padding:4px 6px;">${i+1}</td><td style="padding:4px 6px;font-family:monospace;">${a.ip}</td>
          <td style="padding:4px 6px;color:${rc};font-weight:600;">${a.risk_score}</td>
          <td style="padding:4px 6px;">${a.country||'??'}</td><td style="padding:4px 6px;">${a.total_incidents}</td>
          <td style="padding:4px 6px;">${a.pattern_class}</td><td style="padding:4px 6px;">${a.action_taken}</td>
        </tr>`;
      });
      html += '</tbody></table>';
    }

    // MITRE Coverage
    if (r.mitre_coverage?.techniques_seen?.length > 0) {
      html += `<h3 style="margin:20px 0 8px;">MITRE ATT&CK Coverage (${r.mitre_coverage.total_unique_techniques} techniques)</h3>
        <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px;">`;
      const tactics = r.mitre_coverage.tactics_counts || {};
      Object.entries(tactics).sort((a,b)=>b[1]-a[1]).forEach(([t,c]) => {
        html += `<span style="padding:3px 8px;border-radius:4px;background:#2c1810;color:#f39c12;font-size:0.75rem;">${t}: ${c}</span>`;
      });
      html += `</div><table style="width:100%;border-collapse:collapse;font-size:0.8rem;">
        <thead><tr style="border-bottom:2px solid var(--border);text-align:left;">
          <th style="padding:4px 6px;">Technique</th><th style="padding:4px 6px;">Tactic</th>
          <th style="padding:4px 6px;">Incidents</th><th style="padding:4px 6px;">Attackers</th>
        </tr></thead><tbody>`;
      r.mitre_coverage.techniques_seen.forEach(t => {
        html += `<tr style="border-bottom:1px solid var(--border);">
          <td style="padding:4px 6px;">${t.technique_id} (${t.technique_name})</td>
          <td style="padding:4px 6px;">${t.tactic}</td>
          <td style="padding:4px 6px;">${t.incident_count}</td>
          <td style="padding:4px 6px;">${t.attacker_count}</td></tr>`;
      });
      html += '</tbody></table>';
    }

    // Geographic Distribution
    if (r.geographic_distribution?.by_country?.length > 0) {
      html += `<h3 style="margin:20px 0 8px;">Geographic Distribution</h3>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;">`;
      r.geographic_distribution.by_country.slice(0,12).forEach(c => {
        html += `<div class="kpi-card" style="padding:8px;">
          <div style="font-weight:600;">${c.country_code} ${c.country}</div>
          <div style="font-size:0.75rem;color:var(--dim);">${c.attacker_count} attackers · ${c.incident_count} incidents</div>
        </div>`;
      });
      html += `</div>`;
    }

    // Campaigns
    if (r.campaigns?.length > 0) {
      html += `<h3 style="margin:20px 0 8px;">Detected Campaigns (${r.campaigns.length})</h3>`;
      r.campaigns.forEach(c => {
        const confColor = c.confidence === 'high' ? '#e74c3c' : c.confidence === 'medium' ? '#f39c12' : '#27ae60';
        const typeIcon = (c.correlation_type||'').includes('dna') ? '🧬' : '🔗';
        html += `<div class="kpi-card" style="padding:12px;margin-bottom:8px;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div><span style="font-weight:600;">${c.campaign_id}</span> <span>${typeIcon}</span>
              <span style="padding:2px 6px;border-radius:3px;background:var(--border);font-size:0.7rem;margin-left:4px;">${(c.correlation_type||'') === 'dna' ? 'Behavioral Pattern' : (c.correlation_type||'') === 'ioc' ? 'Shared Indicators' : c.correlation_type||'unknown'}</span></div>
            <div><span style="padding:2px 8px;border-radius:4px;background:${confColor}20;color:${confColor};font-size:0.75rem;">${c.confidence}</span>
              <span style="font-size:0.8rem;color:var(--dim);margin-left:8px;">Risk: ${c.max_risk_score||0}</span></div>
          </div>
          <div style="font-size:0.8rem;margin-top:4px;">${c.summary||''}</div>
          <div style="font-size:0.8rem;margin-top:4px;">IPs (${(c.member_ips||c.attacker_ips||[]).length}): ${(c.member_ips||c.attacker_ips||[]).map(i=>`<code>${i}</code>`).join(', ')}</div>
          ${c.shared_iocs?.length ? `<div style="font-size:0.75rem;color:#e74c3c;margin-top:2px;">IOCs: ${c.shared_iocs.slice(0,5).join(', ')}</div>` : ''}
          ${c.shared_dna_signature ? `<div style="font-size:0.7rem;color:var(--dim);margin-top:2px;">DNA: <code>${c.shared_dna_signature}</code></div>` : ''}
        </div>`;
      });
    }

    // Weekly Trends
    if (r.weekly_trends?.length > 0) {
      html += `<h3 style="margin:20px 0 8px;">Weekly Trends</h3>
        <table style="width:100%;border-collapse:collapse;font-size:0.8rem;">
        <thead><tr style="border-bottom:2px solid var(--border);text-align:left;">
          <th style="padding:4px 6px;">Week</th><th style="padding:4px 6px;">Period</th>
          <th style="padding:4px 6px;">Events</th><th style="padding:4px 6px;">Incidents</th>
          <th style="padding:4px 6px;">Blocks</th><th style="padding:4px 6px;">Attackers</th>
        </tr></thead><tbody>`;
      r.weekly_trends.forEach(w => {
        html += `<tr style="border-bottom:1px solid var(--border);">
          <td style="padding:4px 6px;font-weight:600;">${w.week_label}</td>
          <td style="padding:4px 6px;font-size:0.75rem;">${w.date_range}</td>
          <td style="padding:4px 6px;">${w.events.toLocaleString()}</td>
          <td style="padding:4px 6px;">${w.incidents}</td>
          <td style="padding:4px 6px;">${w.blocks}</td>
          <td style="padding:4px 6px;">${w.unique_attackers}</td>
        </tr>`;
      });
      html += '</tbody></table>';
    }

    // Honeypot Intel
    if (r.honeypot_intelligence?.total_sessions > 0) {
      const h = r.honeypot_intelligence;
      html += `<h3 style="margin:20px 0 8px;">Honeypot Intelligence</h3>
        <div style="font-size:0.8rem;margin-bottom:8px;">${h.total_sessions} sessions from ${h.unique_ips} unique IPs</div>`;
      if (h.top_credentials?.length > 0) {
        html += `<h4 style="font-size:0.8rem;color:var(--dim);margin:8px 0 4px;">Top Credentials</h4>
          <table style="border-collapse:collapse;font-size:0.75rem;"><tbody>`;
        h.top_credentials.slice(0,10).forEach(([u,p,c]) => {
          html += `<tr style="border-bottom:1px solid var(--border);">
            <td style="padding:2px 8px;font-family:monospace;">${u}</td>
            <td style="padding:2px 8px;font-family:monospace;color:var(--dim);">${p}</td>
            <td style="padding:2px 8px;">${c}x</td></tr>`;
        });
        html += '</tbody></table>';
      }
      if (h.top_commands?.length > 0) {
        html += `<h4 style="font-size:0.8rem;color:var(--dim);margin:8px 0 4px;">Top Commands</h4>`;
        h.top_commands.slice(0,10).forEach(([cmd,c]) => {
          html += `<div style="font-family:monospace;font-size:0.7rem;padding:2px 0;"><code>${cmd}</code> <span style="color:var(--dim);">(${c}x)</span></div>`;
        });
      }
    }

    content.innerHTML = html;
    if (status) status.textContent = `Report: ${r.month}`;
  } catch(e) {
    content.innerHTML = `<p style="color:#e74c3c">Failed: ${e.message}</p>`;
    if (status) status.textContent = 'Error';
  }
}

