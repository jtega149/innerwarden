// ── Home view (top-level) ──────────────────────────────────────────────
async function loadHome() {
  try {
    const [status, overview, incidentList, sensors] = await Promise.all([
      loadJson('/api/status'),
      loadJson('/api/overview'),
      loadJson('/api/incidents?limit=100'),
      loadJson('/api/sensors')
    ]);
    window._lastOverview = overview;
    // Count open incidents (no decision) to fix "All Contained" while OPEN exists
    const items = incidentList.items || [];
    const openHighCritical = items.filter(i =>
      i.outcome === 'open' && (i.severity === 'high' || i.severity === 'critical')
    ).length;
    updateHomeBanner(status, overview, openHighCritical);
    updateHomeKpis(overview);
    buildHomeFeed(items);
    updateCollectorStrip(sensors);
    loadBriefing();
  } catch(e) { console.warn('loadHome error:', e); }
}

function updateHomeBanner(status, overview, openHighCritical) {
  var hero = document.getElementById('homeHero');
  var icon = document.getElementById('homeHeroIcon');
  var title = document.getElementById('homeHeroTitle');
  var sub = document.getElementById('homeHeroSub');
  var meta = document.getElementById('homeStatusMeta');
  if (!hero || !icon || !title || !sub) return;

  var u = getUnresolved();
  var noise = overview.ai_ignored || 0;
  var events = overview.events_count || 0;
  // Include open high/critical incidents in unresolved count
  var totalUnresolved = u.unresolved + (openHighCritical || 0);

  if (totalUnresolved > 0) {
    hero.className = 'status-hero danger';
    icon.textContent = '\u26A0\uFE0F';
    title.innerHTML = totalUnresolved + ' Unresolved Threat' + (totalUnresolved > 1 ? 's' : '') +
      ' <button onclick="showView(\'investigate\')" style="' +
      'margin-left:12px;padding:6px 16px;border-radius:8px;border:1px solid var(--danger);' +
      'background:rgba(244,63,94,0.1);color:var(--danger);font-size:0.75rem;font-weight:700;' +
      'cursor:pointer;vertical-align:middle' +
      '">Review Threats \u2192</button>';
    sub.textContent = u.handled + ' contained \u00B7 ' + noise + ' noise filtered';
  } else if (u.total > 0) {
    hero.className = 'status-hero safe';
    icon.textContent = '\uD83D\uDEE1\uFE0F';
    title.textContent = 'All Threats Contained';
    sub.textContent = u.total + ' detected \u00B7 ' + u.handled + ' handled \u00B7 ' + noise + ' noise filtered';
  } else {
    hero.className = 'status-hero safe';
    icon.textContent = '\u2705';
    title.textContent = 'All Clear';
    sub.textContent = 'No confirmed threats \u00B7 ' + events + ' events analyzed';
  }

  if (meta) {
    var mode = (status.mode || 'read_only').replace('_', '-').toUpperCase();
    var heartbeat = status.last_telemetry_secs != null ? status.last_telemetry_secs + 's ago' : 'n/a';
    var aiText = status.ai_enabled ? (status.ai_provider || 'on') : 'off';
    meta.innerHTML = '<span>MODE: ' + mode + '</span><span>\u2764 ' + heartbeat + '</span>';
  }
}

function updateHomeKpis(overview) {
  var u = getUnresolved();
  var el = document.getElementById('homeKpiThreats');
  if (el) {
    el.textContent = u.total || 0;
    el.style.color = u.unresolved > 0 ? 'var(--danger)' : u.total > 0 ? 'var(--ok)' : 'var(--accent)';
  }
  el = document.getElementById('homeKpiResponded');
  if (el) el.textContent = overview.ai_responded || 0;
  el = document.getElementById('homeKpiEvents');
  if (el) el.textContent = (overview.events_count || 0).toLocaleString();
}

// ── AI Intelligence Briefing ────────────────────────────────────────
async function loadBriefing() {
  var section = document.getElementById('briefingSection');
  if (!section) return;
  try {
    var data = await loadJson('/api/briefing');
    section.style.display = '';
    var content = document.getElementById('briefingContent');
    var btn = document.getElementById('briefingBtn');
    if (data.available) {
      var age = data.generated_at ? new Date(data.generated_at).toLocaleTimeString() : '';
      content.innerHTML = '<div style="margin-bottom:8px;font-size:0.65rem;color:var(--muted)">Generated ' + age + '</div>' +
        '<div>' + esc(data.summary).replace(/\n/g, '<br>').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') + '</div>';
      btn.textContent = 'Regenerate';
    } else {
      content.innerHTML = '<div style="color:var(--dim);font-size:0.75rem">' + esc(data.message || 'Click Generate to create your first briefing.') + '</div>';
    }
  } catch(e) {
    section.style.display = 'none';
  }
}

async function generateBriefing() {
  var btn = document.getElementById('briefingBtn');
  var content = document.getElementById('briefingContent');
  if (btn) { btn.textContent = 'Generating...'; btn.disabled = true; }
  if (content) content.innerHTML = '<div style="color:var(--accent)">Analyzing knowledge graph and generating briefing via AI...</div>';
  try {
    var r = await fetch('/api/briefing/generate', { method: 'POST', cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    var data = await r.json();
    if (data.error) {
      content.innerHTML = '<div style="color:var(--danger)">' + esc(data.error) + '</div>';
    } else {
      content.innerHTML = '<div style="margin-bottom:8px;font-size:0.65rem;color:var(--muted)">Generated just now</div>' +
        '<div>' + esc(data.summary).replace(/\n/g, '<br>').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') + '</div>';
    }
  } catch(e) {
    content.innerHTML = '<div style="color:var(--danger)">Error: ' + esc(e.message) + '</div>';
  }
  if (btn) { btn.textContent = 'Regenerate'; btn.disabled = false; }
}

function buildHomeFeed(incidents) {
  var feedEl = document.getElementById('homeFeed');
  if (!feedEl) return;
  // Filter trusted incidents if global toggle is on
  if (state.hideAllowlisted) {
    incidents = (incidents || []).filter(function(inc) { return !isIncidentTrusted(inc); });
  }
  if (!incidents || incidents.length === 0) {
    feedEl.innerHTML = '<div style="padding:30px;text-align:center"><div style="font-size:1.2rem;margin-bottom:6px">\u2705</div><div style="color:var(--ok);font-size:0.82rem;font-weight:600">No security events</div><div style="color:var(--dim);font-size:0.72rem;margin-top:4px">All systems nominal</div></div>';
    return;
  }
  // Chronological feed — most recent first, no aggregation
  var html = '<div class="activity-feed">';
  incidents.slice(0, 15).forEach(function(inc) {
    var slug = (inc.incident_id || '').split(':')[0] || '';
    var label = humanLabel(slug);
    var ago = timeAgo(inc.ts);
    var outcome = inc.outcome || 'open';
    var sev = (inc.effective_severity || inc.severity || '').toLowerCase();
    var entities = inc.entities || [];
    var ipEntity = entities.find(function(e) {
      return (e.type || '').toLowerCase() === 'ip' || (typeof e === 'string' && e.startsWith('ip:'));
    });
    var ipVal = ipEntity ? (ipEntity.value || (typeof ipEntity === 'string' ? ipEntity.slice(3) : '')) : '';

    var icon = '\u26A0\uFE0F';
    if (outcome === 'blocked' || outcome === 'killed' || outcome === 'contained' || outcome === 'suspended') icon = '\uD83D\uDEE1\uFE0F';
    else if (outcome === 'ignored') icon = '\u2796';
    else if (sev === 'critical' || sev === 'high') icon = '\uD83D\uDD34';

    var badge = outcomeBadgeHtml(outcome);
    var rowOpacity = outcome === 'ignored' ? '0.5' : (outcome === 'open' ? '1' : '0.8');

    html += '<div class="activity-row" style="opacity:' + rowOpacity + '" onclick="showView(\'investigate\');handleCardClickByValue(\'ip\',\'' + ipVal + '\')">' +
      '<span class="activity-icon">' + icon + '</span>' +
      '<div style="flex:1;min-width:0">' +
      '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
      '<span style="font-size:0.8rem;font-weight:600;color:var(--fg)">' + label + '</span>' +
      badge +
      '</div>' +
      (ipVal ? '<div style="font-size:0.72rem;color:var(--muted);margin-top:2px;font-family:\'JetBrains Mono\',monospace">' + ipVal + '</div>' : '') +
      '</div>' +
      '<span class="activity-time">' + ago + '</span>' +
      '</div>';
  });
  html += '</div>';
  feedEl.innerHTML = html;
}

function updateCollectorStrip(sensors) {
  var stripEl = document.getElementById('homeCollectorStrip');
  if (!stripEl) return;
  var sources = sensors.sources || [];
  var active = sources.filter(function(s) { return s.count > 0; });
  var total = sources.length;
  var html = '<div class="collector-summary-line">' + active.length + '/' + total + ' collectors active</div>';
  active.forEach(function(s) {
    var color = sensorColor(s.name);
    html += '<div class="collector-row">' +
      '<span class="collector-dot" style="background:' + color + ';box-shadow:0 0 6px ' + color + '"></span>' +
      '<span class="collector-name">' + s.name + '</span>' +
      '<span class="collector-count" style="color:' + color + '">' + s.count.toLocaleString() + '</span>' +
      '</div>';
  });
  if (sources.length > active.length) {
    var idle = sources.length - active.length;
    html += '<div style="font-size:0.68rem;color:var(--dim);margin-top:4px">' + idle + ' idle</div>';
  }
  stripEl.innerHTML = html;
}

