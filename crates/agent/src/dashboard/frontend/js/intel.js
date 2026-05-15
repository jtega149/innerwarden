// ── Intelligence tab ──────────────────────────────────────────────
// 2026-05-03 (PR #413): the Playbooks Intel sub-tab + probe were
// removed alongside the playbook engine. Future declarative
// orchestration belongs to Spec 042 active defense.

// 2026-05-15: page size + active risk filter persisted across calls.
// Operator-reported: KPI "High Risk: 100" was the same as the visible
// row count, not the real bucket size; "Total: 4141" had no way to
// reach the other 4041; sorted-desc table gave no visual cue for
// where the risk cliff was.
const INTEL_PAGE_SIZE = 100;
let _intelOffset = 0;
let _intelRiskFilter = 0; // 0 = all, 70 = high, 40 = medium+, ...
let _intelLoadedProfiles = []; // accumulator for "Load more"

async function loadIntel() {
  _intelOffset = 0;
  _intelLoadedProfiles = [];
  await fetchAndRenderIntel(/* append= */ false);
}

async function fetchAndRenderIntel(append) {
  const status = document.getElementById('intelViewStatus');
  const content = document.getElementById('intelContent');
  if (status) status.textContent = append ? 'Loading more…' : 'Loading…';
  const signal = window._activeFetch_intel ? window._activeFetch_intel.signal : undefined;
  try {
    const sort = document.getElementById('intelSort')?.value || 'risk_score';
    const url = '/api/attacker-profiles?sort=' + encodeURIComponent(sort)
      + '&min_risk=' + _intelRiskFilter
      + '&limit=' + INTEL_PAGE_SIZE
      + '&offset=' + _intelOffset;
    const data = await loadJson(url, { signal });
    if (!data || !data.profiles) { content.innerHTML = '<p style="color:var(--dim)">No attacker profiles yet.</p>'; return; }

    if (append) {
      _intelLoadedProfiles = _intelLoadedProfiles.concat(data.profiles);
    } else {
      _intelLoadedProfiles = data.profiles.slice();
    }

    const buckets = data.totals_by_risk || {};
    const totalAll = data.total || 0;
    const totalHigh = buckets.high || 0;
    const totalMedium = buckets.medium || 0;
    // The visible profiles set respects the current risk filter; the
    // bucket counts in the response are scoped to that filter (the
    // backend computes them over `filtered`). So when filter=0
    // buckets reflect the whole DB; when filter=70, "high" == total
    // visible and others are 0. That's the right honesty contract.

    // KPI tiles — clicking sets the risk filter. Current filter is
    // highlighted so the operator knows which bucket they're seeing.
    const tile = function(label, value, filterValue, active) {
      const cursor = filterValue == null ? '' : 'cursor:pointer;';
      const ring = active ? 'box-shadow:inset 0 0 0 1px var(--accent);' : '';
      const onclick = filterValue == null ? ''
        : ` onclick="setIntelRiskFilter(${filterValue})"`;
      return '<div class="kpi-card" style="' + cursor + ring + '"' + onclick + '>'
        + '<div class="kpi-value">' + value + '</div>'
        + '<div class="kpi-label">' + label + '</div>'
        + '</div>';
    };
    let html = '<div class="kpi-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:12px;">'
      + tile('Total Profiles', totalAll, 0, _intelRiskFilter === 0)
      + tile('High Risk (≥70)', totalHigh, 70, _intelRiskFilter === 70)
      + tile('Medium (40–69)', totalMedium, 40, _intelRiskFilter === 40)
      + tile('Countries', new Set(_intelLoadedProfiles.map(p=>p.geo?.country_code).filter(Boolean)).size, null, false)
      + '</div>';

    // Filter row — IP search + sort + clear-filter (when active).
    html += '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px;font-size:0.78rem;">'
      + '<input id="intelIpSearch" type="search" placeholder="search IP…" oninput="filterIntelByIp(this.value)" autocomplete="off" spellcheck="false" style="padding:5px 10px;border-radius:6px;border:1px solid var(--border);background:var(--card-bg);color:var(--text);min-width:200px;" />'
      + (_intelRiskFilter > 0
          ? '<span style="color:var(--accent);">Filter: risk ≥ ' + _intelRiskFilter + '</span><button type="button" onclick="setIntelRiskFilter(0)" style="padding:3px 8px;border-radius:4px;border:1px solid var(--border);background:transparent;color:var(--muted);cursor:pointer;">× clear</button>'
          : '')
      + '</div>';

    html += '<table id="intelTable" style="width:100%;border-collapse:collapse;font-size:0.85rem;">'
      + '<thead><tr style="border-bottom:2px solid var(--border);text-align:left;">'
      + '<th style="padding:6px;">Risk</th><th style="padding:6px;">IP</th><th style="padding:6px;">Country</th>'
      + '<th style="padding:6px;">Incidents</th><th style="padding:6px;">Blocks</th><th style="padding:6px;">Detectors</th>'
      + '<th style="padding:6px;">Pattern</th><th style="padding:6px;">Last Seen</th>'
      + '</tr></thead><tbody>';

    for (const p of _intelLoadedProfiles) {
      const riskColor = p.risk_score >= 70 ? '#e74c3c' : p.risk_score >= 40 ? '#f39c12' : '#27ae60';
      const riskBar = '<div style="display:flex;align-items:center;gap:6px;">'
        + '<div style="width:40px;height:8px;background:var(--border);border-radius:4px;overflow:hidden;">'
        + '<div style="width:' + p.risk_score + '%;height:100%;background:' + riskColor + ';"></div></div>'
        + '<span style="color:' + riskColor + ';font-weight:600;">' + p.risk_score + '</span></div>';
      const country = p.geo?.country_code || '??';
      const detectors = (p.detectors_triggered || []).slice(0, 3).join(', ');
      const patternRaw = p.dna?.pattern_class || 'unknown';
      const lastSeen = p.last_seen ? new Date(p.last_seen).toLocaleDateString() : '\u2014';
      const patternLabels = { regular_scanner:'Regular Scanner', targeted:'Targeted Attack', opportunistic:'Opportunistic', unknown:'Unknown' };
      const pattern = patternLabels[patternRaw] || patternRaw.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
      const patternBadge = pattern === 'Regular Scanner' ? lucideIcon('refresh-ccw') : pattern === 'Targeted Attack' ? lucideIcon('target') : pattern === 'Opportunistic' ? lucideIcon('crosshair') : lucideIcon('alert-circle');
      // 2026-05-15 slim-down: dropped the DNA-hash column from the
      // table. The full DNA fingerprint is still on the per-profile
      // detail page; on the list, an 10-char monospace string was
      // chrome noise that pushed Last Seen into ellipsis territory
      // on common screen widths.
      // 2026-05-15: tint rows \u226570 so the operator can spot the cliff
      // even when the visible page mixes risk bands.
      const rowTint = p.risk_score >= 70 ? 'background:rgba(231,76,60,0.05);' : '';
      html += '<tr style="border-bottom:1px solid var(--border);cursor:pointer;' + rowTint + '" data-ip="' + esc(p.ip) + '" onclick="openProfileModal(\'' + esc(p.ip) + '\')">'
        + '<td style="padding:6px;">' + riskBar + '</td>'
        + '<td style="padding:6px;font-family:monospace;">' + esc(p.ip) + '</td>'
        + '<td style="padding:6px;">' + country + '</td>'
        + '<td style="padding:6px;">' + p.total_incidents + '</td>'
        + '<td style="padding:6px;">' + p.total_blocks + '</td>'
        + '<td style="padding:6px;font-size:0.75rem;">' + detectors + '</td>'
        + '<td style="padding:6px;">' + patternBadge + ' ' + pattern + '</td>'
        + '<td style="padding:6px;font-size:0.75rem;">' + lastSeen + '</td>'
        + '</tr>';
    }
    html += '</tbody></table>';

    // "Showing X of Y" + Load more button. Honest about pagination \u2014
    // operator no longer has to wonder where the other 4000+ profiles
    // went.
    const shown = _intelLoadedProfiles.length;
    html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-top:12px;font-size:0.78rem;color:var(--muted);">';
    html += '<span>Showing ' + shown + ' of ' + totalAll + ' profiles' + (_intelRiskFilter > 0 ? ' (filter: risk \u2265 ' + _intelRiskFilter + ')' : '') + '</span>';
    if (shown < totalAll) {
      html += '<button type="button" onclick="loadMoreIntelProfiles()" style="padding:5px 14px;border-radius:6px;border:1px solid var(--accent);background:transparent;color:var(--accent);cursor:pointer;font-weight:600;">Load more (' + Math.min(INTEL_PAGE_SIZE, totalAll - shown) + ' more)</button>';
    }
    html += '</div>';

    content.innerHTML = html;
    if (status) status.textContent = shown + ' of ' + totalAll + ' profiles';
  } catch(e) {
    if (e && (e.name === 'AbortError' || e.code === 20)) return;
    content.innerHTML = '<p style="color:#e74c3c;">Failed to load: ' + esc(e.message) + '</p>';
    if (status) status.textContent = 'Error';
  }
}

// 2026-05-15: click handlers \u2014 keep them at module scope so the
// `onclick=` attributes in the rendered HTML can reach them.
function setIntelRiskFilter(risk) {
  _intelRiskFilter = risk;
  loadIntel();
}

function loadMoreIntelProfiles() {
  _intelOffset += INTEL_PAGE_SIZE;
  fetchAndRenderIntel(/* append= */ true);
}

function filterIntelByIp(query) {
  const q = (query || '').trim().toLowerCase();
  const rows = document.querySelectorAll('#intelTable tbody tr');
  rows.forEach(function(r) {
    const ip = (r.getAttribute('data-ip') || '').toLowerCase();
    r.style.display = (!q || ip.indexOf(q) !== -1) ? '' : 'none';
  });
}

// 2026-05-15 PR-A: dossier body builder. Returns the HTML for an
// attacker dossier given the `/api/attacker-profiles/<ip>` payload.
// Header chrome (back button / close button) is the caller's
// responsibility — `openProfileModal` (the shared drill-down used by
// Cases journey + Intel profile rows) supplies its own X-close in the
// modal header, so this body is chrome-free.
function renderProfileDossierHtml(p) {
  if (!p || p.error) {
    return `<p style="color:#e74c3c">${p?.error || 'Not found'}</p>`;
  }
  const riskColor = p.risk_score >= 70 ? '#e74c3c' : p.risk_score >= 40 ? '#f39c12' : '#27ae60';
  let html = '';
  html += `<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">`;

    // Left: Identity + Timeline
    html += `<div class="kpi-card" style="padding:16px;">
      <h3 style="margin:0 0 12px;display:flex;align-items:center;gap:8px">${lucideIcon('target',{size:18})} ${p.ip}</h3>
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
        <div style="width:120px;height:12px;background:var(--border);border-radius:6px;overflow:hidden;">
          <div style="width:${p.risk_score}%;height:100%;background:${riskColor};"></div>
        </div>
        <span style="font-size:1.5rem;font-weight:700;color:${riskColor};">${p.risk_score}/100</span>
      </div>
      <table style="font-size:0.8rem;"><tbody>
        <tr><td style="padding:2px 8px;color:var(--dim);">Country</td><td>${p.geo?.country || '—'} (${p.geo?.country_code || '??'})</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">ISP</td><td>${p.geo?.isp || '—'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">ASN</td><td>${p.geo?.asn || '—'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">AbuseIPDB</td><td>${p.abuseipdb_score ?? '—'}/100</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">CrowdSec</td><td>${p.crowdsec_listed ? lucideIcon('alert-triangle',{size:12}) + ' Listed' : lucideIcon('check-circle',{size:12}) + ' Clean'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Tor</td><td>${p.is_tor ? lucideIcon('globe',{size:12}) + ' Yes' : 'No'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">First Seen</td><td>${p.first_seen ? new Date(p.first_seen).toLocaleString() : '—'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Last Seen</td><td>${p.last_seen ? new Date(p.last_seen).toLocaleString() : '—'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Days Active</td><td>${p.visit_count} days</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Pattern</td><td>${p.dna?.pattern_class || 'unknown'}</td></tr>
      </tbody></table>
    </div>`;

    // Right: Attack Profile
    html += `<div class="kpi-card" style="padding:16px;">
      <h3 style="margin:0 0 12px;display:flex;align-items:center;gap:8px">${lucideIcon('swords',{size:16})} Attack Profile</h3>
      <table style="font-size:0.8rem;"><tbody>
        <tr><td style="padding:2px 8px;color:var(--dim);">Incidents</td><td>${p.total_incidents}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Blocks</td><td>${p.total_blocks}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Shield Blocks</td><td>${p.shield_blocks || 0}${p.shield_last_blocked ? ' (last: ' + new Date(p.shield_last_blocked).toLocaleString() + ')' : ''}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Honeypot</td><td>${p.total_honeypot_diversions} diversions, ${p.honeypot_sessions} sessions</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Max Severity</td><td style="font-weight:600;">${p.max_severity}</td></tr>
      </tbody></table>
      <h4 style="margin:12px 0 4px;font-size:0.8rem;color:var(--dim);">Detectors Triggered</h4>
      <div style="display:flex;flex-wrap:wrap;gap:4px;">${(p.detectors_triggered||[]).map(d=>`<span style="padding:2px 6px;border-radius:4px;background:var(--border);font-size:0.7rem;">${esc(d)}</span>`).join('')}</div>
      <h4 style="margin:12px 0 4px;font-size:0.8rem;color:var(--dim);">MITRE Techniques</h4>
      <div style="display:flex;flex-wrap:wrap;gap:4px;">${(p.mitre_techniques||[]).map(t=>`<span style="padding:2px 6px;border-radius:4px;background:#2c1810;color:#f39c12;font-size:0.7rem;">${esc(t)}</span>`).join('')}</div>
    </div>`;
    html += `</div>`;

    // DNA section
    html += `<div class="kpi-card" style="padding:16px;margin-top:16px;">
      <h3 style="margin:0 0 12px;display:flex;align-items:center;gap:8px">${lucideIcon('dna',{size:16})} Behavioral DNA</h3>
      <div style="font-family:monospace;font-size:0.75rem;color:var(--dim);margin-bottom:8px;">Hash: ${p.dna?.hash || '—'}</div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;">
        <div><h4 style="font-size:0.8rem;color:var(--dim);margin:0 0 4px;">Hour Distribution</h4>
          <div style="display:flex;align-items:flex-end;gap:1px;height:40px;">${(p.dna?.hour_distribution||[]).map((v,i)=>`<div title="${i}:00 — ${v} events" style="flex:1;background:${v>0?'#3498db':'var(--border)'};height:${v?Math.max(4,v/Math.max(...(p.dna?.hour_distribution||[1]))*40):2}px;border-radius:1px;"></div>`).join('')}</div>
          <div style="display:flex;justify-content:space-between;font-size:0.6rem;color:var(--dim);"><span>0h</span><span>12h</span><span>23h</span></div>
        </div>
        <div><h4 style="font-size:0.8rem;color:var(--dim);margin:0 0 4px;">Target Users</h4>
          ${(p.dna?.target_users||[]).map(u=>`<div style="font-family:monospace;font-size:0.75rem;">${esc(u)}</div>`).join('')||'<span style="color:var(--dim);font-size:0.75rem;">none</span>'}
        </div>
        <div><h4 style="font-size:0.8rem;color:var(--dim);margin:0 0 4px;">Tool Signatures</h4>
          ${(p.dna?.tool_signatures||[]).map(t=>`<span style="padding:2px 6px;border-radius:4px;background:#1a2634;color:#3498db;font-size:0.7rem;margin:2px;">${esc(t)}</span>`).join('')||'<span style="color:var(--dim);font-size:0.75rem;">none</span>'}
        </div>
      </div>
    </div>`;

    // Honeypot Intel
    if (p.honeypot_sessions > 0) {
      html += `<div class="kpi-card" style="padding:16px;margin-top:16px;">
        <h3 style="margin:0 0 12px;display:flex;align-items:center;gap:8px">${lucideIcon('bug',{size:16})} Honeypot Intel</h3>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
          <div><h4 style="font-size:0.8rem;color:var(--dim);margin:0 0 4px;">Credentials Attempted</h4>
            <table style="font-size:0.75rem;"><tbody>
              ${(p.credentials_attempted||[]).slice(0,10).map(([u,pw])=>`<tr><td style="padding:1px 6px;font-family:monospace;">${esc(u)}</td><td style="padding:1px 6px;font-family:monospace;color:var(--dim);">${esc(pw)}</td></tr>`).join('')}
            </tbody></table>
          </div>
          <div><h4 style="font-size:0.8rem;color:var(--dim);margin:0 0 4px;">Commands Executed</h4>
            ${(p.commands_executed||[]).slice(0,10).map(c=>`<div style="font-family:monospace;font-size:0.7rem;padding:2px 0;border-bottom:1px solid var(--border);">${esc(c)}</div>`).join('')}
          </div>
        </div>
        ${(p.iocs?.urls||[]).length > 0 ? `<h4 style="font-size:0.8rem;color:var(--dim);margin:12px 0 4px;">IOCs</h4>
          ${(p.iocs.urls||[]).map(u=>`<div style="font-family:monospace;font-size:0.7rem;display:flex;align-items:center;gap:6px">${lucideIcon('link',{size:12})} ${esc(u)}</div>`).join('')}
          ${(p.iocs.ips||[]).map(i=>`<div style="font-family:monospace;font-size:0.7rem;display:flex;align-items:center;gap:6px">${lucideIcon('globe',{size:12})} ${esc(i)}</div>`).join('')}` : ''}
      </div>`;
    }

  return html;
}

// 2026-05-15 PR-A: shared dossier modal. The drill-down for an
// attacker IP is one DOM surface, opened from both Cases journey
// ("View full profile") and Intel profile-row clicks. Previously
// `openIntelProfile` did `showView('intel') → setTimeout(120ms) →
// switchIntelTab('profiles') → showProfileDetail` — that 120ms
// race lost when the Intel tab fetch out-ran the timer, leaving the
// operator on the generic profile list instead of the requested IP.
// The modal sidesteps that entirely: no tab switch, no race window.
async function openProfileModal(ip) {
  if (!ip) return;
  const modal = document.getElementById('profileModal');
  const title = document.getElementById('profileModalTitle');
  const body = document.getElementById('profileModalBody');
  if (!modal || !body) return;
  // Show the modal immediately with a loading state — operator gets
  // visual feedback the click registered even if the API is slow.
  if (title) title.textContent = 'Attacker dossier · ' + ip;
  body.innerHTML = '<div style="color:var(--muted);padding:24px;text-align:center">Loading…</div>';
  modal.style.display = 'flex';
  // Focus the close button for keyboard users; Escape closes (wired
  // by the document-level keydown handler below).
  const closeBtn = modal.querySelector('.enf-modal-close');
  if (closeBtn) closeBtn.focus();
  try {
    const p = await loadJson(`/api/attacker-profiles/${encodeURIComponent(ip)}`);
    // Re-check the modal is still open + still targeting THIS IP
    // (rapid-click protection — a second openProfileModal call would
    // have already overwritten the title with the new IP).
    if (modal.style.display === 'none') return;
    if (title && title.textContent !== 'Attacker dossier · ' + ip) return;
    body.innerHTML = renderProfileDossierHtml(p);
  } catch (e) {
    body.innerHTML = `<p style="color:#e74c3c;padding:16px">Failed to load: ${esc(e.message)}</p>`;
  }
}

function closeProfileModal() {
  const modal = document.getElementById('profileModal');
  if (!modal) return;
  modal.style.display = 'none';
  // Clear body so a follow-up open call starts from the loading
  // skeleton, not stale content from the previous IP.
  const body = document.getElementById('profileModalBody');
  if (body) body.innerHTML = '<div style="color:var(--muted);padding:24px;text-align:center">Loading…</div>';
}

// Escape-to-close. Single document-level listener so we never leak
// multiple handlers across re-opens.
if (typeof window !== 'undefined' && !window._profileModalEscBound) {
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      const modal = document.getElementById('profileModal');
      if (modal && modal.style.display !== 'none') closeProfileModal();
    }
  });
  window._profileModalEscBound = true;
}

// 2026-05-15 PR-A: `openIntelProfile` kept as a thin alias for
// backward compatibility with any cached call sites. New code MUST
// call `openProfileModal(ip)` directly.
function openIntelProfile(ip) {
  openProfileModal(ip);
}

let currentIntelTab = 'profiles';
// 2026-05-15 PR-B: Intel sub-tabs trimmed to Profiles + Baseline.
// Campaigns moved to a Cases header tag (PR-D). Chains: per-incident
// chains already on the Cases journey panel. MITRE: heatmap already
// on Monthly. Baseline is the only sub-tab that survives this PR — it
// moves to Health in PR-C.
function switchIntelTab(tab) {
  currentIntelTab = tab;
  const tabs = ['Profiles', 'Baseline'];
  tabs.forEach(t => {
    const btn = document.getElementById('intelTab'+t);
    if (btn) { const active = t.toLowerCase() === tab; btn.style.background = active ? 'var(--accent)' : 'var(--card-bg)'; btn.style.color = active ? '#0a0f1a' : 'var(--text)'; btn.style.fontWeight = active ? '600' : '400'; btn.style.borderColor = active ? 'var(--accent)' : 'var(--border)'; }
  });

  // 2026-05-02 audit fix (P8): the previous tab's content stayed on
  // screen for ~5s while the new sub-tab fetch was in flight. Clear
  // the content area immediately and abort any in-flight intel fetch
  // so a fast tab cycle never paints stale data under the new title.
  if (window._activeFetch_intel && typeof window._activeFetch_intel.abort === 'function') {
    try { window._activeFetch_intel.abort(); } catch (_) {}
  }
  window._activeFetch_intel = new AbortController();
  const content = document.getElementById('intelContent');
  if (content) content.innerHTML = '<div style="text-align:center;padding:40px;color:var(--muted);font-size:0.8rem">Loading...</div>';
  const status = document.getElementById('intelViewStatus');
  if (status) status.textContent = '';

  if (tab === 'baseline') loadBaseline();
  else loadIntel();
}

// ── Baseline sub-tab ──────────────────────────────────────────────
// ── Baseline tab — three-level UX (2026-05-03 redesign) ──────────────
//
// Operator complaint: the previous version dumped every learned
// signal as a long table and used SOC vocabulary ("lineages",
// "observations", "EMA"). Both the security analyst and the lay
// operator bounced off it. The redesign answers three questions in
// order:
//
//   1. Is everything normal right now?  → Hero (1 line, always visible)
//   2. If not, what changed?              → Deviation cards (top 5)
//   3. What does the agent consider normal here? → "Show learned baseline" (collapsed)
//
// The Hero card paints semaphore colours; deviation cards are
// actionable (each links to the relevant journey); the learned
// baseline section is opt-in. Layouts use heatmap + sparkline so
// the operator can read a week's pattern in one glance instead of
// scrolling a 24-row table per user.

// Friendly headlines + emoji + suggested action text per anomaly type.
// Server returns the raw `anomaly_type` enum value; this map turns it
// into a card the operator can read in 2 seconds.
// 2026-05-03 (PR #419 Wave 2): translated PT-BR → EN to align with
// the rest of the dashboard. Original strings were Portuguese-only,
// inconsistent with all other tabs. Operator request.
const BASELINE_ANOMALY_LABELS = {
  event_rate_drop: {
    icon: '📉',
    headline: (a) => `${prettySource(a)} went silent`,
    explainer: (a) => `Expected this hour: about ${a.expected}. Seen: ${a.observed}.`,
    why: 'Could mean nobody used the service or something disabled the logs. Worth checking.',
  },
  event_rate_spike: {
    icon: '📈',
    headline: (a) => `${prettySource(a)} spiked above normal`,
    explainer: (a) => `Expected: about ${a.expected}. Seen: ${a.observed}.`,
    why: 'Sudden activity peak. Could be a deploy, an external scan, or an attack in progress.',
  },
  process_lineage: {
    icon: '🌿',
    headline: (a) => 'Process lineage never seen before',
    explainer: (a) => a.description,
    why: 'The agent has never observed this parent → child on this host. Often indicates a shell spawning out of a web service.',
  },
  user_login_time: {
    icon: '🌙',
    headline: (a) => `${a.subject || 'User'} logged in outside typical hours`,
    explainer: (a) => `Typical hours: ${a.expected}. Login now: ${a.observed}.`,
    why: 'Access outside the historical pattern. Confirm whether it was you or an authorised user.',
  },
  new_destination: {
    icon: '🔀',
    headline: (a) => `${a.subject || 'Process'} connected to a new destination`,
    explainer: (a) => `Typical destinations: ${a.expected}. Now: ${a.observed}.`,
    why: 'A known process talking to an unfamiliar endpoint. Risk profile changes.',
  },
};

function prettySource(a) {
  // Pull a friendly source name from the description if present, or
  // fall back to a generic phrase. Server passes details inline.
  const m = (a.description || '').match(/source ['"]?([a-z_]+)['"]?/i);
  return m ? m[1] : 'Event collection';
}

function baselineCardForAnomaly(a) {
  const meta = BASELINE_ANOMALY_LABELS[a.anomaly_type] || {
    icon: '⚠️',
    headline: () => 'Pattern outside normal',
    explainer: (x) => x.description || '',
    why: '',
  };
  const ageMin = Math.max(0, Math.floor((Date.now() - new Date(a.ts).getTime()) / 60000));
  const ageStr = ageMin < 60
    ? `${ageMin}m ago`
    : ageMin < 1440
      ? `${Math.floor(ageMin / 60)}h ago`
      : `${Math.floor(ageMin / 1440)}d ago`;
  const sevColor = a.severity === 'critical' ? '#e74c3c'
    : a.severity === 'high' ? '#f39c12'
    : a.severity === 'medium' ? '#f59e0b'
    : 'var(--dim)';
  const subjectLink = a.subject
    ? `<button type="button" onclick="homeBannerOpenPivot('${a.anomaly_type === 'user_login_time' ? 'user' : 'ip'}', '${esc(a.subject)}')" style="margin-top:6px;padding:4px 10px;border-radius:4px;border:1px solid var(--accent);background:transparent;color:var(--accent);cursor:pointer;font-size:0.75rem;">Investigate ${esc(a.subject)} →</button>`
    : '';
  return `
    <div class="baseline-deviation-card">
      <div style="display:flex;align-items:flex-start;gap:10px;">
        <div style="font-size:1.5rem;line-height:1;">${meta.icon}</div>
        <div style="flex:1;">
          <div style="display:flex;align-items:baseline;gap:8px;flex-wrap:wrap;">
            <span style="font-weight:600;font-size:0.92rem;">${esc(meta.headline(a))}</span>
            <span style="font-size:0.7rem;color:${sevColor};text-transform:uppercase;letter-spacing:0.05em;">${esc(a.severity)}</span>
            <span style="font-size:0.7rem;color:var(--dim);">${ageStr}</span>
          </div>
          <div style="font-size:0.82rem;color:var(--text);margin-top:4px;line-height:1.5;">${esc(meta.explainer(a))}</div>
          ${meta.why ? `<div style="font-size:0.75rem;color:var(--dim);margin-top:4px;font-style:italic;">${esc(meta.why)}</div>` : ''}
          ${subjectLink}
        </div>
      </div>
    </div>`;
}

function baselineHeroCard(b, deviations24h) {
  if (!b.mature) {
    const days = b.training_days || 0;
    const remaining = Math.max(0, 7 - days);
    return `
      <div class="baseline-hero baseline-hero-learning">
        <div class="baseline-hero-icon">🔵</div>
        <div class="baseline-hero-body">
          <div class="baseline-hero-title">Learning what's normal on this server</div>
          <div class="baseline-hero-sub">${days} of 7 days collected. Anomaly detection starts in ${remaining} ${remaining === 1 ? 'day' : 'days'}.</div>
        </div>
      </div>`;
  }
  if (deviations24h === 0) {
    return `
      <div class="baseline-hero baseline-hero-normal">
        <div class="baseline-hero-icon">🟢</div>
        <div class="baseline-hero-body">
          <div class="baseline-hero-title">Normal</div>
          <div class="baseline-hero-sub">The server is behaving the same as on recent days. No patterns outside normal in the last 24 hours.</div>
        </div>
      </div>`;
  }
  return `
    <div class="baseline-hero baseline-hero-deviation">
      <div class="baseline-hero-icon">🟡</div>
      <div class="baseline-hero-body">
        <div class="baseline-hero-title">Something changed</div>
        <div class="baseline-hero-sub">${deviations24h} ${deviations24h === 1 ? 'pattern' : 'patterns'} outside normal in the last 24 hours. See what changed below.</div>
      </div>
    </div>`;
}

// 2026-05-03 (Wave 5): pagination state for the login heatmap. Stays a
// module-level let so back/forward inside the same Baseline render
// preserves the page; switching tabs resets via `_loginHeatmapPage = 0`
// in `loadBaseline`. Toggle state is persisted in localStorage so the
// operator's choice survives reloads.
let _loginHeatmapPage = 0;
const LOGIN_HEATMAP_PAGE_SIZE = 20;
const LOGIN_HEATMAP_LS_KEY = 'innerwarden.baseline.showServices';
// 2026-05-10: persist the "What I consider normal here" <details>
// open state so pagination re-renders don't collapse the section
// the operator was actively reading. Operator complaint: clicking
// Next on the user-list pagination collapsed the entire learned-
// baseline section. The HTML <details> default is closed, and
// loadBaseline() re-renders intelContent.innerHTML on every page
// change, so the open attribute was never preserved.
const BASELINE_LEARNED_OPEN_LS_KEY = 'innerwarden.baseline.learnedOpen';

function baselineLearnedIsOpen() {
  try {
    return localStorage.getItem(BASELINE_LEARNED_OPEN_LS_KEY) === '1';
  } catch (_) {
    return false;
  }
}

function baselineLearnedSetOpen(v) {
  try {
    localStorage.setItem(BASELINE_LEARNED_OPEN_LS_KEY, v ? '1' : '0');
  } catch (_) {}
}

function loginHeatmapShowServices() {
  try {
    return localStorage.getItem(LOGIN_HEATMAP_LS_KEY) === '1';
  } catch (_) {
    return false;
  }
}

function loginHeatmapSetShowServices(v) {
  try {
    localStorage.setItem(LOGIN_HEATMAP_LS_KEY, v ? '1' : '0');
  } catch (_) {}
}

// Exposed onclick handlers for the toggle + pagination. Re-renders by
// calling `loadBaseline()` so the controls go through the same data path
// as the initial load — a single source of truth for what the user sees.
window.toggleLoginHeatmapServices = function () {
  loginHeatmapSetShowServices(!loginHeatmapShowServices());
  _loginHeatmapPage = 0;
  loadBaseline();
};
window.loginHeatmapNextPage = function () {
  _loginHeatmapPage += 1;
  loadBaseline();
};
window.loginHeatmapPrevPage = function () {
  _loginHeatmapPage = Math.max(0, _loginHeatmapPage - 1);
  loadBaseline();
};
// 2026-05-10: persist <details open> state for the learned-baseline
// section so re-renders triggered by user-list pagination do not
// collapse the section the operator was actively reading.
window.baselineLearnedOnToggle = function (el) {
  baselineLearnedSetOpen(el && el.open);
};

function loginHeatmap(logins, userClasses) {
  // Full-width 24×N heatmap. Each user gets a single row of 24 cells.
  // Bright cell = login activity seen in that hour historically.
  //
  // 2026-05-03 (Wave 5 — semantics fix):
  // - PAM emits "session opened" entries for daemon accounts
  //   (snap_daemon, systemd-resolve, messagebus, _apt, ...) that share
  //   plumbing with real SSH logins. Without filtering, the heatmap
  //   reads as "many users have logged in" when in reality only the
  //   `Human` + `Root` rows are real human SSH sessions.
  // - The endpoint enriches the JSON with `user_classes`. When that
  //   field is missing (older agent / classification failed), every
  //   user falls back to `unknown` and is shown — operator visibility
  //   beats false reassurance.
  // - The "Show system accounts" toggle is persisted in localStorage
  //   so the operator's choice survives reloads.
  // - Pagination kicks in only when visible humans exceed
  //   LOGIN_HEATMAP_PAGE_SIZE (20). Below that threshold, no paging
  //   controls render at all — keeps the simple case simple.
  const allUsers = Object.entries(logins);
  if (allUsers.length === 0) return '';
  const classes = userClasses || {};
  const classOf = (u) => classes[u] || 'unknown';

  const showServices = loginHeatmapShowServices();
  const visible = allUsers.filter(([user]) => {
    const c = classOf(user);
    if (c === 'service') return showServices;
    return true; // human, root, unknown — always visible
  });
  const hiddenServices = allUsers.length - visible.length;

  const totalPages = Math.max(1, Math.ceil(visible.length / LOGIN_HEATMAP_PAGE_SIZE));
  if (_loginHeatmapPage >= totalPages) _loginHeatmapPage = totalPages - 1;
  const pageStart = _loginHeatmapPage * LOGIN_HEATMAP_PAGE_SIZE;
  const pageUsers = visible.slice(pageStart, pageStart + LOGIN_HEATMAP_PAGE_SIZE);

  const classBadge = (c) => {
    const labels = { human: 'human', root: 'root', service: 'service', unknown: 'unknown' };
    const label = labels[c] || c;
    return `<span class="login-class-badge login-class-badge-${c}">${label}</span>`;
  };

  const rows = pageUsers.map(([user, hours]) => {
    const c = classOf(user);
    const cells = hours.map((v, i) => {
      const active = v > 0;
      const cls = active ? 'login-cell login-cell-active' : 'login-cell';
      const tip = `${user} (${c}) - ${i}:00 ${active ? '✓ session at this hour' : '(no record)'}`;
      return `<div class="${cls}" title="${esc(tip)}"></div>`;
    }).join('');
    return `
      <div class="login-heatmap-row">
        <div class="login-heatmap-user">
          ${classBadge(c)}
          <span class="login-heatmap-user-name" title="${esc(user)}">${esc(user)}</span>
        </div>
        <div class="login-heatmap-cells">${cells}</div>
      </div>`;
  }).join('');

  // Toggle row + (optional) pagination row + (optional) hint about
  // hidden service entries. Keep them above the grid so the operator
  // sees the controls before the data.
  const showHideLabel = showServices
    ? `Hide system accounts`
    : (hiddenServices > 0
      ? `Show system accounts (${hiddenServices})`
      : `Show system accounts`);
  const toggleRow = `
    <div class="login-heatmap-controls">
      <button type="button" class="login-heatmap-toggle" onclick="toggleLoginHeatmapServices()">
        ${esc(showHideLabel)}
      </button>
      ${hiddenServices > 0 && !showServices ? `
        <span class="login-heatmap-hint">
          ${hiddenServices} ${hiddenServices === 1 ? 'daemon PAM session is' : 'daemon PAM sessions are'} hidden (snap_daemon, systemd-resolve, etc.) — they share SSH plumbing but are not real human logins.
        </span>` : ''}
    </div>`;

  const paginationRow = visible.length > LOGIN_HEATMAP_PAGE_SIZE ? `
    <div class="login-heatmap-pagination">
      <button type="button" onclick="loginHeatmapPrevPage()" ${_loginHeatmapPage === 0 ? 'disabled' : ''}>← Prev</button>
      <span class="login-heatmap-page-meta">Page ${_loginHeatmapPage + 1} of ${totalPages} · showing ${pageUsers.length} of ${visible.length} users</span>
      <button type="button" onclick="loginHeatmapNextPage()" ${_loginHeatmapPage >= totalPages - 1 ? 'disabled' : ''}>Next →</button>
    </div>` : '';

  return `
    ${toggleRow}
    <div class="login-heatmap">
      <div class="login-heatmap-axis"><span>0h</span><span>6h</span><span>12h</span><span>18h</span><span>23h</span></div>
      ${rows}
    </div>
    ${paginationRow}`;
}

function eventRateAggregateSparkline(rates) {
  const sourceCount = Object.keys(rates).length;
  if (sourceCount === 0) return '';
  // Aggregate: sum per hour across all sources. Operator wants the
  // overall pulse, not per-source detail at this level.
  const aggregate = new Array(24).fill(0);
  for (const hours of Object.values(rates)) {
    for (let i = 0; i < 24; i++) aggregate[i] += hours[i] || 0;
  }
  const max = Math.max(...aggregate, 1);
  const bars = aggregate.map((v, i) => {
    const h = Math.max(2, (v / max) * 36);
    const tooltip = `${i}:00 - ~${v.toFixed(0)} typical events`;
    return `<div class="sparkline-bar" style="height:${h}px;" title="${tooltip}"></div>`;
  }).join('');
  return `
    <div class="baseline-sparkline">
      <div class="baseline-sparkline-label">Typical activity per hour (all ${sourceCount} sources combined)</div>
      <div class="baseline-sparkline-bars">${bars}</div>
      <div class="baseline-sparkline-axis"><span>0h</span><span>6h</span><span>12h</span><span>18h</span><span>23h</span></div>
    </div>`;
}

function topProcessDestinations(dests, limit) {
  const entries = Object.entries(dests)
    .map(([p, ips]) => ({ proc: p, count: Array.isArray(ips) ? ips.length : 0 }))
    .filter((x) => x.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
  if (entries.length === 0) return '<p style="color:var(--dim);font-size:0.8rem;">No destinations observed yet.</p>';
  return `
    <ul class="baseline-dest-list">
      ${entries.map((x) => `
        <li><code>${esc(x.proc)}</code> connects to <strong>${x.count}</strong> ${x.count === 1 ? 'known destination' : 'known destinations'}</li>
      `).join('')}
    </ul>`;
}

function topProcessLineages(lineages, limit) {
  // The wire shape can be either an array of strings ("nginx→sh") or
  // an object map. Normalise.
  let list = [];
  if (Array.isArray(lineages)) list = lineages;
  else if (lineages && typeof lineages === 'object') list = Object.keys(lineages);
  if (list.length === 0) return '';
  return `
    <p style="font-size:0.8rem;margin:6px 0;color:var(--dim);">
      ${list.length} parent→child chains considered normal. Examples:
      ${list.slice(0, limit).map((l) => `<code>${esc(l)}</code>`).join(' · ')}
    </p>`;
}

async function loadBaseline() {
  const content = document.getElementById('intelContent');
  const statusEl = document.getElementById('intelViewStatus');
  if (statusEl) statusEl.textContent = 'Loading…';
  const signal = window._activeFetch_intel ? window._activeFetch_intel.signal : undefined;
  try {
    const b = await loadJson('/api/baseline-status', { signal });

    // Anomalies in the last 24h. Server may or may not surface them;
    // tolerate both shapes.
    const anomalies = Array.isArray(b.recent_anomalies) ? b.recent_anomalies : [];
    const since24h = Date.now() - 24 * 3600 * 1000;
    const recent = anomalies
      .filter((a) => a.ts && new Date(a.ts).getTime() >= since24h)
      .sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());

    let html = '';

    // ── Level 1: Hero ────────────────────────────────────────
    html += baselineHeroCard(b, recent.length);

    // ── Level 2: deviation cards (top 5) ─────────────────────
    if (recent.length > 0) {
      html += '<h3 class="baseline-section-title">What changed in the last 24 hours</h3>';
      html += '<div class="baseline-deviations">';
      html += recent.slice(0, 5).map(baselineCardForAnomaly).join('');
      html += '</div>';
      if (recent.length > 5) {
        html += `<p style="font-size:0.78rem;color:var(--dim);margin-top:8px;">+${recent.length - 5} other patterns. <a href="#threats" style="color:var(--accent);">See in investigation →</a></p>`;
      }
    } else if (b.mature) {
      html += '<div class="baseline-empty-deviations">No deviations detected in the last 24 hours.</div>';
    }

    // ── Level 3: collapsed "learned baseline" ────────────────
    const lineages = b.process_lineages;
    const lineageCount = Array.isArray(lineages)
      ? lineages.length
      : (lineages && typeof lineages === 'object' ? Object.keys(lineages).length : 0);
    const learnedSummary = `
      ${(b.training_days || 0) >= 7 ? '✓ 7+ days of learning' : `${b.training_days || 0}/7 days of learning`}
      · ${(b.total_observations || 0).toLocaleString('en-US')} events observed
      · ${lineageCount} known process lineages
    `;
    const learnedOpenAttr = baselineLearnedIsOpen() ? 'open' : '';
    html += `
      <details class="baseline-learned" id="baselineLearnedSection" ${learnedOpenAttr} ontoggle="window.baselineLearnedOnToggle && window.baselineLearnedOnToggle(this)">
        <summary class="baseline-learned-summary">
          <span>What I consider normal here</span>
          <span class="baseline-learned-meta">${learnedSummary.replace(/\s+/g, ' ').trim()}</span>
        </summary>
        <div class="baseline-learned-body">
          ${eventRateAggregateSparkline(b.event_rate_by_hour || {})}
          ${Object.keys(b.user_login_hours || {}).length > 0 ? `
            <h4 class="baseline-subtitle">Who logs in, when</h4>
            <p style="font-size:0.8rem;color:var(--dim);margin:0 0 8px;">Each row is a user; each square is an hour of the day this user was seen with an active session. System accounts (snap_daemon, systemd-resolve, _apt, ...) are hidden by default — they share PAM plumbing with real SSH logins but are not human sessions.</p>
            ${loginHeatmap(b.user_login_hours, b.user_classes)}
          ` : ''}
          ${Object.keys(b.process_destinations || {}).length > 0 ? `
            <h4 class="baseline-subtitle">Processes that talk to the outside</h4>
            ${topProcessDestinations(b.process_destinations, 6)}
          ` : ''}
          ${lineageCount > 0 ? `
            <h4 class="baseline-subtitle">Learned process lineages</h4>
            ${topProcessLineages(lineages, 6)}
          ` : ''}
        </div>
      </details>`;

    content.innerHTML = html;
    if (statusEl) {
      statusEl.textContent = !b.mature
        ? `Learning (${b.training_days || 0}/7 days)`
        : recent.length === 0
          ? 'All normal'
          : `${recent.length} ${recent.length === 1 ? 'deviation' : 'deviations'} in the last 24h`;
    }
  } catch(e) {
    if (e && (e.name === 'AbortError' || e.code === 20)) return;
    content.innerHTML = `<p style="color:#e74c3c">Failed to load Baseline: ${e.message}</p>`;
  }
}
