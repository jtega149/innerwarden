// ── Confidence system helpers ─────────────────────────────────────────
function getUnresolved() {
  var ov = window._lastOverview || {};
  var confirmed = ov.ai_confirmed || 0;
  var responded = ov.ai_responded || 0;
  var unresolved = ov.unresolved_count != null ? ov.unresolved_count : Math.max(confirmed - responded, 0);
  return { total: confirmed, unresolved: unresolved, handled: responded };
}

var DETECTOR_LABELS = {
  ssh_bruteforce: 'SSH login attempts', credential_stuffing: 'Credential testing',
  host_drift: 'Unexpected process', execution_guard: 'Command monitoring',
  port_scan: 'Port scan', web_scan: 'Web vulnerability scan',
  user_agent_scanner: 'Automated scanner', network_sniffer: 'Network monitor detected',
  network_sniffing: 'Network monitoring tool', kernel_module: 'Kernel module loaded',
  dns_tunnel: 'DNS tunnel attempt', dns_c2: 'DNS command-and-control',
  reverse_shell: 'Reverse shell attempt', fileless_exec: 'Memory-only execution',
  sudo_abuse: 'Privilege escalation attempt', search_abuse: 'Search abuse',
  service_stop: 'Service stopped', container_escape: 'Container escape attempt',
  rootkit: 'Rootkit detection', log_tampering: 'Log tampering',
  proto_anomaly: 'Suspicious connection', threat_intel: 'Known malicious IP',
  packet_flood: 'Packet flood', discovery_burst: 'Reconnaissance burst',
  data_exfil_cmd: 'Data exfiltration attempt', suspicious_execution: 'Suspicious command',
  suspicious_archive: 'Suspicious archive creation', logging_config_change: 'Logging config changed',
  timing_anomaly: 'Timing anomaly'
};

function humanLabel(slug) {
  return DETECTOR_LABELS[slug] || slug.replace(/_/g, ' ').replace(/\b\w/g, function(c) { return c.toUpperCase(); });
}

function aggregateIncidents(incidents) {
  var groups = {};
  (incidents || []).forEach(function(inc) {
    var slug = (inc.incident_id || '').split(':')[0] || 'unknown';
    var outcome = inc.outcome || 'open';
    var key = slug + '|' + outcome;
    if (!groups[key]) {
      groups[key] = { slug: slug, outcome: outcome, count: 0,
        severity: inc.severity, latest: inc, ips: {} };
    }
    groups[key].count++;
    var ip = (inc.entities || []).find(function(e) { return e.type === 'Ip' || e.type === 'ip'; });
    if (ip) groups[key].ips[ip.value] = true;
    if (inc.ts > groups[key].latest.ts) groups[key].latest = inc;
  });
  return Object.values(groups).sort(function(a, b) {
    if (a.outcome === 'open' && b.outcome !== 'open') return -1;
    if (a.outcome !== 'open' && b.outcome === 'open') return 1;
    return b.count - a.count;
  });
}

function outcomeBadgeHtml(outcome) {
  if (outcome === 'blocked' || outcome === 'killed' || outcome === 'contained' || outcome === 'suspended')
    return '<span class="badge-contained">CONTAINED</span>';
  if (outcome === 'ignored') return '<span class="badge-noise">NOISE</span>';
  if (outcome === 'open') return '<span class="badge-unresolved">OPEN</span>';
  if (outcome === 'monitored') return '<span class="badge-monitor" style="font-size:0.62rem;padding:2px 7px;border-radius:4px">MONITORING</span>';
  if (outcome === 'honeypot') return '<span style="font-size:0.62rem;padding:2px 7px;border-radius:4px;background:rgba(255,140,66,0.12);color:var(--orange);font-weight:600">HONEYPOT</span>';
  return '';
}

function humanIncidentTitle(detector, rawTitle, ip) {
  var label = humanLabel(detector);
  if (ip) label += ' \u2014 ' + ip;
  return label;
}

function contextLine(outcome, severity) {
  switch (outcome) {
    case 'blocked': case 'killed': case 'contained': case 'suspended':
      return { text: 'Handled automatically \u2014 no action needed', cls: '' };
    case 'ignored':
      return { text: 'Classified as noise \u2014 no action needed', cls: '' };
    case 'monitored':
      return { text: 'Being monitored \u2014 system watching for escalation', cls: '' };
    case 'honeypot':
      return { text: 'Redirected to honeypot \u2014 attacker contained safely', cls: '' };
    default:
      if (severity === 'critical' || severity === 'high')
        return { text: 'Needs review \u2014 no automated response taken', cls: 'needs-action' };
      return { text: 'Awaiting analysis', cls: '' };
  }
}

function entryOutcomeClass(entry) {
  var d = entry.data || {};
  // For decisions, use the action to infer outcome
  if (entry.kind === 'decision') {
    var at = d.action_type || '';
    if (['block_ip','kill_process','block_container','suspend_user_sudo'].includes(at)) return 'entry-contained';
    if (at === 'ignore') return 'entry-noise';
    return '';
  }
  // For incidents, check if there's an outcome hint or use severity
  // We don't have outcome directly on the entry, so we check if the journey has it
  return '';
}

function toggleDetail(btn) {
  var body = btn.parentElement.nextElementSibling;
  if (!body) return;
  body.classList.toggle('open');
  btn.textContent = body.classList.contains('open') ? 'Hide details' : 'Show details';
}


function isPrivateIp(ip) {
  return ip.startsWith('10.') || ip.startsWith('127.') || ip.startsWith('192.168.') ||
    ip.startsWith('169.254.') || ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}

function isIncidentTrusted(inc) {
  var entities = inc.entities || [];
  var hasExternalIp = false;
  for (var i = 0; i < entities.length; i++) {
    var e = entities[i];
    var eType = (typeof e === 'string') ? (e.split(':')[0] || '') : (e.type || '');
    var eVal = (typeof e === 'string') ? (e.split(':').slice(1).join(':') || '') : (e.value || '');
    if (eType.toLowerCase() === 'ip') {
      if (isIpTrusted(eVal) || isPrivateIp(eVal)) return true;
      hasExternalIp = true;
    }
    if (eType.toLowerCase() === 'user') {
      if (_trustedUsers.indexOf(eVal) >= 0) return true;
    }
  }
  // No IP at all = internal/local activity = trusted
  if (!hasExternalIp) return true;
  return false;
}


// ── E2 - Home state (Threats right-panel) ────────────────────────────────
async function loadHomeState() {
  try {
    const [overview, decisions, pivots] = await Promise.all([
      loadJson('/api/overview'),
      loadJson('/api/decisions?limit=5'),
      loadJson('/api/pivots?group_by=ip&limit=5')
    ]);

    // Update status hero and activity feed
    const incidentList = await loadJson('/api/incidents?limit=30');
    updateStatusHero(incidentList.items || [], decisions.items || []);
    buildActivityFeed(incidentList.items || [], decisions.items || []);

    // KPI strip in left panel
    setHomeKpi('h-events', overview.events_count ?? 0);
    setHomeKpi('h-incidents', overview.incidents_count ?? 0);
    setHomeKpi('h-decisions', overview.decisions_count ?? 0);
    setHomeKpi('h-blocks', (decisions.items || []).filter(d => d.action_type === 'block_ip' && d.auto_executed).length);
  } catch(e) {
    console.warn('Home state load error:', e);
  }
}

function setHomeKpi(id, val) {
  const el = document.getElementById(id);
  if (el) { el.textContent = val; }
}

function timeAgo(ts) {
  if (!ts) return '';
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60) return diff + 's ago';
  if (diff < 3600) return Math.floor(diff/60) + 'm ago';
  if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
  return Math.floor(diff/86400) + 'd ago';
}

function handleCardClickByValue(type, value) {
  // Find the card with this value and click it, or load journey directly
  const cards = document.querySelectorAll('.attacker-card');
  for (const card of cards) {
    if (card.dataset.subjectValue === value && card.dataset.subjectType === type) {
      card.click();
      return;
    }
  }
  // Direct load
  loadJourney(type, value);
}

function showHomeState() {
  document.getElementById('homeState').style.display = '';
  document.getElementById('journeyContent').style.display = 'none';
  document.getElementById('journeyContent').innerHTML = '';
  // Deselect active card
  document.querySelectorAll('.attacker-card.active').forEach(c => c.classList.remove('active'));
  state.currentSubject = null;
}

function investigateTopThreat() {
  // Click the first attacker card if one exists, else no-op
  const first = document.querySelector('.attacker-card');
  if (first) { first.click(); return; }
  // Show investigate tab in case we're in a different view
  showView('investigate');
}

function toggleAdvFilters() {
  const el = document.getElementById('advFilters');
  const btn = document.getElementById('flt-adv-toggle');
  if (!el || !btn) return;
  const open = el.style.display !== 'none';
  el.style.display = open ? 'none' : 'block';
  btn.textContent = open ? '▸ Advanced filters' : '▾ Advanced filters';
}
