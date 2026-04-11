// ── Honeypot tab ──────────────────────────────────────────────────────
async function loadHoneypot() {
  const status = document.getElementById('honeypotViewStatus');
  const content = document.getElementById('honeypotContent');
  if (!status || !content) return;
  status.textContent = 'Loading…';
  content.innerHTML = '<div class="empty" style="padding:40px;text-align:center">Loading…</div>';
  try {
    const data = await loadJson('/api/honeypot/sessions');
    status.textContent = 'Updated ' + new Date().toLocaleTimeString();
    content.innerHTML = renderHoneypot(data);
  } catch(e) {
    status.textContent = 'Error';
    content.innerHTML = '<div class="empty" style="padding:40px;text-align:center;color:var(--danger)">Failed to load honeypot sessions.</div>';
  }
}

async function testHoneypot() {
  const btn = document.getElementById('btnTestHoneypot');
  if (!btn) return;
  btn.disabled = true;
  btn.textContent = '⏳ Starting...';
  try {
    const reason = 'Teste manual via dashboard';
    const resp = await fetch('/api/action/honeypot', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason, duration_secs: 120 })
    });
    const data = await resp.json();
    if (data.success) {
      showToast('🍯 ' + data.message, 'ok');
    } else {
      showToast('❌ ' + data.message, 'err');
    }
  } catch (e) {
    showToast('❌ Request failed: ' + e.message, 'err');
  } finally {
    btn.disabled = false;
    btn.textContent = '🧪 Start test session';
  }
}

function renderHoneypot(data) {
  const sessions = data.sessions || [];

  // Test button shown regardless of whether sessions exist
  const testBtn = '<div style="padding:16px 16px 0;max-width:900px;margin:0 auto">' +
    '<button id="btnTestHoneypot" onclick="testHoneypot()" ' +
    'style="background:rgba(120,229,255,0.08);border:1px solid rgba(120,229,255,0.28);' +
    'border-radius:8px;color:var(--accent);font-size:0.78rem;font-weight:600;' +
    'padding:8px 18px;cursor:pointer;transition:background 0.15s,border-color 0.15s;' +
    'font-family:inherit" ' +
    'onmouseover="this.style.background=\'rgba(120,229,255,0.15)\'" ' +
    'onmouseout="this.style.background=\'rgba(120,229,255,0.08)\'">' +
    '🧪 Start test session</button>' +
    '<span style="font-size:0.68rem;color:var(--muted);margin-left:10px">' +
    'Injects a test incident - the agent evaluates and triggers the honeypot on the next tick (≤2 s).' +
    '</span></div>';

  if (sessions.length === 0) {
    return testBtn + '<div class="empty" style="padding:40px;text-align:center;opacity:0.5">🍯 No honeypot sessions yet.<br><span style="font-size:0.8rem">Sessions appear here when attackers interact with a honeypot listener.</span></div>';
  }

  let html = testBtn + '<div style="padding:16px;max-width:900px;margin:0 auto">';
  html += '<div style="font-size:1.1rem;font-weight:600;color:var(--accent);margin-bottom:16px">🍯 Honeypot Sessions (' + sessions.length + ')</div>';

  for (const s of sessions) {
    const ip = s.target_ip || '-';
    const sessionId = s.session_id || '-';
    const startedAt = s.started_at ? new Date(s.started_at).toLocaleString() : '-';
    const duration = s.duration_secs ? s.duration_secs + 's' : '-';
    const cmdCount = s.commands_count || 0;
    const authCount = s.auth_attempts || 0;
    const commands = s.commands || [];
    const iocs = s.iocs || [];
    const blocked = !!s.blocked;
    const mode = s.mode || 'listener';

    html += '<div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:16px;margin-bottom:12px">';

    // Header row
    html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap">';
    html += '<span style="font-family:monospace;font-size:1rem;color:var(--accent)">' + esc(ip) + '</span>';
    if (blocked) {
      html += '<span style="background:rgba(58,194,126,0.15);color:#3ac27e;border:1px solid rgba(58,194,126,0.3);border-radius:4px;padding:2px 8px;font-size:0.7rem;font-weight:600">BLOCKED</span>';
    }
    if (mode === 'always_on') {
      html += '<span style="background:rgba(120,229,255,0.08);color:var(--accent);border:1px solid rgba(120,229,255,0.2);border-radius:4px;padding:2px 8px;font-size:0.7rem">ALWAYS-ON</span>';
    }
    html += '<span style="font-size:0.75rem;opacity:0.6">' + esc(startedAt) + '</span>';
    if (s.duration_secs) html += '<span style="font-size:0.75rem;opacity:0.6">Duration: ' + esc(duration) + '</span>';
    html += '<span style="font-size:0.75rem;opacity:0.6">Auth attempts: ' + authCount + '</span>';
    html += '<span style="font-size:0.75rem;opacity:0.6">Commands: ' + cmdCount + '</span>';
    html += '</div>';

    // Session ID
    html += '<div style="font-size:0.7rem;opacity:0.4;margin-bottom:10px;font-family:monospace">' + esc(sessionId) + '</div>';

    // Commands
    if (commands.length > 0) {
      html += '<div style="margin-bottom:10px">';
      html += '<div style="font-size:0.75rem;font-weight:600;color:rgba(255,255,255,0.7);margin-bottom:6px">Commands typed by attacker</div>';
      html += '<div style="background:rgba(0,0,0,0.3);border-radius:6px;padding:10px;font-family:monospace;font-size:0.78rem;color:rgba(255,255,255,0.85)">';
      for (const cmd of commands.slice(0, 15)) {
        html += '<div style="margin-bottom:3px"><span style="color:var(--accent);opacity:0.7">$</span> ' + esc(cmd) + '</div>';
      }
      if (commands.length > 15) {
        html += '<div style="opacity:0.4;font-size:0.7rem">... ' + (commands.length - 15) + ' more commands</div>';
      }
      html += '</div></div>';
    }

    // IOCs
    if (iocs.length > 0) {
      html += '<div style="margin-top:10px">';
      html += '<div style="font-size:0.75rem;font-weight:600;color:#f59e0b;margin-bottom:6px">⚠ Extracted IOCs</div>';
      html += '<div style="background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);border-radius:6px;padding:10px">';
      for (const ioc of iocs) {
        html += '<div style="font-family:monospace;font-size:0.78rem;color:var(--warn);margin-bottom:3px">' + esc(ioc) + '</div>';
      }
      html += '</div></div>';
    }

    html += '</div>'; // end session card
  }

  html += '</div>';
  return html;
}

