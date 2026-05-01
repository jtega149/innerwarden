// ── Investigation state ────────────────────────────────────────────────
const state = {
  pivot: 'ip',
  selected: { type: 'ip', value: null },
  filters: {
    date: '',
    compare_date: '',
    severity_min: '',
    detector: '',
    window_seconds: '',
    // Audit 2.6 partial: outcome bucket filter (blocked / monitoring /
    // honeypot / needs_attention / dismissed / allowlisted). Empty
    // string keeps every bucket visible (default).
    status: ''
  },
  clusters: [],
  knownItemValues: new Set(),  // D7: tracks rendered entity values for diff
  hideAllowlisted: true,
  filterOutcome: null,
  // spec 017 01-home Change 8: consume-once handoff from Home's
  // viewActivity() to Threats. 02-threats.md's responsibility to
  // read-and-clear this flag after selecting the first matching item.
  autoSelectOnThreatsOpen: null,
};

const pivotTitle = (pivot) => ({
  ip: 'Attackers (IP)',
  user: 'Users (Pivot)',
  detector: 'Detectors (Pivot)',
}[pivot] || 'Entities');

function parsePivotToken(token) {
  const i = String(token || '').indexOf(':');
  if (i <= 0) return { type: 'detector', value: String(token || '') };
  return { type: token.slice(0, i), value: token.slice(i + 1) };
}

function buildQuery(params) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v === null || v === undefined) return;
    const val = String(v).trim();
    if (!val) return;
    q.set(k, val);
  });
  return q.toString();
}

function syncFiltersFromUi() {
  // 2026-04-29: clamp future dates the operator may have picked from
  // the calendar widget. Without this, picking next month yields an
  // empty page with no signal the date is wrong. Bring it back to
  // today; the empty-state diagnostic surfaces a clearer message if
  // data is still missing.
  var rawDate = document.getElementById('flt-date').value || '';
  if (rawDate) {
    var today = new Date().toISOString().slice(0, 10);
    if (rawDate > today) {
      rawDate = today;
      var dEl = document.getElementById('flt-date');
      if (dEl) dEl.value = today;
    }
  }
  state.filters.date = rawDate;
  state.filters.compare_date = document.getElementById('flt-compare-date').value || '';
  state.filters.severity_min = document.getElementById('flt-severity').value || '';
  state.filters.detector = (document.getElementById('flt-detector').value || '').trim();
  state.filters.window_seconds = document.getElementById('flt-window').value || '';
  state.filters.status = document.getElementById('flt-status').value || '';
}

function hydrateStateFromQuery() {
  const qs = new URLSearchParams(window.location.search || '');
  const pivot = (qs.get('pivot') || '').trim();
  if (pivot === 'ip' || pivot === 'user' || pivot === 'detector') {
    state.pivot = pivot;
  }

  // Ignore a stale `date` query param from a prior session: if the URL
  // carries yesterday's date (or older), default to today so the Threats
  // tab does not appear empty on reload. Users can still pick an older
  // date manually via the filter — that stays live because refreshLeft
  // calls syncUrl and keeps the picker value in sync.
  const qsDate = (qs.get('date') || '').trim();
  const todayIso = new Date().toISOString().slice(0, 10);
  state.filters.date = qsDate && qsDate >= todayIso ? qsDate : '';
  state.filters.compare_date = (qs.get('compare_date') || '').trim();
  state.filters.severity_min = (qs.get('severity_min') || '').trim();
  state.filters.detector = (qs.get('detector') || '').trim();
  state.filters.window_seconds = (qs.get('window_seconds') || '').trim();
  state.filters.status = (qs.get('status') || '').trim();

  const subjectType = (qs.get('subject_type') || '').trim();
  const subject = (qs.get('subject') || '').trim();
  if ((subjectType === 'ip' || subjectType === 'user' || subjectType === 'detector') && subject) {
    state.selected = { type: subjectType, value: subject };
  }
}

function syncUrl() {
  const qs = buildQuery({
    pivot: state.pivot,
    date: state.filters.date,
    compare_date: state.filters.compare_date,
    severity_min: state.filters.severity_min,
    detector: state.filters.detector,
    window_seconds: state.filters.window_seconds,
    status: state.filters.status,
    subject_type: state.selected.value ? state.selected.type : '',
    subject: state.selected.value ? state.selected.value : '',
  });
  const nextUrl = qs ? ('?' + qs) : window.location.pathname;
  window.history.replaceState({}, '', nextUrl);
}

function updatePivotUi() {
  document.querySelectorAll('.pivot-tab').forEach((tab) => {
    tab.classList.toggle('active', tab.dataset.pivot === state.pivot);
  });
  document.getElementById('entityTitle').textContent = pivotTitle(state.pivot);
}

