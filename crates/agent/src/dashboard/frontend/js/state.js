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
    status: '',
    // Spec 049 PR5: hour-of-day scope picker. Strings (not numbers)
    // so the empty default ('') passes through buildQuery's trim/
    // empty check without sending a stray `hour_from=NaN`. Backend
    // PR4 validates: both must be present, both 0-23, lo <= hi.
    hour_from: '',
    hour_to: ''
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
  // 2026-05-15 slim-down: compare-date, severity, detector, window and
  // status inputs were removed from the Cases sidebar. Guard each read
  // so syncFiltersFromUi does not throw on null.value — the state
  // fields are kept in `state.filters` for URL-deep-link replay.
  var cmpEl = document.getElementById('flt-compare-date');
  state.filters.compare_date = cmpEl ? (cmpEl.value || '') : '';
  var sevEl = document.getElementById('flt-severity');
  state.filters.severity_min = sevEl ? (sevEl.value || '') : '';
  var detEl = document.getElementById('flt-detector');
  state.filters.detector = detEl ? ((detEl.value || '').trim()) : '';
  var winEl = document.getElementById('flt-window');
  state.filters.window_seconds = winEl ? (winEl.value || '') : '';
  var statEl = document.getElementById('flt-status');
  state.filters.status = statEl ? (statEl.value || '') : '';
  // Spec 049 PR5: hour-of-day picker. Validate at the UI boundary so
  // a malformed value (e.g. typed "99") never reaches the backend.
  // Same contract as `parse_hour_filter` in `data_api.rs`: both must
  // be in 0-23 and `from <= to`, otherwise treat as no filter.
  var hourFromEl = document.getElementById('flt-hour-from');
  var hourToEl = document.getElementById('flt-hour-to');
  var hf = hourFromEl ? parseInt(hourFromEl.value, 10) : NaN;
  var ht = hourToEl ? parseInt(hourToEl.value, 10) : NaN;
  if (Number.isInteger(hf) && Number.isInteger(ht)
      && hf >= 0 && hf <= 23 && ht >= 0 && ht <= 23 && hf <= ht) {
    state.filters.hour_from = String(hf);
    state.filters.hour_to = String(ht);
  } else {
    state.filters.hour_from = '';
    state.filters.hour_to = '';
  }
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
  // Spec 049 PR5: hydrate hour-of-day filter from URL so deep links
  // ("share me the case you saw at 15h yesterday") survive a reload.
  state.filters.hour_from = (qs.get('hour_from') || '').trim();
  state.filters.hour_to = (qs.get('hour_to') || '').trim();

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
    // Spec 049 PR5: hour-of-day flows through the URL so the scope
    // survives reloads + deep-link shares between MSSP operators.
    hour_from: state.filters.hour_from,
    hour_to: state.filters.hour_to,
    subject_type: state.selected.value ? state.selected.type : '',
    subject: state.selected.value ? state.selected.value : '',
  });
  const nextUrl = qs ? ('?' + qs) : window.location.pathname;
  window.history.replaceState({}, '', nextUrl);
}

function updatePivotUi() {
  // 2026-05-15 slim-down: pivot tabs + entity-title header were removed
  // from the Cases sidebar. Function kept as a defensive no-op so older
  // call sites do not need to be touched all at once.
  document.querySelectorAll('.pivot-tab').forEach((tab) => {
    tab.classList.toggle('active', tab.dataset.pivot === state.pivot);
  });
  var title = document.getElementById('entityTitle');
  if (title) title.textContent = pivotTitle(state.pivot);
}

