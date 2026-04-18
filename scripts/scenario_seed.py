#!/usr/bin/env python3
# Spec 024 — seed helper for scenarios that cannot drive the agent through a
# real sensor run (no eBPF on the CI runner, no root for a TCP honeypot
# listener, no packet generator for DDoS).
#
# Reads fixtures from a scenario's `input/` directory and pre-populates the
# agent's data_dir so that `agent --once` sees the same state it would see in
# production after the corresponding attack happened:
#
#   input/seed-incidents.jsonl           -> rows inserted into innerwarden.db
#   input/seed-honeypot-sessions.jsonl   -> honeypot-sessions-YYYY-MM-DD.jsonl
#   input/seed-kv.jsonl                  -> rows inserted into kv_state
#
# seed-kv.jsonl is one JSON per line, each with `namespace`, `key`, and `value`
# (value may be an object — it is stringified as JSON before being stored as
# BLOB). Used for pre-warming caches the agent reads before calling out (e.g.
# `abuseipdb_cache` for scenario 3).
#
# Each line of seed-incidents.jsonl is a full Incident JSON (matches
# `core::Incident` serde layout). `incident_id` MUST be unique within the file
# (the sqlite schema enforces UNIQUE). Missing fields default to empty/today.
#
# The schema is copied from `crates/store/src/schema.rs` — if it drifts this
# script starts failing loudly in CI, which is the intended feedback loop.

from __future__ import annotations

import argparse
import datetime as _dt
import json
import pathlib
import sqlite3
import sys


SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id          INTEGER PRIMARY KEY,
    ts          TEXT NOT NULL,
    host        TEXT NOT NULL,
    incident_id TEXT NOT NULL UNIQUE,
    severity    TEXT NOT NULL,
    detector    TEXT NOT NULL,
    title       TEXT NOT NULL,
    summary     TEXT,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents(ts);
CREATE INDEX IF NOT EXISTS idx_incidents_incident_id ON incidents(incident_id);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);

CREATE TABLE IF NOT EXISTS kv_state (
    namespace   TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       BLOB NOT NULL,
    expires_at  TEXT,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (namespace, key)
);
"""


def _detector_from_id(incident_id: str) -> str:
    parts = incident_id.split(":")
    return ":".join(parts[:2]) if len(parts) >= 2 else incident_id


def _seed_incidents(db_path: pathlib.Path, seed_path: pathlib.Path) -> int:
    if not seed_path.is_file():
        return 0
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(SCHEMA)
        inserted = 0
        with seed_path.open() as f:
            for lineno, raw in enumerate(f, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    inc = json.loads(line)
                except json.JSONDecodeError as e:
                    print(
                        f"scenario_seed: bad JSON at {seed_path}:{lineno}: {e}",
                        file=sys.stderr,
                    )
                    sys.exit(2)

                incident_id = inc.get("incident_id")
                if not incident_id:
                    print(
                        f"scenario_seed: missing incident_id at {seed_path}:{lineno}",
                        file=sys.stderr,
                    )
                    sys.exit(2)

                severity = str(inc.get("severity", "medium")).lower()
                ts = inc.get("ts") or _dt.datetime.now(_dt.timezone.utc).isoformat()
                host = inc.get("host") or "scenario-qa"
                title = inc.get("title") or incident_id
                summary = inc.get("summary") or ""
                detector = _detector_from_id(incident_id)

                cur = conn.execute(
                    """INSERT OR IGNORE INTO incidents
                       (ts, host, incident_id, severity, detector, title, summary, data)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (ts, host, incident_id, severity, detector, title, summary, json.dumps(inc)),
                )
                if cur.rowcount > 0:
                    inserted += 1
        conn.commit()
        return inserted
    finally:
        conn.close()


def _seed_kv(db_path: pathlib.Path, seed_path: pathlib.Path) -> int:
    if not seed_path.is_file():
        return 0
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(SCHEMA)
        now = _dt.datetime.now(_dt.timezone.utc).isoformat()
        inserted = 0
        with seed_path.open() as f:
            for lineno, raw in enumerate(f, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    print(
                        f"scenario_seed: bad JSON at {seed_path}:{lineno}: {e}",
                        file=sys.stderr,
                    )
                    sys.exit(2)

                ns = entry.get("namespace")
                key = entry.get("key")
                value = entry.get("value")
                if not ns or not key or value is None:
                    print(
                        f"scenario_seed: missing namespace/key/value at {seed_path}:{lineno}",
                        file=sys.stderr,
                    )
                    sys.exit(2)

                # Accept either a raw string or a structured value; structured
                # values are stringified so agent code can `serde_json::from_str`.
                if not isinstance(value, str):
                    value = json.dumps(value)

                expires_at = entry.get("expires_at")  # optional, ISO 8601
                conn.execute(
                    """INSERT INTO kv_state (namespace, key, value, expires_at, updated_at)
                       VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT (namespace, key) DO UPDATE SET
                         value = excluded.value,
                         expires_at = excluded.expires_at,
                         updated_at = excluded.updated_at""",
                    (ns, key, value.encode("utf-8"), expires_at, now),
                )
                inserted += 1
        conn.commit()
        return inserted
    finally:
        conn.close()


def _seed_honeypot(data_dir: pathlib.Path, seed_path: pathlib.Path) -> int:
    if not seed_path.is_file():
        return 0
    today = _dt.date.today().isoformat()
    target = data_dir / f"honeypot-sessions-{today}.jsonl"
    lines_written = 0
    with seed_path.open() as src, target.open("a") as dst:
        for raw in src:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Validate it parses; we do not transform.
            try:
                json.loads(line)
            except json.JSONDecodeError as e:
                print(f"scenario_seed: bad honeypot JSON: {e}", file=sys.stderr)
                sys.exit(2)
            dst.write(line + "\n")
            lines_written += 1
    return lines_written


def main() -> int:
    ap = argparse.ArgumentParser(description="Seed a scenario data dir for scenario-qa.")
    ap.add_argument("--scenario-dir", required=True, type=pathlib.Path)
    ap.add_argument("--data-dir", required=True, type=pathlib.Path)
    args = ap.parse_args()

    args.data_dir.mkdir(parents=True, exist_ok=True)
    db_path = args.data_dir / "innerwarden.db"

    incidents_seed = args.scenario_dir / "input" / "seed-incidents.jsonl"
    kv_seed = args.scenario_dir / "input" / "seed-kv.jsonl"
    honeypot_seed = args.scenario_dir / "input" / "seed-honeypot-sessions.jsonl"

    n_inc = _seed_incidents(db_path, incidents_seed)
    n_kv = _seed_kv(db_path, kv_seed)
    n_hp = _seed_honeypot(args.data_dir, honeypot_seed)

    print(f"scenario_seed: incidents={n_inc} kv={n_kv} honeypot_sessions={n_hp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
