#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_ssh_auth_methods.py

Optional SSH auth-method fingerprinting using userauth "none".
This checks which auth methods a server advertises (e.g., password/publickey)
without trying credentials.

IMPORTANT:
- This is active authentication probing.
- Keep disabled by default.
- Run only with explicit legal/organizational approval.

Example:
  python probe_ssh_auth_methods.py \
    --input data/scans/latest/open_22.txt \
    --sqlite data/scans/latest/nonweb_banners.sqlite \
    --confirm-legal
"""

import argparse
import json
import socket
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List

try:
    import paramiko
except ImportError:
    print("This script requires paramiko. Install with:")
    print("  pip install paramiko")
    raise SystemExit(1)

UTC = timezone.utc


def now_utc() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def iter_ips(path: Path, limit: int = 0) -> Iterable[str]:
    count = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            yield s
            count += 1
            if limit and count >= limit:
                break


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            service TEXT,
            port INTEGER,
            input_file TEXT,
            output_file TEXT,
            started_at TEXT,
            finished_at TEXT,
            notes TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS banners (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT,
            ts TEXT,
            ip TEXT,
            port INTEGER,
            service TEXT,
            banner TEXT,
            software TEXT,
            extra TEXT,
            error TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_banners_run_id ON banners(run_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_banners_ip_port ON banners(ip, port)")


def probe_one(ip: str, port: int, username: str, timeout: float) -> Dict[str, str]:
    ts = now_utc()
    service = "ssh_auth"
    banner = ""
    software = ""
    error = ""
    methods: List[str] = []
    state = "unknown"

    sock = None
    transport = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=timeout)

        banner = (transport.remote_version or "").strip()
        if banner.startswith("SSH-2.0-"):
            software = banner[len("SSH-2.0-") :]
        else:
            software = banner

        try:
            transport.auth_none(username)
            # Very unusual: server accepted auth-none.
            methods = ["none"]
            state = "none_accepted"
        except paramiko.BadAuthenticationType as e:
            methods = sorted(set(e.allowed_types or []))
            state = "none_rejected_methods_advertised"
        except paramiko.AuthenticationException:
            methods = []
            state = "authentication_rejected_no_method_list"
        except Exception as e:
            state = "auth_probe_error"
            error = f"auth_probe_error: {e}"
    except Exception as e:
        state = "connect_error"
        error = str(e)
    finally:
        try:
            if transport is not None:
                transport.close()
        except Exception:
            pass
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass

    password_allowed = ("password" in methods) or ("keyboard-interactive" in methods)
    publickey_allowed = ("publickey" in methods)
    extra = {
        "probe": "ssh_userauth_none",
        "username_used": username,
        "state": state,
        "allowed_methods": methods,
        "password_allowed": bool(password_allowed),
        "publickey_allowed": bool(publickey_allowed),
    }

    return {
        "ts": ts,
        "ip": ip,
        "port": port,
        "service": service,
        "banner": banner,
        "software": software,
        "extra": json.dumps(extra, ensure_ascii=True),
        "error": error,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Optional SSH auth-method probe using userauth none (legal approval required)."
    )
    ap.add_argument("--input", required=True, help="Path to open SSH IP list (one per line)")
    ap.add_argument("--output", default="", help="Output JSONL path (default: ssh_auth_methods.jsonl beside input)")
    ap.add_argument("--sqlite", default="", help="Optional SQLite DB to store results")
    ap.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    ap.add_argument("--username", default="probe", help="Username for auth-none probe (default: probe)")
    ap.add_argument("--timeout", type=float, default=4.0)
    ap.add_argument("--concurrency", type=int, default=100)
    ap.add_argument("--limit", type=int, default=0, help="Limit number of IPs (testing)")
    ap.add_argument(
        "--confirm-legal",
        action="store_true",
        help="Required acknowledgment flag before running active auth-method probe.",
    )
    args = ap.parse_args()

    if not args.confirm_legal:
        print("[!] Refusing to run without --confirm-legal.")
        print("    This probe is active authentication fingerprinting.")
        return 2

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] Input file not found: {input_path}")
        return 2

    output_path = Path(args.output) if args.output else input_path.with_name("ssh_auth_methods.jsonl")
    run_id = now_utc().replace(":", "-")

    db_conn = None
    if args.sqlite:
        db_conn = sqlite3.connect(args.sqlite)
        init_db(db_conn)
        db_conn.execute(
            """
            INSERT OR REPLACE INTO runs
            (run_id, service, port, input_file, output_file, started_at, finished_at, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                "ssh_auth",
                args.port,
                str(input_path),
                str(output_path),
                now_utc(),
                "",
                "active auth-none probe; requires legal approval",
            ),
        )
        db_conn.commit()

    results: List[Dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = [
            ex.submit(probe_one, ip, args.port, args.username, args.timeout)
            for ip in iter_ips(input_path, limit=args.limit)
        ]
        for fut in as_completed(futures):
            results.append(fut.result())

    with output_path.open("w", encoding="utf-8") as fh:
        for item in results:
            fh.write(json.dumps(item, ensure_ascii=True) + "\n")

    if db_conn:
        db_conn.executemany(
            """
            INSERT INTO banners
            (run_id, ts, ip, port, service, banner, software, extra, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id,
                    item.get("ts", ""),
                    item.get("ip", ""),
                    int(item.get("port", args.port)),
                    item.get("service", "ssh_auth"),
                    item.get("banner", ""),
                    item.get("software", ""),
                    item.get("extra", ""),
                    item.get("error", ""),
                )
                for item in results
            ],
        )
        db_conn.execute("UPDATE runs SET finished_at = ? WHERE run_id = ?", (now_utc(), run_id))
        db_conn.commit()
        db_conn.close()

    print(f"[OK] Wrote results: {output_path}")
    if args.sqlite:
        print(f"[OK] SQLite updated: {args.sqlite}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

