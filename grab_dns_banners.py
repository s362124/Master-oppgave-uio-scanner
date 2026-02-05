#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
grab_dns_banners.py

DNS probing for port 53 (UDP). Reads a list of IPs and stores results
in JSONL and optional SQLite (same schema as other banner grabbers).

Notes:
- Default query is a simple A query for example.com with RD=0.
- Optional version.bind CHAOS/TXT query can be enabled for version hints.
"""

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.rdataclass
    import dns.flags
    import dns.rcode
except ImportError:
    print("This script requires dnspython. Install with:")
    print("  pip install dnspython")
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


def dns_probe(ip: str, qname: str, rd: bool, timeout: float, version_bind: bool) -> dict:
    ts = now_utc()
    port = 53
    service = "dns"
    error = ""
    version = ""
    banner = ""
    extra = {}
    try:
        msg = dns.message.make_query(qname, dns.rdatatype.A, dns.rdataclass.IN)
        if rd:
            msg.flags |= dns.flags.RD
        else:
            msg.flags &= ~dns.flags.RD
        resp = dns.query.udp(msg, ip, timeout=timeout)
        rcode = dns.rcode.to_text(resp.rcode())
        ra = bool(resp.flags & dns.flags.RA)
        aa = bool(resp.flags & dns.flags.AA)
        size = len(resp.to_wire())
        banner = f"rcode={rcode} ra={int(ra)} aa={int(aa)} size={size}"
        extra = {"rcode": rcode, "ra": ra, "aa": aa, "size": size, "qname": qname, "rd": rd}
    except Exception as e:
        error = str(e)

    if version_bind:
        try:
            vmsg = dns.message.make_query("version.bind.", dns.rdatatype.TXT, dns.rdataclass.CH)
            vmsg.flags &= ~dns.flags.RD
            vresp = dns.query.udp(vmsg, ip, timeout=timeout)
            for rrset in vresp.answer:
                if rrset.rdtype == dns.rdatatype.TXT:
                    for rdata in rrset:
                        # rdata.strings is a tuple of bytes
                        if getattr(rdata, "strings", None):
                            version = b"".join(rdata.strings).decode(errors="replace")
                            break
                if version:
                    break
        except Exception:
            pass

    return {
        "ts": ts,
        "ip": ip,
        "port": port,
        "service": service,
        "banner": banner,
        "software": version,
        "extra": json.dumps(extra, ensure_ascii=True),
        "error": error,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Grab DNS responses from an IP list (UDP/53)")
    ap.add_argument("--input", required=True, help="Path to IP list (one per line)")
    ap.add_argument("--output", default="", help="Output JSONL path (default: banners_dns.jsonl beside input)")
    ap.add_argument("--sqlite", default="", help="Optional SQLite DB to store results")
    ap.add_argument("--qname", default="example.com", help="DNS qname to query (default: example.com)")
    ap.add_argument("--rd", action="store_true", help="Set RD flag (recursion desired)")
    ap.add_argument("--version-bind", action="store_true", help="Query version.bind (CHAOS/TXT) for version hints")
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--concurrency", type=int, default=200)
    ap.add_argument("--limit", type=int, default=0, help="Limit number of IPs (for testing)")
    args = ap.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] Input file not found: {input_path}")
        return 2

    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.with_name("banners_dns.jsonl")

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
            (run_id, "dns", 53, str(input_path), str(output_path), now_utc(), "", ""),
        )
        db_conn.commit()

    results = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = [
            ex.submit(dns_probe, ip, args.qname, args.rd, args.timeout, args.version_bind)
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
                    int(item.get("port", 53)),
                    item.get("service", "dns"),
                    item.get("banner", ""),
                    item.get("software", ""),
                    item.get("extra", ""),
                    item.get("error", ""),
                )
                for item in results
            ],
        )
        db_conn.execute(
            "UPDATE runs SET finished_at = ? WHERE run_id = ?",
            (now_utc(), run_id),
        )
        db_conn.commit()
        db_conn.close()

    print(f"[✓] Wrote results: {output_path}")
    if args.sqlite:
        print(f"[✓] SQLite updated: {args.sqlite}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
