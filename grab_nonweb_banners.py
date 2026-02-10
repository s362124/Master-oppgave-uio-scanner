#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
grab_nonweb_banners.py

Passive-ish banner grabbing for non-web services (SSH, FTP, VNC).
Reads a list of IPs (one per line) and writes JSONL + optional SQLite.

Examples:
  python grab_nonweb_banners.py --input data/scans/latest/open_22.txt --service ssh
  python grab_nonweb_banners.py --input data/scans/latest/open_21.txt --service ftp --extended
  python grab_nonweb_banners.py --input data/scans/latest/open_5900.txt --service vnc
"""

import argparse
import asyncio
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

UTC = timezone.utc

SSH_BANNER_RE = re.compile(r"^SSH-\d\.\d-(?P<software>.+)$")
VNC_BANNER_RE = re.compile(r"RFB\s*(?P<version>\d{3}\.\d{3})", re.IGNORECASE)


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


def parse_ssh_software(banner: str) -> str:
    m = SSH_BANNER_RE.match(banner.strip())
    return m.group("software") if m else ""


def parse_vnc_software(banner: str) -> str:
    m = VNC_BANNER_RE.search(banner.strip())
    return f"RFB {m.group('version')}" if m else ""


async def read_line(reader: asyncio.StreamReader, timeout: float, max_bytes: int = 255) -> str:
    try:
        data = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not data:
            data = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
        return data.decode(errors="replace").strip()
    except Exception:
        return ""


async def grab_ssh(ip: str, port: int, timeout: float) -> Tuple[str, str, Optional[str]]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        banner = await read_line(reader, timeout=timeout)
        if not banner:
            try:
                writer.write(b"SSH-2.0-UiO-Scanner\r\n")
                await writer.drain()
                banner = await read_line(reader, timeout=timeout)
            except Exception:
                pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return banner, parse_ssh_software(banner), None
    except Exception as e:
        return "", "", str(e)


async def read_ftp_multiline(reader: asyncio.StreamReader, timeout: float, max_lines: int = 10) -> List[str]:
    lines: List[str] = []
    for _ in range(max_lines):
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        except Exception:
            break
        if not line:
            break
        text = line.decode(errors="replace").rstrip("\r\n")
        lines.append(text)
        # End of multiline reply is a status code + space, not dash.
        if re.match(r"^\d{3} ", text):
            break
    return lines


async def grab_ftp(
    ip: str,
    port: int,
    timeout: float,
    extended: bool,
    login_check: bool,
) -> Tuple[str, str, Optional[str]]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        banner = await read_line(reader, timeout=timeout)
        extra_parts: List[str] = []
        if login_check:
            try:
                writer.write(b"USER anonymous\r\n")
                await writer.drain()
                login_resp = await read_line(reader, timeout=timeout)
                if login_resp:
                    # Fingerprint login mode without attempting password submission.
                    extra_parts.append(f"LOGIN_CHECK_USER_ANON: {login_resp}")
            except Exception:
                pass

        if extended:
            try:
                writer.write(b"SYST\r\n")
                await writer.drain()
                syst = await read_line(reader, timeout=timeout)
                writer.write(b"FEAT\r\n")
                await writer.drain()
                feat_lines = await read_ftp_multiline(reader, timeout=timeout)
                extra_parts.extend([l for l in [syst] if l] + feat_lines)
            except Exception:
                pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        extra = "\n".join([p for p in extra_parts if p]).strip()
        return banner, extra, None
    except Exception as e:
        return "", "", str(e)


async def grab_vnc(ip: str, port: int, timeout: float) -> Tuple[str, str, Optional[str]]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        raw = await asyncio.wait_for(reader.read(64), timeout=timeout)
        banner = raw.decode(errors="replace").strip()
        if "\n" in banner:
            banner = banner.splitlines()[0].strip()
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return banner, parse_vnc_software(banner), None
    except Exception as e:
        return "", "", str(e)


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


async def result_writer(
    queue: asyncio.Queue,
    output_path: Path,
    db_conn: Optional[sqlite3.Connection],
    run_id: str,
) -> None:
    batch: List[Tuple[str, str, str, int, str, str, str, str, str]] = []
    with output_path.open("w", encoding="utf-8") as fh:
        while True:
            item = await queue.get()
            if item is None:
                break
            fh.write(json.dumps(item, ensure_ascii=True) + "\n")
            if db_conn:
                batch.append(
                    (
                        run_id,
                        item.get("ts", ""),
                        item.get("ip", ""),
                        int(item.get("port", 0)),
                        item.get("service", ""),
                        item.get("banner", ""),
                        item.get("software", ""),
                        item.get("extra", ""),
                        item.get("error", ""),
                    )
                )
                if len(batch) >= 500:
                    db_conn.executemany(
                        """
                        INSERT INTO banners
                        (run_id, ts, ip, port, service, banner, software, extra, error)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        batch,
                    )
                    db_conn.commit()
                    batch.clear()
    if db_conn and batch:
        db_conn.executemany(
            """
            INSERT INTO banners
            (run_id, ts, ip, port, service, banner, software, extra, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            batch,
        )
        db_conn.commit()


async def worker(
    ip_queue: asyncio.Queue,
    result_queue: asyncio.Queue,
    service: str,
    port: int,
    timeout: float,
    extended: bool,
    ftp_login_check: bool,
) -> None:
    while True:
        ip = await ip_queue.get()
        if ip is None:
            ip_queue.task_done()
            break
        if service == "ssh":
            banner, software, error = await grab_ssh(ip, port, timeout)
            extra = ""
        elif service == "ftp":
            banner, extra, error = await grab_ftp(ip, port, timeout, extended, ftp_login_check)
            software = ""
        else:
            banner, software, error = await grab_vnc(ip, port, timeout)
            extra = ""

        await result_queue.put(
            {
                "ts": now_utc(),
                "ip": ip,
                "port": port,
                "service": service,
                "banner": banner,
                "software": software,
                "extra": extra,
                "error": error or "",
            }
        )
        ip_queue.task_done()


async def run_async(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] Input file not found: {input_path}")
        return 2

    service = args.service
    default_ports = {"ssh": 22, "ftp": 21, "vnc": 5900}
    port = args.port or default_ports[service]

    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.with_name(f"banners_{service}.jsonl")

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
            (run_id, service, port, str(input_path), str(output_path), now_utc(), "", ""),
        )
        db_conn.commit()

    ip_queue: asyncio.Queue = asyncio.Queue(maxsize=args.concurrency * 2)
    result_queue: asyncio.Queue = asyncio.Queue(maxsize=args.concurrency * 2)

    writer_task = asyncio.create_task(result_writer(result_queue, output_path, db_conn, run_id))

    workers = [
        asyncio.create_task(
            worker(
                ip_queue,
                result_queue,
                service,
                port,
                args.timeout,
                args.extended,
                args.ftp_login_check,
            )
        )
        for _ in range(args.concurrency)
    ]

    # Producer: feed IPs
    for ip in iter_ips(input_path, limit=args.limit):
        await ip_queue.put(ip)

    # Stop workers
    for _ in range(args.concurrency):
        await ip_queue.put(None)

    await ip_queue.join()
    for w in workers:
        await w

    await result_queue.put(None)
    await writer_task

    if db_conn:
        db_conn.execute(
            "UPDATE runs SET finished_at = ? WHERE run_id = ?",
            (now_utc(), run_id),
        )
        db_conn.commit()
        db_conn.close()

    print(f"[OK] Wrote results: {output_path}")
    if args.sqlite:
        print(f"[OK] SQLite updated: {args.sqlite}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Grab SSH/FTP/VNC banners from an IP list")
    ap.add_argument("--input", required=True, help="Path to IP list (one per line)")
    ap.add_argument("--service", required=True, choices=["ssh", "ftp", "vnc"])
    ap.add_argument("--port", type=int, default=0, help="Override port (default: 22 for ssh, 21 for ftp, 5900 for vnc)")
    ap.add_argument("--output", default="", help="Output JSONL path (default: banners_<service>.jsonl beside input)")
    ap.add_argument("--sqlite", default="", help="Optional SQLite DB to store results")
    ap.add_argument("--concurrency", type=int, default=200)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--limit", type=int, default=0, help="Limit number of IPs (for testing)")
    ap.add_argument("--extended", action="store_true", help="FTP: send SYST/FEAT after greeting")
    ap.add_argument(
        "--ftp-login-check",
        action="store_true",
        help="FTP: send USER anonymous and record first response (no password attempt).",
    )
    args = ap.parse_args()

    return asyncio.run(run_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
