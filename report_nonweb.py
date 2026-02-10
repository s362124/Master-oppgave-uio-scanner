#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
report_nonweb.py

Generate a simple human-readable report from the nonweb_banners.sqlite DB
so you don't need to run raw SQL commands.
"""

import argparse
import json
import re
import sqlite3
from pathlib import Path
from typing import List, Tuple


def fetch_all(conn: sqlite3.Connection, query: str, params: tuple = ()) -> List[Tuple]:
    return list(conn.execute(query, params))


def format_section(title: str, rows: List[Tuple], col_names: List[str]) -> str:
    if not rows:
        return f"{title}\n  (no data)\n"
    widths = [len(c) for c in col_names]
    for row in rows:
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(str(val)))
    header = "  " + "  ".join([col_names[i].ljust(widths[i]) for i in range(len(col_names))])
    sep = "  " + "  ".join(["-" * widths[i] for i in range(len(col_names))])
    lines = [f"{title}", header, sep]
    for row in rows:
        line = "  " + "  ".join([str(row[i]).ljust(widths[i]) for i in range(len(col_names))])
        lines.append(line)
    return "\n".join(lines) + "\n"


def count_open_totals(scan_dir: Path) -> List[Tuple[int, int, str]]:
    """
    Count exact unique open IP totals per port from open_<port>.txt files.
    """
    rows: List[Tuple[int, int, str]] = []
    for path in scan_dir.glob("open_*.txt"):
        m = re.match(r"open_(\d+)\.txt$", path.name)
        if not m:
            continue
        port = int(m.group(1))
        ips = set()
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                ip = line.strip()
                if ip and not ip.startswith("#"):
                    ips.add(ip)
        rows.append((port, len(ips), path.name))
    rows.sort(key=lambda x: x[0])
    return rows


def classify_ssh(text: str) -> Tuple[str, str, str]:
    """
    Heuristic classification for SSH banners.
    Returns (status, product, version) where status in: ok/legacy/outdated/unknown.
    """
    if not text:
        return ("unknown", "", "")
    m = re.search(r"OpenSSH[_-]([0-9]+(?:\.[0-9]+)*)", text)
    if m:
        ver = m.group(1)
        try:
            major = int(ver.split(".")[0])
        except Exception:
            return ("unknown", "OpenSSH", ver)
        if major <= 6:
            return ("outdated", "OpenSSH", ver)
        if major == 7:
            return ("legacy", "OpenSSH", ver)
        return ("ok", "OpenSSH", ver)
    m = re.search(r"dropbear[_-]?([0-9]{4}(?:\.[0-9]+)?)", text, re.IGNORECASE)
    if m:
        ver = m.group(1)
        try:
            year = int(ver.split(".")[0])
        except Exception:
            return ("unknown", "dropbear", ver)
        if year < 2020:
            return ("outdated", "dropbear", ver)
        if year < 2023:
            return ("legacy", "dropbear", ver)
        return ("ok", "dropbear", ver)
    return ("unknown", "", "")


def classify_ftp(text: str) -> Tuple[str, str, str]:
    """
    Heuristic classification for FTP banners.
    Returns (status, product, version) where status in: ok/legacy/outdated/unknown.
    """
    if not text:
        return ("unknown", "", "")
    m = re.search(r"vsFTPd\s+([0-9]+(?:\.[0-9]+)*)", text, re.IGNORECASE)
    if m:
        ver = m.group(1)
        try:
            major = int(ver.split(".")[0])
        except Exception:
            return ("unknown", "vsFTPd", ver)
        if major < 3:
            return ("legacy", "vsFTPd", ver)
        return ("ok", "vsFTPd", ver)
    m = re.search(r"FileZilla Server\s+([0-9]+(?:\.[0-9]+)*)", text, re.IGNORECASE)
    if m:
        ver = m.group(1)
        if ver.startswith("0.9"):
            return ("legacy", "FileZilla Server", ver)
        return ("ok", "FileZilla Server", ver)
    m = re.search(r"ProFTPD[^0-9]*([0-9]+(?:\.[0-9]+)+)", text, re.IGNORECASE)
    if m:
        ver = m.group(1)
        return ("unknown", "ProFTPD", ver)
    if re.search(r"Pure-FTPd", text, re.IGNORECASE):
        return ("unknown", "Pure-FTPd", "")
    if re.search(r"Microsoft FTP Service", text, re.IGNORECASE):
        return ("unknown", "Microsoft FTP Service", "")
    return ("unknown", "", "")


def classify_dns(text: str) -> Tuple[str, str, str]:
    """
    Heuristic classification for DNS version strings (if available).
    Currently returns unknown to avoid over-claiming.
    """
    if not text:
        return ("unknown", "", "")
    return ("unknown", "dns", text)


def classify_vnc(text: str) -> Tuple[str, str, str]:
    """
    Conservative VNC classification: keep unknown unless policy/rules are defined.
    """
    if not text:
        return ("unknown", "", "")
    m = re.search(r"RFB\s*([0-9]{3}\.[0-9]{3})", text, re.IGNORECASE)
    if m:
        return ("unknown", "RFB", m.group(1))
    return ("unknown", "vnc", "")


def parse_ftp_login_hint(extra: str) -> Tuple[str, str]:
    """
    Parse optional FTP login-check marker from extra field.
    Returns (category, response_line).
    """
    if not extra:
        return ("not_tested", "")
    for line in extra.splitlines():
        line = line.strip()
        if line.startswith("LOGIN_CHECK_USER_ANON:"):
            resp = line.split(":", 1)[1].strip()
            m = re.match(r"^(\d{3})", resp)
            code = m.group(1) if m else ""
            if code == "230":
                return ("anonymous_allowed", resp)
            if code == "331":
                return ("password_required", resp)
            if code == "332":
                return ("account_required", resp)
            if code == "530":
                return ("login_not_allowed", resp)
            if code:
                return (f"code_{code}", resp)
            return ("response_unparsed", resp)
    return ("not_tested", "")


def main() -> int:
    ap = argparse.ArgumentParser(description="Summarize non-web banner scans from SQLite")
    ap.add_argument(
        "--sqlite",
        default="data/scans/latest/nonweb_banners.sqlite",
        help="Path to SQLite DB (default: data/scans/latest/nonweb_banners.sqlite)",
    )
    ap.add_argument("--limit", type=int, default=10, help="Top-N limit (default: 10)")
    ap.add_argument("--out", default="", help="Optional output file (text). If omitted, writes beside DB.")
    args = ap.parse_args()

    db_path = Path(args.sqlite)
    if not db_path.exists():
        print(f"[!] SQLite file not found: {db_path}")
        return 2

    conn = sqlite3.connect(str(db_path))
    open_totals = count_open_totals(db_path.parent)

    total = fetch_all(conn, "select count(*) from banners")[0][0]
    by_service = fetch_all(
        conn,
        "select service, count(*) as n from banners group by service order by n desc",
    )
    empty_banner = fetch_all(
        conn,
        "select service, count(*) as n from banners where banner = '' group by service order by n desc",
    )
    ssh_top = fetch_all(
        conn,
        "select software, count(*) as n from banners "
        "where service = 'ssh' and software != '' "
        "group by software order by n desc limit ?",
        (args.limit,),
    )
    ftp_top = fetch_all(
        conn,
        "select banner, count(*) as n from banners "
        "where service = 'ftp' and banner != '' "
        "group by banner order by n desc limit ?",
        (args.limit,),
    )
    dns_top = fetch_all(
        conn,
        "select software, count(*) as n from banners "
        "where service = 'dns' and software != '' "
        "group by software order by n desc limit ?",
        (args.limit,),
    )
    vnc_top = fetch_all(
        conn,
        "select banner, count(*) as n from banners "
        "where service = 'vnc' and banner != '' "
        "group by banner order by n desc limit ?",
        (args.limit,),
    )
    ssh_auth_top = fetch_all(
        conn,
        "select software, count(*) as n from banners "
        "where service = 'ssh_auth' and software != '' "
        "group by software order by n desc limit ?",
        (args.limit,),
    )
    # Risk classification (heuristic)
    risk_counts = {}
    examples = []
    rows = fetch_all(conn, "select ip, service, banner, software, extra from banners")

    ftp_login_counts = {}
    ftp_login_samples = []
    dns_behavior_counts = {}
    ssh_auth_method_counts = {}

    for ip, service, banner, software, extra in rows:
        if service == "ssh":
            text = software or ""
        elif service == "dns":
            text = software or ""
        elif service == "vnc":
            text = banner or software or ""
        elif service == "ssh_auth":
            text = software or banner or ""
        else:
            text = banner or ""
        if service == "ssh":
            status, product, version = classify_ssh(text)
        elif service == "ftp":
            status, product, version = classify_ftp(text)
        elif service == "dns":
            status, product, version = classify_dns(text)
        elif service == "vnc":
            status, product, version = classify_vnc(text)
        elif service == "ssh_auth":
            status, product, version = ("unknown", "ssh_auth", "")
        else:
            status, product, version = ("unknown", "", "")

        risk_counts.setdefault(service, {})
        risk_counts[service][status] = risk_counts[service].get(status, 0) + 1

        if status in ("outdated", "legacy") and len(examples) < args.limit:
            examples.append((ip, service, product, version, status))

        if service == "ftp":
            category, resp = parse_ftp_login_hint(extra or "")
            ftp_login_counts[category] = ftp_login_counts.get(category, 0) + 1
            if resp and len(ftp_login_samples) < args.limit:
                ftp_login_samples.append((ip, category, resp))

        if service == "dns":
            try:
                extra_obj = json.loads(extra) if extra else {}
            except Exception:
                extra_obj = {}
            rcode = str(extra_obj.get("rcode", "unknown"))
            ra = str(int(bool(extra_obj.get("ra", False)))) if "ra" in extra_obj else "na"
            key = f"rcode={rcode},ra={ra}"
            dns_behavior_counts[key] = dns_behavior_counts.get(key, 0) + 1

        if service == "ssh_auth":
            try:
                extra_obj = json.loads(extra) if extra else {}
            except Exception:
                extra_obj = {}
            methods = extra_obj.get("allowed_methods", [])
            if isinstance(methods, list):
                methods_label = ",".join(sorted(str(m) for m in methods)) if methods else "(none-listed)"
            else:
                methods_label = "(invalid)"
            password_allowed = bool(extra_obj.get("password_allowed", False))
            publickey_allowed = bool(extra_obj.get("publickey_allowed", False))
            key = (methods_label, password_allowed, publickey_allowed)
            ssh_auth_method_counts[key] = ssh_auth_method_counts.get(key, 0) + 1

    conn.close()

    parts = []
    parts.append(f"Non-web banner report\nTotal records: {total}\n")
    parts.append(
        format_section(
            "Exact open totals by port (from scan open_*.txt files)",
            [(str(port), count, fname) for port, count, fname in open_totals],
            ["port", "open", "source_file"],
        )
    )
    parts.append(format_section("Counts by service", by_service, ["service", "count"]))
    parts.append(format_section("Empty banners by service", empty_banner, ["service", "count"]))
    parts.append(format_section("Top SSH software strings", ssh_top, ["software", "count"]))
    parts.append(format_section("Top FTP banner strings", ftp_top, ["banner", "count"]))
    parts.append(format_section("Top DNS version strings", dns_top, ["software", "count"]))
    parts.append(format_section("Top VNC banner strings", vnc_top, ["banner", "count"]))
    parts.append(format_section("Top SSH auth-probe software strings", ssh_auth_top, ["software", "count"]))

    ftp_login_rows = [(k, v) for k, v in sorted(ftp_login_counts.items(), key=lambda x: (-x[1], x[0]))]
    parts.append(format_section("FTP login-establishment fingerprint", ftp_login_rows, ["category", "count"]))
    parts.append(format_section("FTP login-check sample responses", ftp_login_samples, ["ip", "category", "response"]))

    dns_behavior_rows = [(k, v) for k, v in sorted(dns_behavior_counts.items(), key=lambda x: (-x[1], x[0]))]
    parts.append(format_section("DNS behavior fingerprint", dns_behavior_rows, ["signal", "count"]))

    ssh_auth_rows = [
        (methods, int(password_allowed), int(publickey_allowed), count)
        for (methods, password_allowed, publickey_allowed), count in sorted(
            ssh_auth_method_counts.items(), key=lambda x: (-x[1], x[0][0])
        )
    ]
    parts.append(
        format_section(
            "SSH auth-method fingerprint (legal-gated)",
            ssh_auth_rows,
            ["allowed_methods", "password_allowed", "publickey_allowed", "count"],
        )
    )
    # Risk summary
    risk_rows = []
    for service in sorted(risk_counts.keys()):
        for status in ("outdated", "legacy", "ok", "unknown"):
            if status in risk_counts[service]:
                risk_rows.append((service, status, risk_counts[service][status]))
    parts.append(format_section("Risk classification (heuristic)", risk_rows, ["service", "status", "count"]))
    parts.append(format_section("Legacy/Outdated examples (sample)", examples, ["ip", "service", "product", "version", "status"]))
    parts.append(
        "Notes:\n"
        "- Risk classification is heuristic based on banner strings (no exploitation).\n"
        "- Some sections may show '(no data)' if the corresponding probe was disabled or returned no usable response.\n"
        "- Update thresholds/rules in code if your policy changes.\n"
    )
    report = "\n".join(parts).rstrip() + "\n"

    out_path = Path(args.out) if args.out else db_path.with_name("nonweb_report.txt")
    out_path.write_text(report, encoding="utf-8")
    print(f"[OK] Wrote report: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
