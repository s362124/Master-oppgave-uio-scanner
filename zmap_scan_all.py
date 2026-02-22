#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zmap_scan_all.py — Norway web surface (baseline)
Effektiv og korrekt oppsummering (open/closed/unknown).
"""

import argparse
import csv
import datetime as dt
import ipaddress
import shutil
import subprocess
import sys
import time
import json
import platform
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------- blacklist -----------
DEFAULT_BLACKLIST_TEXT = """
0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.2.0/24
192.168.0.0/16
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
224.0.0.0/4
240.0.0.0/4
255.255.255.255/32
"""

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def write_symlink_latest(out_root: Path, run_dir: Path):
    """Lag/oppdater 'latest' peker i out_root -> denne run_dir (bruk run_dir.name)."""
    latest = out_root / "latest"
    try:
        if latest.exists() or latest.is_symlink():
            latest.unlink()
        latest.symlink_to(run_dir.name)
    except Exception:
        with (out_root / "LATEST.txt").open("w", encoding="utf-8") as fh:
            fh.write(str(run_dir.resolve()))

def ensure_blacklist(path_from_cli: str) -> str:
    if path_from_cli and Path(path_from_cli).exists():
        return path_from_cli
    sys_blk = Path("/etc/zmap/blacklist.conf")
    if sys_blk.exists():
        return str(sys_blk)
    local_blk = Path("data/zmap_blacklist.conf")
    if not local_blk.exists():
        ensure_dir(local_blk.parent)
        local_blk.write_text(DEFAULT_BLACKLIST_TEXT, encoding="utf-8")
    return str(local_blk)

CIDR_FILE_DEFAULT = Path("data/norway_ipv4_whitelist.txt")
OUT_ROOT = Path("data/scans")
AGG_FILE_NAME = "aggregate.csv"

ZMAP_CANDIDATES = [
    shutil.which("zmap"),
    "/usr/local/sbin/zmap",
    "/usr/sbin/zmap",
    "/opt/homebrew/sbin/zmap",
]

def find_zmap() -> Optional[str]:
    for p in ZMAP_CANDIDATES:
        if p and Path(p).exists():
            return p
    return None

def detect_iface() -> str:
    """
    Best-effort default interface detection (Linux/WSL).
    Returns interface name or empty string if not found.
    """
    cmds = [
        ["ip", "route", "get", "1.1.1.1"],
        ["ip", "route", "get", "8.8.8.8"],
        ["ip", "route"],
    ]
    for cmd in cmds:
        try:
            cp = subprocess.run(cmd, capture_output=True, text=True)
            if cp.returncode != 0:
                continue
            out = (cp.stdout or "") + "\n" + (cp.stderr or "")
            m = re.search(r"\bdev\s+(\S+)", out)
            if m:
                return m.group(1)
        except Exception:
            continue
    return ""

def build_dns_query_hex(qname: str, rd: bool = False) -> str:
    """
    Build a minimal DNS A query for qname.
    Returns hex-encoded bytes suitable for ZMap UDP probe-args.
    """
    name = qname.strip().strip(".")
    if not name:
        name = "example.com"
    labels = name.split(".")
    try:
        qname_bytes = b"".join(
            bytes([len(label)]) + label.encode("ascii") for label in labels if label
        ) + b"\x00"
    except Exception:
        # Fallback to example.com if encoding fails
        qname_bytes = b"\x07example\x03com\x00"
    # Header: ID=0xCAFE, flags=RD? QDCOUNT=1, AN/NS/AR=0
    flags = 0x0100 if rd else 0x0000
    header = bytes([
        0xCA, 0xFE,
        (flags >> 8) & 0xFF, flags & 0xFF,
        0x00, 0x01,  # QDCOUNT
        0x00, 0x00,  # ANCOUNT
        0x00, 0x00,  # NSCOUNT
        0x00, 0x00,  # ARCOUNT
    ])
    qtype_qclass = b"\x00\x01\x00\x01"  # QTYPE=A, QCLASS=IN
    payload = header + qname_bytes + qtype_qclass
    return payload.hex()

def open_run_dir(run_dir: Path) -> None:
    """
    Best-effort: open the run directory in a file explorer.
    Works on Windows, macOS, Linux, and WSL.
    """
    try:
        if platform.system().lower().startswith("win"):
            subprocess.run(["explorer", str(run_dir.resolve())], check=False)
            return
        # WSL: use explorer.exe with Windows path if available
        if "microsoft" in platform.release().lower():
            try:
                cp = subprocess.run(
                    ["wslpath", "-w", str(run_dir.resolve())],
                    capture_output=True,
                    text=True,
                )
                win_path = (cp.stdout or "").strip()
                if win_path:
                    subprocess.run(["explorer.exe", win_path], check=False)
                    return
            except Exception:
                pass
        if shutil.which("xdg-open"):
            subprocess.run(["xdg-open", str(run_dir.resolve())], check=False)
            return
        if shutil.which("open"):
            subprocess.run(["open", str(run_dir.resolve())], check=False)
    except Exception:
        pass

def get_zmap_version(zmap_path: str) -> str:
    try:
        cp = subprocess.run([zmap_path, "--version"], capture_output=True, text=True)
        out = (cp.stdout or cp.stderr or "").strip()
        return out.splitlines()[0] if out else "unknown"
    except Exception:
        return "unknown"

def load_cidrs(path: Path) -> List[str]:
    lines = []
    with path.open() as f:
        for l in f:
            l = l.strip()
            if l and not l.startswith("#"):
                lines.append(l)
    return lines

def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def parse_zmap_csv_line(line: str) -> Dict[str, Optional[str]]:
    # forventet: saddr,success,ttl
    parts = [p.strip() for p in line.strip().split(",")]
    if not parts:
        return {}
    # header?
    if parts[0] in ("saddr", "ip", "saddr "):
        return {}
    if len(parts[0].split(".")) != 4:
        return {}
    d = {"ip": parts[0], "success": None, "ttl": None}
    if len(parts) > 1: d["success"] = parts[1]
    if len(parts) > 2: d["ttl"] = parts[2]
    return d


def count_ips_in_cidrs(cidrs: List[str]) -> int:
    total = 0
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                total += int(net.num_addresses)
        except Exception:
            continue
    return total


# ---- CIDR/IP helper functions ----

def build_cidr_networks(cidrs: List[str]) -> List[ipaddress.IPv4Network]:
    nets: List[ipaddress.IPv4Network] = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                nets.append(net)
        except Exception:
            continue
    # Most specific first (in case of overlaps)
    nets.sort(key=lambda n: (-n.prefixlen, int(n.network_address)))
    return nets


def find_cidr_for_ip(ip: str, nets: List[ipaddress.IPv4Network]) -> str:
    try:
        addr = ipaddress.IPv4Address(ip)
    except Exception:
        return ""
    for net in nets:
        if addr in net:
            return str(net)
    return ""

def parse_bandwidth_mbps(bw: str) -> float:
    """
    Godtar f.eks: 10M, 100M, 1G.
    Returnerer Mbps.
    """
    s = bw.strip().upper()
    if s.endswith("G"):
        return float(s[:-1]) * 1000.0
    if s.endswith("M"):
        return float(s[:-1])
    # fallback: anta Mbps hvis bare tall
    return float(s)

def estimate_runtime_seconds(total_ips: int, bandwidth_mbps: float, ports_count: int,
                             bytes_per_probe: int = 120) -> float:
    if total_ips <= 0 or bandwidth_mbps <= 0 or ports_count <= 0:
        return 0.0
    bits_per_probe = bytes_per_probe * 8
    total_bits = total_ips * bits_per_probe * ports_count
    return total_bits / (bandwidth_mbps * 1e6)

def estimate_runtime(total_ips: int, bandwidth_mbps: float, ports_count: int,
                     bytes_per_probe: int = 120) -> float:
    seconds = estimate_runtime_seconds(total_ips, bandwidth_mbps, ports_count, bytes_per_probe=bytes_per_probe)
    if seconds <= 0:
        return 0.0
    minutes = seconds / 60
    print(f"[i] Estimated duration: ~{seconds:.1f}s ({minutes:.1f} min) "
          f"for {total_ips:,} IPs at {bandwidth_mbps:.1f} Mbit/s over {ports_count} ports")
    return seconds

def read_text_tail(path: Path, max_chars: int = 2000) -> str:
    if not path.exists():
        return ""
    try:
        txt = path.read_text(encoding="utf-8", errors="replace")
        return txt[-max_chars:].strip()
    except Exception:
        return ""

def write_open_lists(run_dir: Path, open_by_port: dict) -> None:
    """Write helper lists for downstream validation (httpx/zgrab)."""
    # Always write per-port open lists (useful for non-web services).
    for port, ips in open_by_port.items():
        ip_list = sorted(ips)
        (run_dir / f"open_{port}.txt").write_text(
            "\n".join(ip_list) + ("\n" if ip_list else ""), encoding="utf-8"
        )

    # Only write 80/443 convenience lists if both ports were scanned.
    has80 = "80" in open_by_port
    has443 = "443" in open_by_port

    if has80 and has443:
        open80 = sorted(open_by_port.get("80", set()))
        open443 = sorted(open_by_port.get("443", set()))
        both = sorted(set(open80).intersection(open443))
        any_open = sorted(set(open80).union(open443))

        (run_dir / "open_both_80_443.txt").write_text(
            "\n".join(both) + ("\n" if both else ""), encoding="utf-8"
        )
        (run_dir / "open_any_80_443.txt").write_text(
            "\n".join(any_open) + ("\n" if any_open else ""), encoding="utf-8"
        )
    else:
        # Clean up legacy web-only lists if they exist.
        for fname in ("open_both_80_443.txt", "open_any_80_443.txt"):
            fpath = run_dir / fname
            if fpath.exists():
                try:
                    fpath.unlink()
                except Exception:
                    pass
    # Remove per-port files that do not apply to this run (if left from earlier runs).
    if not has80:
        fpath = run_dir / "open_80.txt"
        if fpath.exists():
            try:
                fpath.unlink()
            except Exception:
                pass
    if not has443:
        fpath = run_dir / "open_443.txt"
        if fpath.exists():
            try:
                fpath.unlink()
            except Exception:
                pass


def count_targets(path: Path) -> int:
    count = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.strip()
            if s and not s.startswith("#"):
                count += 1
    return count


def run_postprocess_pipeline(
    run_dir: Path,
    sqlite_path: Path,
    report_path: Path,
    ftp_extended: bool,
    ftp_login_check: bool,
    dns_qname: str,
    dns_rd: bool,
    dns_version_bind: bool,
    ssh_auth_probe: bool,
    ssh_auth_confirm_legal: bool,
    ssh_auth_username: str,
    continue_on_error: bool,
) -> int:
    """
    Run banner grabbers + report directly from this scan's run_dir.
    """
    script_dir = Path(__file__).resolve().parent
    py = sys.executable

    jobs = [
        {
            "name": "ssh",
            "input": run_dir / "open_22.txt",
            "cmd": [
                py, str(script_dir / "grab_nonweb_banners.py"),
                "--input", str(run_dir / "open_22.txt"),
                "--service", "ssh",
                "--sqlite", str(sqlite_path),
            ],
        },
        {
            "name": "ftp",
            "input": run_dir / "open_21.txt",
            "cmd": [
                py, str(script_dir / "grab_nonweb_banners.py"),
                "--input", str(run_dir / "open_21.txt"),
                "--service", "ftp",
                "--sqlite", str(sqlite_path),
            ] + (["--extended"] if ftp_extended else []) + (["--ftp-login-check"] if ftp_login_check else []),
        },
        {
            "name": "dns",
            "input": run_dir / "open_53.txt",
            "cmd": [
                py, str(script_dir / "grab_dns_banners.py"),
                "--input", str(run_dir / "open_53.txt"),
                "--sqlite", str(sqlite_path),
                "--qname", dns_qname,
            ] + (["--rd"] if dns_rd else []) + (["--version-bind"] if dns_version_bind else []),
        },
        {
            "name": "vnc",
            "input": run_dir / "open_5900.txt",
            "cmd": [
                py, str(script_dir / "grab_nonweb_banners.py"),
                "--input", str(run_dir / "open_5900.txt"),
                "--service", "vnc",
                "--sqlite", str(sqlite_path),
            ],
        },
    ]

    if ssh_auth_probe:
        if not ssh_auth_confirm_legal:
            print("[!] SSH auth probe requested but missing legal acknowledgment.")
            print("    Add --pipeline-ssh-auth-confirm-legal to proceed.")
            if not continue_on_error:
                return 2
        else:
            jobs.append(
                {
                    "name": "ssh_auth",
                    "input": run_dir / "open_22.txt",
                    "cmd": [
                        py, str(script_dir / "probe_ssh_auth_methods.py"),
                        "--input", str(run_dir / "open_22.txt"),
                        "--sqlite", str(sqlite_path),
                        "--username", ssh_auth_username,
                        "--confirm-legal",
                    ],
                }
            )

    for job in jobs:
        input_path = job["input"]
        if not input_path.exists():
            print(f"[i] Skipping {job['name']}: input file not found ({input_path})")
            continue

        targets = count_targets(input_path)
        if targets == 0:
            print(f"[i] Skipping {job['name']}: no targets in {input_path.name}")
            continue

        print(f"[i] {job['name']} targets: {targets}")
        cp = subprocess.run(job["cmd"], text=True)
        if cp.returncode != 0:
            print(f"[!] Postprocess step failed: {job['name']} (rc={cp.returncode})")
            if not continue_on_error:
                return cp.returncode

    report_cmd = [
        py, str(script_dir / "report_nonweb.py"),
        "--sqlite", str(sqlite_path),
        "--out", str(report_path),
    ]
    cp = subprocess.run(report_cmd, text=True)
    if cp.returncode != 0:
        print(f"[!] Postprocess report step failed (rc={cp.returncode})")
        if not continue_on_error:
            return cp.returncode

    print("[OK] Postprocess pipeline complete.")
    print(f"    SQLite: {sqlite_path}")
    print(f"    Report: {report_path}")
    return 0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ports", default="21,22,53,5900",
                    help="Comma-separated ports to scan (default: 21,22,53,5900).")
    ap.add_argument("--passes", type=int, default=2,
                    help="Number of scan passes per port with seed variation (default: 2).")
    ap.add_argument("--seed-step", type=int, default=1000,
                    help="Step added to seed between passes (default: 1000).")
    ap.add_argument("--max-ips-total", type=int, default=0,
                    help="Hvis satt: -n til zmap (gjelder per port siden vi kjører zmap per port).")
    ap.add_argument("--bandwidth", default="10M",
                    help="ZMap bandwidth target (default: 10M).")
    ap.add_argument("--rate", type=int, default=0)
    ap.add_argument("--seed", type=int, default=1,
                    help="Base seed for ZMap target permutation (default: 1).")
    ap.add_argument("--iface", "-i", default="",
                    help="Network interface (auto-detect if omitted on Linux/WSL).")
    ap.add_argument("--gateway-mac", "-G", default="")
    ap.add_argument("--blacklist-file", "-b", default="")
    ap.add_argument(
        "--open-only",
        action="store_true",
        help=(
            "Default: inkluder både 'open' og negative responser (success=0) i ZMap-output for bedre analyse. "
            "Sett --open-only for å kun beholde 'open'-treff (mindre output / raskere parsing)."
        ),
    )
    ap.add_argument("--dns-udp", dest="dns_udp", action="store_true", default=True,
                    help="Bruk UDP DNS-probe for port 53 (default: true).")
    ap.add_argument("--dns-tcp", dest="dns_udp", action="store_false",
                    help="Tving TCP SYN-scan for port 53 (ikke UDP).")
    ap.add_argument("--dns-query", default="example.com",
                    help="DNS qname for UDP-probe (default: example.com).")
    ap.add_argument("--dns-rd", action="store_true",
                    help="Sett RD-flagget (recursion desired) i DNS-probe.")
    ap.add_argument("--cidr-file", default=str(CIDR_FILE_DEFAULT), help="Path to CIDR/whitelist file (default: data/norway_ipv4_whitelist.txt)")
    # Raw ZMap CSV handling:
    # Default: keep raw files (port_*/zmap.csv) because they may be needed for downstream work.
    # Use --cleanup-raw to delete them after parsing to save disk/IO.
    ap.add_argument(
        "--cleanup-raw",
        action="store_true",
        help="Slett port_*/zmap.csv etter parsing for å spare disk/IO. Default: behold råfiler.",
    )
    ap.add_argument(
        "--keep-raw",
        action="store_true",
        help="(deprecated) Behold port_*/zmap.csv. Råfiler beholdes nå som standard; bruk --cleanup-raw for å slette.",
    )
    ap.add_argument("--write-aggregate", action="store_true",
                    help="Skriv aggregate.csv (kan bli stor). Default: ikke skriv aggregate.")
    ap.add_argument("--no-open-lists", action="store_true",
                    help="Ikke skriv open_*.txt lister. Default: skriv dem.")
    ap.add_argument("--no-latest", action="store_true",
                    help="Ikke oppdater data/scans/latest peker (nyttig for test-kjøringer).")
    ap.add_argument("--open-run-dir", action="store_true",
                    help="Aapne run-mappen i filutforsker etter fullfort skann.")
    ap.add_argument("--full-pipeline", dest="full_pipeline", action="store_true", default=True,
                    help="After scan, run SSH/FTP/DNS/VNC banner grab + nonweb report automatically (default: on).")
    ap.add_argument("--no-full-pipeline", dest="full_pipeline", action="store_false",
                    help="Disable automatic postprocess pipeline after scan.")
    ap.add_argument("--pipeline-sqlite", default="",
                    help="SQLite path for full pipeline (default: <run_dir>/nonweb_banners.sqlite).")
    ap.add_argument("--pipeline-report-out", default="",
                    help="Report output path for full pipeline (default: <run_dir>/nonweb_report.txt).")
    ap.add_argument("--pipeline-no-ftp-extended", action="store_true",
                    help="Disable FTP extended probing (SYST/FEAT) in full pipeline mode.")
    ap.add_argument("--pipeline-ftp-login-check", dest="pipeline_ftp_login_check", action="store_true", default=True,
                    help="Enable FTP login-establishment fingerprint (USER anonymous only, no password attempt) (default: on).")
    ap.add_argument("--pipeline-no-ftp-login-check", dest="pipeline_ftp_login_check", action="store_false",
                    help="Disable FTP login-establishment fingerprint in pipeline mode.")
    ap.add_argument("--pipeline-dns-qname", default="example.com",
                    help="DNS qname for pipeline DNS grabber (default: example.com).")
    ap.add_argument("--pipeline-dns-rd", dest="pipeline_dns_rd", action="store_true", default=True,
                    help="Set RD flag for pipeline DNS grabber (default: on).")
    ap.add_argument("--pipeline-no-dns-rd", dest="pipeline_dns_rd", action="store_false",
                    help="Disable RD flag for pipeline DNS grabber.")
    ap.add_argument("--pipeline-dns-version-bind", dest="pipeline_dns_version_bind", action="store_true", default=True,
                    help="Enable version.bind fingerprint in pipeline DNS grabber (default: on).")
    ap.add_argument("--pipeline-no-dns-version-bind", dest="pipeline_dns_version_bind", action="store_false",
                    help="Disable version.bind fingerprint in pipeline DNS grabber.")
    ap.add_argument("--pipeline-ssh-auth-probe", action="store_true",
                    help="Enable optional SSH auth-method probe (userauth none). OFF by default.")
    ap.add_argument("--pipeline-ssh-auth-confirm-legal", action="store_true",
                    help="Required legal acknowledgment for --pipeline-ssh-auth-probe.")
    ap.add_argument("--pipeline-ssh-auth-username", default="probe",
                    help="Username for SSH auth-none probe (default: probe).")
    ap.add_argument("--pipeline-continue-on-error", action="store_true",
                    help="Continue full pipeline if one postprocess step fails.")
    ap.add_argument("--pipeline-only", action="store_true",
                    help="Run only banner/report pipeline (no scan). Uses --pipeline-run-dir or data/scans/latest.")
    ap.add_argument("--pipeline-run-dir", default="",
                    help="Run directory for --pipeline-only (default: data/scans/latest).")
    ap.add_argument("--zmap-heartbeat-sec", type=int, default=60,
                    help="Print heartbeat while each ZMap pass runs (default: 60s, 0=off).")
    ap.add_argument("--zmap-pass-timeout-sec", type=int, default=0,
                    help="Hard timeout per ZMap pass in seconds (default: auto from estimate).")
    ap.add_argument("--zmap-pass-timeout-factor", type=float, default=3.0,
                    help="Auto-timeout multiplier on estimated pass duration (default: 3.0).")
    ap.add_argument("--zmap-min-pass-timeout-sec", type=int, default=600,
                    help="Minimum auto-timeout per pass in seconds (default: 600).")
    ap.add_argument("--zmap-stall-timeout-sec", type=int, default=1800,
                    help="Abort if output CSV stops growing this long after first growth (default: 1800, 0=off).")
    args = ap.parse_args()

    if args.passes < 1:
        print("[!] --passes must be >= 1")
        return 2
    if args.zmap_heartbeat_sec < 0:
        print("[!] --zmap-heartbeat-sec must be >= 0")
        return 2
    if args.zmap_pass_timeout_sec < 0:
        print("[!] --zmap-pass-timeout-sec must be >= 0")
        return 2
    if args.zmap_pass_timeout_factor <= 0:
        print("[!] --zmap-pass-timeout-factor must be > 0")
        return 2
    if args.zmap_min_pass_timeout_sec < 0:
        print("[!] --zmap-min-pass-timeout-sec must be >= 0")
        return 2
    if args.zmap_stall_timeout_sec < 0:
        print("[!] --zmap-stall-timeout-sec must be >= 0")
        return 2
    if args.pipeline_only:
        base_dir = Path(args.pipeline_run_dir) if args.pipeline_run_dir else (OUT_ROOT / "latest")
        if not base_dir.exists():
            print(f"[!] Pipeline run directory not found: {base_dir}")
            return 2
        run_dir = base_dir.resolve()
        sqlite_path = Path(args.pipeline_sqlite) if args.pipeline_sqlite else (run_dir / "nonweb_banners.sqlite")
        report_path = Path(args.pipeline_report_out) if args.pipeline_report_out else (run_dir / "nonweb_report.txt")
        return run_postprocess_pipeline(
            run_dir=run_dir,
            sqlite_path=sqlite_path,
            report_path=report_path,
            ftp_extended=(not args.pipeline_no_ftp_extended),
            ftp_login_check=args.pipeline_ftp_login_check,
            dns_qname=args.pipeline_dns_qname,
            dns_rd=args.pipeline_dns_rd,
            dns_version_bind=args.pipeline_dns_version_bind,
            ssh_auth_probe=args.pipeline_ssh_auth_probe,
            ssh_auth_confirm_legal=args.pipeline_ssh_auth_confirm_legal,
            ssh_auth_username=args.pipeline_ssh_auth_username,
            continue_on_error=args.pipeline_continue_on_error,
        )

    # Default: we want both open and negative responses for analysis.
    # Use --open-only to reduce output size to only open responders.
    args.output_all = not args.open_only

    if not args.iface:
        detected = detect_iface()
        if detected:
            args.iface = detected
            print(f"[i] Auto-detected iface: {args.iface}")
        else:
            print("[i] No --iface provided and auto-detect failed; letting ZMap choose default.")


    zmap_path = find_zmap()
    if not zmap_path:
        print("[!] zmap ikke funnet.")
        return 1

    blacklist_path = ensure_blacklist(args.blacklist_file)

    cidr_file = Path(args.cidr_file)
    if not cidr_file.exists():
        print(f"[!] CIDR/whitelist file not found: {cidr_file}")
        return 2
    cidrs = load_cidrs(cidr_file)

    run_meta = {
        "run_id": None,
        "started_at": now_utc(),
        "host": platform.node(),
        "platform": platform.platform(),
        "zmap_version": get_zmap_version(zmap_path),
        "cidr_file": str(cidr_file),
        "cidrs_loaded": None,
        "total_targets_all": None,
        "targets_per_port_effective": None,
        "ports": None,
        "bandwidth": args.bandwidth,
        "rate": args.rate,
        "seed": args.seed,
        "passes": args.passes,
        "seed_step": args.seed_step,
        "zmap_heartbeat_sec": args.zmap_heartbeat_sec,
        "zmap_pass_timeout_sec": args.zmap_pass_timeout_sec,
        "zmap_pass_timeout_factor": args.zmap_pass_timeout_factor,
        "zmap_min_pass_timeout_sec": args.zmap_min_pass_timeout_sec,
        "zmap_stall_timeout_sec": args.zmap_stall_timeout_sec,
        "iface": args.iface,
        "gateway_mac": args.gateway_mac,
        "blacklist": blacklist_path,
        "open_only": bool(args.open_only),
        "dns_udp": bool(args.dns_udp),
        "dns_query": args.dns_query,
        "dns_rd": bool(args.dns_rd),
        "full_pipeline": bool(args.full_pipeline),
        "pipeline_ftp_login_check": bool(args.pipeline_ftp_login_check),
        "pipeline_dns_qname": args.pipeline_dns_qname,
        "pipeline_dns_rd": bool(args.pipeline_dns_rd),
        "pipeline_dns_version_bind": bool(args.pipeline_dns_version_bind),
        "pipeline_ssh_auth_probe": bool(args.pipeline_ssh_auth_probe),
        "commands": {},
        "results": {},
    }

    # Build CIDR networks and compute total targets
    cidr_nets = build_cidr_networks(cidrs)
    cidr_total_by_net = {str(n): int(n.num_addresses) for n in cidr_nets}
    total_targets_all = int(sum(cidr_total_by_net.values()))
    run_meta["cidrs_loaded"] = len(cidrs)
    run_meta["total_targets_all"] = total_targets_all

    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    run_meta["ports"] = ports
    bw_mbps = parse_bandwidth_mbps(args.bandwidth)

    # Total targets: full CIDR space vs optional test limit (-n)
    total_targets_effective = args.max_ips_total if args.max_ips_total > 0 else total_targets_all
    run_meta["targets_per_port_effective"] = total_targets_effective

    estimate_runtime(total_targets_effective, bw_mbps, ports_count=len(ports) * args.passes)
    estimated_pass_seconds = estimate_runtime_seconds(total_targets_effective, bw_mbps, ports_count=1)
    if args.zmap_pass_timeout_sec > 0:
        pass_timeout_sec = args.zmap_pass_timeout_sec
    else:
        pass_timeout_sec = int(max(
            args.zmap_min_pass_timeout_sec,
            estimated_pass_seconds * args.zmap_pass_timeout_factor
        ))
    run_meta["zmap_pass_timeout_effective_sec"] = pass_timeout_sec
    print(
        f"[i] Watchdog: per-pass timeout={pass_timeout_sec}s, "
        f"stall-timeout={'off' if args.zmap_stall_timeout_sec == 0 else str(args.zmap_stall_timeout_sec) + 's'}, "
        f"heartbeat={'off' if args.zmap_heartbeat_sec == 0 else str(args.zmap_heartbeat_sec) + 's'}"
    )

    run_id = now_utc().replace(":", "-")
    run_meta["run_id"] = run_id
    run_dir = OUT_ROOT / run_id
    ensure_dir(run_dir)
    (run_dir / "run.json").write_text(json.dumps(run_meta, indent=2), encoding="utf-8")

    # Removed creation of all_targets_file/targets__ALL.txt
    agg_file = (run_dir / AGG_FILE_NAME) if args.write_aggregate else None
    summary_path = run_dir / "summary.txt"

    # Telling for summary
    counts_port = defaultdict(lambda: {"open": 0, "closed": 0, "unknown": 0})
    open_by_port = defaultdict(set)

    # CIDR-level analysis (unique IPs per CIDR per port)
    cidr_open_by_port = defaultdict(lambda: defaultdict(set))   # cidr -> port -> set(ip)
    cidr_closed_by_port = defaultdict(lambda: defaultdict(set)) # cidr -> port -> set(ip)

    t0_total = time.perf_counter()

    # Optional aggregate writer
    fh = None
    writer = None
    if agg_file:
        fh = agg_file.open("w", newline="", encoding="utf-8")
        writer = csv.writer(fh)
        writer.writerow(["scan_timestamp","run_id","ip","ip_block","port","status","ttl","source"])

    for port in ports:
        port_dir = run_dir / f"port_{port}"
        ensure_dir(port_dir)

        open_ips_union = set()
        closed_ips_union = set()
        output_lines_total = 0
        port_commands = []
        pass_results = []
        port_runtime_total = 0.0

        for pass_idx in range(args.passes):
            pass_no = pass_idx + 1
            out_csv = port_dir / ("zmap.csv" if args.passes == 1 else f"zmap_pass{pass_no}.csv")

            use_dns_udp = (port == 53 and args.dns_udp)
            if use_dns_udp:
                dns_hex = build_dns_query_hex(args.dns_query, rd=args.dns_rd)
                cmd = [
                    zmap_path, "-M", "udp", "-p", str(port),
                    "-w", str(cidr_file),
                    "-O", "csv",
                    "--output-fields=saddr,success,ttl",
                    "--probe-args", f"hex:{dns_hex}",
                    "-b", blacklist_path,
                    "-o", str(out_csv),
                ]
            else:
                cmd = [
                    zmap_path, "-M", "tcp_synscan", "-p", str(port),
                    "-w", str(cidr_file),
                    "-O", "csv",
                    "--output-fields=saddr,success,ttl",
                    "-b", blacklist_path,
                    "-o", str(out_csv),
                ]

            if args.output_all:
                cmd += ["--output-filter=repeat=0"]

            if args.rate:
                cmd += ["-r", str(args.rate)]
            else:
                cmd += ["-B", str(args.bandwidth)]

            if args.max_ips_total:
                cmd += ["-n", str(args.max_ips_total)]

            if args.seed:
                seed_for_pass = args.seed + (pass_idx * args.seed_step)
            else:
                # Stable, varied default for multi-pass runs.
                seed_for_pass = pass_no
            cmd += ["--seed", str(seed_for_pass)]

            if args.iface:
                cmd += ["-i", args.iface]
            if args.gateway_mac:
                cmd += ["-G", args.gateway_mac]

            port_commands.append(" ".join(cmd))
            print(f"[i] Running ZMap on port {port} (pass {pass_no}/{args.passes}, seed={seed_for_pass}) ...")

            t0 = time.perf_counter()
            timed_out_reason = ""
            zmap_log_path = out_csv.with_suffix(out_csv.suffix + ".log")
            try:
                with zmap_log_path.open("w", encoding="utf-8", errors="replace") as zlog:
                    proc = subprocess.Popen(cmd, text=True, stdout=zlog, stderr=subprocess.STDOUT)
                    last_heartbeat = t0
                    last_growth = t0
                    last_size = out_csv.stat().st_size if out_csv.exists() else 0
                    saw_growth = last_size > 0
                    rc = None

                    while True:
                        rc = proc.poll()
                        now = time.perf_counter()

                        # Track CSV growth continuously for stall detection.
                        cur_size = out_csv.stat().st_size if out_csv.exists() else 0
                        if cur_size > last_size:
                            saw_growth = True
                            last_growth = now
                            last_size = cur_size

                        if rc is not None:
                            break

                        elapsed = now - t0
                        if pass_timeout_sec > 0 and elapsed > pass_timeout_sec:
                            timed_out_reason = f"pass exceeded timeout ({pass_timeout_sec}s)"
                        elif (
                            args.zmap_stall_timeout_sec > 0
                            and saw_growth
                            and (now - last_growth) > args.zmap_stall_timeout_sec
                        ):
                            timed_out_reason = (
                                f"no output growth for {args.zmap_stall_timeout_sec}s "
                                f"(last csv size={last_size} bytes)"
                            )

                        if timed_out_reason:
                            proc.terminate()
                            try:
                                proc.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                proc.kill()
                                proc.wait(timeout=10)
                            rc = proc.returncode if proc.returncode is not None else 124
                            break

                        if args.zmap_heartbeat_sec > 0 and (now - last_heartbeat) >= args.zmap_heartbeat_sec:
                            print(
                                f"[i] Port {port} pass {pass_no}/{args.passes} heartbeat | "
                                f"elapsed={elapsed:.0f}s csv_bytes={cur_size:,}"
                            )
                            last_heartbeat = now

                        time.sleep(1)
            except KeyboardInterrupt:
                print("\n[!] Scan interrupted by user (Ctrl+C). Stopping gracefully.")
                run_meta["finished_at"] = now_utc()
                run_meta["interrupted"] = True
                run_meta["interrupted_port"] = port
                run_meta["interrupted_pass"] = pass_no
                (run_dir / "run.json").write_text(json.dumps(run_meta, indent=2), encoding="utf-8")
                if fh:
                    fh.close()
                return 130
            t1 = time.perf_counter()
            pass_runtime = t1 - t0
            port_runtime_total += pass_runtime

            if timed_out_reason:
                err_tail = read_text_tail(zmap_log_path, max_chars=2000)
                print(f"[!] ZMap aborted on port {port} pass {pass_no}: {timed_out_reason}")
                if err_tail:
                    print(f"[i] ZMap log tail ({zmap_log_path.name}):\n{err_tail}")
                if fh:
                    fh.close()
                return 2

            if rc != 0:
                err_tail = read_text_tail(zmap_log_path, max_chars=2000)
                print(f"[!] ZMap feilet på port {port} pass {pass_no} (rc={rc}).")
                if err_tail:
                    print(f"[i] ZMap log tail ({zmap_log_path.name}):\n{err_tail}")
                if fh:
                    fh.close()
                return 2

            open_ips_pass = set()
            closed_ips_pass = set()
            output_lines_pass = 0

            if out_csv.exists():
                with out_csv.open("r", encoding="utf-8", errors="replace") as rf:
                    for line in rf:
                        d = parse_zmap_csv_line(line)
                        if not d:
                            continue
                        output_lines_pass += 1
                        ip, success, ttl = d["ip"], d["success"], d["ttl"]

                        if success == "1":
                            status = "open"
                            open_ips_pass.add(ip)
                        elif success == "0":
                            status = "closed"
                            closed_ips_pass.add(ip)
                        else:
                            status = "unknown"

                        cidr_hit = find_cidr_for_ip(ip, cidr_nets)
                        if cidr_hit:
                            if status == "open":
                                cidr_open_by_port[cidr_hit][str(port)].add(ip)
                            elif status == "closed":
                                cidr_closed_by_port[cidr_hit][str(port)].add(ip)

                        if writer:
                            writer.writerow([now_utc(), run_id, ip, cidr_hit or "", port, status, ttl, "zmap"])

            open_ips_union.update(open_ips_pass)
            closed_ips_union.update(closed_ips_pass)
            output_lines_total += output_lines_pass
            closed_only_pass = closed_ips_pass - open_ips_pass
            pass_results.append({
                "pass": pass_no,
                "seed": seed_for_pass,
                "open": len(open_ips_pass),
                "closed": len(closed_only_pass),
                "output_lines": output_lines_pass,
                "runtime_seconds": round(pass_runtime, 3),
            })

            pass_dupes = max(0, output_lines_pass - len(open_ips_pass) - len(closed_ips_pass))
            print(
                f"[i] Port {port} pass {pass_no} done in {pass_runtime:.2f}s | "
                f"open={len(open_ips_pass)} closed={len(closed_only_pass)} "
                f"output_lines={output_lines_pass} dupes~={pass_dupes}"
            )

            if out_csv.exists() and args.cleanup_raw:
                try:
                    out_csv.unlink()
                except Exception:
                    pass

        closed_only_union = closed_ips_union - open_ips_union
        open_cnt = len(open_ips_union)
        closed_cnt = len(closed_only_union)
        open_by_port[str(port)] = open_ips_union

        if args.output_all:
            unknown_cnt = max(0, total_targets_effective - open_cnt - closed_cnt)
        else:
            closed_cnt = 0
            unknown_cnt = max(0, total_targets_effective - open_cnt)

        counts_port[str(port)]["open"] = open_cnt
        counts_port[str(port)]["closed"] = closed_cnt
        counts_port[str(port)]["unknown"] = unknown_cnt

        run_meta["commands"][str(port)] = port_commands[0] if args.passes == 1 else port_commands
        run_meta["results"][str(port)] = {
            "open": open_cnt,
            "closed": closed_cnt,
            "no_response": unknown_cnt,
            "output_lines": output_lines_total,
            "passes": pass_results,
        }

        dupes = max(0, output_lines_total - len(open_ips_union) - len(closed_ips_union))
        print(
            f"[i] Port {port} done in {port_runtime_total:.2f}s | "
            f"open={open_cnt} closed={closed_cnt} no_response={unknown_cnt} | "
            f"output_lines={output_lines_total} dupes~={dupes}"
        )

    # Close optional aggregate file
    if fh:
        fh.close()

    # Summary + optional "both open" (only for 80/443 scans)
    ports_str = [str(p) for p in ports]
    unique_open_ips = set().union(*open_by_port.values()) if open_by_port else set()
    both_open = []
    if "80" in ports_str and "443" in ports_str:
        both_open = sorted(open_by_port.get("80", set()).intersection(open_by_port.get("443", set())))

    t1_total = time.perf_counter()

    with summary_path.open("w", encoding="utf-8") as sf:
        sf.write(f"Run ID: {run_id}\n")
        sf.write(f"Ports scanned: {ports}\n")
        sf.write(f"CIDR file: {cidr_file}\n")
        sf.write(f"CIDRs loaded: {len(cidrs)}\n")
        sf.write(f"Total targets (all CIDRs): {total_targets_all}\n")
        sf.write(f"Targets per port (effective): {total_targets_effective}\n")
        sf.write(f"Output-all enabled: {args.output_all}\n")
        for p in ports:
            c = counts_port[str(p)]
            denom = float(total_targets_effective) if total_targets_effective > 0 else 1.0
            open_pct = (c['open'] / denom) * 100.0
            closed_pct = (c['closed'] / denom) * 100.0
            nr_pct = (c['unknown'] / denom) * 100.0
            sf.write(
                f"Port {p}: open={c['open']} ({open_pct:.2f}%) "
                f"closed={c['closed']} ({closed_pct:.2f}%) "
                f"no_response={c['unknown']} ({nr_pct:.2f}%)\n"
            )
        sf.write(f"Unique IPs with at least one open port: {len(unique_open_ips)}\n")
        if both_open:
            sf.write(f"IPs open on BOTH 80 and 443: {len(both_open)}\n")

        sf.write("\n--- Top CIDR ranges by open responses (any port) ---\n")

        # Compute per-CIDR stats (unique responders). For sampled runs (-n), per-CIDR "no_response"
        # cannot be derived correctly because target distribution per CIDR is unknown.
        sampled_run = args.max_ips_total > 0
        rows = []
        for net_str, total in cidr_total_by_net.items():
            per_port = {}
            for p in ports_str:
                open_set = cidr_open_by_port[net_str].get(p, set())
                closed_set = cidr_closed_by_port[net_str].get(p, set())
                # Treat "closed" as closed-only to avoid overlap with IPs seen open in another pass.
                closed_only_set = closed_set - open_set
                open_p = len(open_set)
                close_p = len(closed_only_set)
                no_resp_p = "n/a" if sampled_run else max(0, total - open_p - close_p)
                per_port[p] = (open_p, close_p, no_resp_p)
            if ports_str:
                open_any = len(set().union(*[cidr_open_by_port[net_str].get(p, set()) for p in ports_str]))
            else:
                open_any = 0
            rows.append((open_any, net_str, total, per_port))

        rows.sort(reverse=True, key=lambda x: (x[0], x[2]))
        top = rows[:20]

        # Fixed-width, readable table (dynamic columns based on scanned ports)
        cidr_w = 17
        count_w = 8
        header = f"{'CIDR':<{cidr_w}}  {'total':>{count_w}}"
        for p in ports_str:
            header += f"  {('o' + p):>{count_w}}  {('c' + p):>{count_w}}  {('nr' + p):>{count_w}}"
        header += f"  {'open_any':>{count_w}}"
        sf.write(header + "\n")

        sep = f"{'-' * cidr_w}  {'-' * count_w}"
        for _ in ports_str:
            sep += f"  {'-' * count_w}  {'-' * count_w}  {'-' * count_w}"
        sep += f"  {'-' * count_w}"
        sf.write(sep + "\n")

        for open_any, net_str, total, per_port in top:
            line = f"{net_str:<{cidr_w}}  {total:>{count_w}}"
            for p in ports_str:
                open_p, close_p, no_resp_p = per_port[p]
                line += f"  {open_p:>{count_w}}  {close_p:>{count_w}}  {no_resp_p:>{count_w}}"
            line += f"  {open_any:>{count_w}}"
            sf.write(line + "\n")

        sf.write("\nNotes:\n")
        sf.write("- ZMap output is response-driven; hosts with no response are not listed and are shown as 'no_response'.\n")
        sf.write("- 'closed' counts only *observed* negative responses (e.g., RST). Many networks silently drop packets, so most non-responders appear as 'no_response'.\n")
        if sampled_run:
            sf.write("- This run used a target sample (--max-ips-total), so per-CIDR nr* is shown as 'n/a'.\n")

        total_s = (t1_total - t0_total)
        total_min = total_s / 60.0
        sf.write(f"Total runtime: {total_s:.2f}s ({total_min:.2f} min)\n")

    # Write helper open lists for downstream validation (optional)
    if not args.no_open_lists:
        write_open_lists(run_dir, open_by_port)

    run_meta["finished_at"] = now_utc()
    run_meta["total_runtime_seconds"] = round(t1_total - t0_total, 3)
    # Persist final metadata
    (run_dir / "run.json").write_text(json.dumps(run_meta, indent=2), encoding="utf-8")

    # Update latest pointer only after a successful run completes.
    if not args.no_latest:
        write_symlink_latest(OUT_ROOT, run_dir)

    if agg_file:
        print(f"[✓] Ferdig — resultater i {agg_file}")
    else:
        print("[✓] Ferdig — aggregate.csv deaktivert (--write-aggregate for å skrive den)")
    print(f"    Oppsummering: {summary_path}")
    if args.no_latest:
        print("    Latest-peker: (ikke oppdatert, --no-latest)")
    else:
        print(f"    Latest-peker: {OUT_ROOT / 'latest'}")
    if args.open_run_dir:
        open_run_dir(run_dir)
    if args.full_pipeline:
        sqlite_path = Path(args.pipeline_sqlite) if args.pipeline_sqlite else (run_dir / "nonweb_banners.sqlite")
        report_path = Path(args.pipeline_report_out) if args.pipeline_report_out else (run_dir / "nonweb_report.txt")
        rc = run_postprocess_pipeline(
            run_dir=run_dir,
            sqlite_path=sqlite_path,
            report_path=report_path,
            ftp_extended=(not args.pipeline_no_ftp_extended),
            ftp_login_check=args.pipeline_ftp_login_check,
            dns_qname=args.pipeline_dns_qname,
            dns_rd=args.pipeline_dns_rd,
            dns_version_bind=args.pipeline_dns_version_bind,
            ssh_auth_probe=args.pipeline_ssh_auth_probe,
            ssh_auth_confirm_legal=args.pipeline_ssh_auth_confirm_legal,
            ssh_auth_username=args.pipeline_ssh_auth_username,
            continue_on_error=args.pipeline_continue_on_error,
        )
        if rc != 0:
            return rc
    return 0

if __name__ == "__main__":
    sys.exit(main())
