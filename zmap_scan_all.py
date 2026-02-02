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

CIDR_FILE_DEFAULT = Path("data/test-file.txt")
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

def estimate_runtime(total_ips: int, bandwidth_mbps: float, ports_count: int,
                     bytes_per_probe: int = 120) -> None:
    if total_ips <= 0:
        return
    bits_per_probe = bytes_per_probe * 8
    total_bits = total_ips * bits_per_probe * ports_count
    seconds = total_bits / (bandwidth_mbps * 1e6)
    minutes = seconds / 60
    print(f"[i] Estimated duration: ~{seconds:.1f}s ({minutes:.1f} min) "
          f"for {total_ips:,} IPs at {bandwidth_mbps:.1f} Mbit/s over {ports_count} ports")

def write_open_lists(run_dir: Path, open_by_port: dict) -> None:
    """Write helper lists for downstream validation (httpx/zgrab)."""
    open80 = sorted(open_by_port.get("80", set()))
    open443 = sorted(open_by_port.get("443", set()))
    both = sorted(set(open80).intersection(open443))
    any_open = sorted(set(open80).union(open443))

    (run_dir / "open_80.txt").write_text("\n".join(open80) + ("\n" if open80 else ""), encoding="utf-8")
    (run_dir / "open_443.txt").write_text("\n".join(open443) + ("\n" if open443 else ""), encoding="utf-8")
    (run_dir / "open_both_80_443.txt").write_text("\n".join(both) + ("\n" if both else ""), encoding="utf-8")
    (run_dir / "open_any_80_443.txt").write_text("\n".join(any_open) + ("\n" if any_open else ""), encoding="utf-8")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ports", default="80,443")
    ap.add_argument("--max-ips-total", type=int, default=0,
                    help="Hvis satt: -n til zmap (gjelder per port siden vi kjører zmap per port).")
    ap.add_argument("--bandwidth", default="10M")
    ap.add_argument("--rate", type=int, default=0)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--iface", "-i", default="")
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
    args = ap.parse_args()

    # Default: we want both open and negative responses for analysis.
    # Use --open-only to reduce output size to only open responders.
    args.output_all = not args.open_only


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
        "iface": args.iface,
        "gateway_mac": args.gateway_mac,
        "blacklist": blacklist_path,
        "open_only": bool(args.open_only),
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

    estimate_runtime(total_targets_effective, bw_mbps, ports_count=len(ports))

    run_id = now_utc().replace(":", "-")
    run_meta["run_id"] = run_id
    run_dir = OUT_ROOT / run_id
    ensure_dir(run_dir)
    write_symlink_latest(OUT_ROOT, run_dir)
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
        out_csv = port_dir / "zmap.csv"

        cmd = [
            zmap_path, "-M", "tcp_synscan", "-p", str(port),
            "-w", str(cidr_file),
            "-O", "csv",
            "--output-fields=saddr,success,ttl",
            "-b", blacklist_path,
            "-o", str(out_csv),
        ]

        # Viktig:
        # - Default output i ZMap er typisk kun success=1.
        # - Med --output-all setter vi output-filter til repeat=0 (da får du også success=0).
        if args.output_all:
            cmd += ["--output-filter=repeat=0"]

        if args.rate:
            cmd += ["-r", str(args.rate)]
        else:
            cmd += ["-B", str(args.bandwidth)]

        if args.max_ips_total:
            cmd += ["-n", str(args.max_ips_total)]
        if args.seed:
            cmd += ["--seed", str(args.seed)]
        if args.iface:
            cmd += ["-i", args.iface]
        if args.gateway_mac:
            cmd += ["-G", args.gateway_mac]

        run_meta["commands"][str(port)] = " ".join(cmd)

        print(f"[i] Running ZMap on port {port} ...")
        t0 = time.perf_counter()
        cp = subprocess.run(cmd, text=True, capture_output=True)
        t1 = time.perf_counter()
        if cp.returncode != 0:
            err = (cp.stderr or cp.stdout or "").strip()
            print(f"[!] ZMap feilet på port {port} (rc={cp.returncode}). Siste output:\n{err[-2000:]}")
            if fh:
                fh.close()
            return 2

        # Parse out_csv etterpå (raskere enn å håndtere stdout i Python mens zmap kjører)
        open_ips = set()
        closed_ips = set()
        output_lines = 0

        if out_csv.exists():
            with out_csv.open("r", encoding="utf-8", errors="replace") as rf:
                for line in rf:
                    d = parse_zmap_csv_line(line)
                    if not d:
                        continue
                    output_lines += 1
                    ip, success, ttl = d["ip"], d["success"], d["ttl"]

                    if success == "1":
                        status = "open"
                        open_ips.add(ip)
                    elif success == "0":
                        status = "closed"
                        closed_ips.add(ip)
                    else:
                        status = "unknown"

                    # Map to CIDR (best-effort) for range-level analysis
                    cidr_hit = find_cidr_for_ip(ip, cidr_nets)
                    if cidr_hit:
                        if status == "open":
                            cidr_open_by_port[cidr_hit][str(port)].add(ip)
                        elif status == "closed":
                            cidr_closed_by_port[cidr_hit][str(port)].add(ip)

                    if writer:
                        writer.writerow([now_utc(), run_id, ip, cidr_hit or "", port, status, ttl, "zmap"])

        open_cnt = len(open_ips)
        closed_cnt = len(closed_ips)
        open_by_port[str(port)] = open_ips

        # Note: ZMap output typically contains *responses* (SYN-ACK/RST). Hosts with no response
        # are not listed; we model those as "no_response" (stored in `unknown`).
        if args.output_all:
            unknown_cnt = max(0, total_targets_effective - open_cnt - closed_cnt)
        else:
            # Without output-all, we may only see "open" responses; treat everything else as no_response.
            closed_cnt = 0
            unknown_cnt = max(0, total_targets_effective - open_cnt)

        counts_port[str(port)]["open"] = open_cnt
        counts_port[str(port)]["closed"] = closed_cnt
        counts_port[str(port)]["unknown"] = unknown_cnt

        run_meta["results"][str(port)] = {
            "open_unique": open_cnt,
            "closed_unique": closed_cnt,
            "no_response": unknown_cnt,
            "output_lines": output_lines,
        }

        dupes = max(0, output_lines - len(open_ips) - len(closed_ips))
        print(
            f"[i] Port {port} done in {(t1 - t0):.2f}s | "
            f"open_unique={open_cnt} closed_unique={closed_cnt} no_response={unknown_cnt} | "
            f"output_lines={output_lines} dupes~={dupes}"
        )

        # Slett rå zmap.csv kun hvis eksplisitt bedt om det (for å spare disk/IO)
        if out_csv.exists() and args.cleanup_raw:
            try:
                out_csv.unlink()
            except Exception:
                pass

    # Close optional aggregate file
    if fh:
        fh.close()

    # Summary + “both open”
    both_open = sorted(open_by_port.get("80", set()).intersection(open_by_port.get("443", set())))
    unique_open_ips = set().union(*open_by_port.values()) if open_by_port else set()

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
                f"Port {p}: open_unique={c['open']} ({open_pct:.2f}%) "
                f"closed_unique={c['closed']} ({closed_pct:.2f}%) "
                f"no_response={c['unknown']} ({nr_pct:.2f}%)\n"
            )
        sf.write(f"Unique IPs with at least one open port: {len(unique_open_ips)}\n")
        sf.write(f"IPs open on BOTH 80 and 443: {len(both_open)}\n")

        sf.write("\n--- Top CIDR ranges by open responses (any port) ---\n")

        # Compute per-CIDR stats (unique responders) and derive no_response as remainder of CIDR size.
        rows = []
        for net_str, total in cidr_total_by_net.items():
            open_80 = len(cidr_open_by_port[net_str].get("80", set()))
            close_80 = len(cidr_closed_by_port[net_str].get("80", set()))
            open_443 = len(cidr_open_by_port[net_str].get("443", set()))
            close_443 = len(cidr_closed_by_port[net_str].get("443", set()))
            no_respons_80 = max(0, total - open_80 - close_80)
            no_respons_443 = max(0, total - open_443 - close_443)
            open_any = len(set().union(
                cidr_open_by_port[net_str].get("80", set()),
                cidr_open_by_port[net_str].get("443", set()),
            ))
            rows.append((open_any, net_str, total, open_80, close_80, no_respons_80, open_443, close_443, no_respons_443))

        rows.sort(reverse=True, key=lambda x: (x[0], x[2]))
        top = rows[:20]

        # Fixed-width, readable table
        sf.write("CIDR               total    o80   c80   nr80    o443  c443  nr443  open_any\n")
        sf.write("-----------------  ------  ----  ----  -----  -----  ----  -----  --------\n")
        for open_any, net_str, total, open_80, close_80, no_respons_80, open_443, close_443, no_respons_443 in top:
            sf.write(
                f"{net_str:<17}  {total:>6}  {open_80:>4}  {close_80:>4}  {no_respons_80:>5}  "
                f"{open_443:>5}  {close_443:>4}  {no_respons_443:>5}  {open_any:>8}\n"
            )

        sf.write("\nNotes:\n")
        sf.write("- ZMap output is response-driven; hosts with no response are not listed and are shown as 'no_response'.\n")
        sf.write("- 'closed' counts only *observed* negative responses (e.g., RST). Many networks silently drop packets, so most non-responders appear as 'no_response'.\n")

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

    if agg_file:
        print(f"[✓] Ferdig — resultater i {agg_file}")
    else:
        print("[✓] Ferdig — aggregate.csv deaktivert (--write-aggregate for å skrive den)")
    print(f"    Oppsummering: {summary_path}")
    print(f"    Latest-peker: {OUT_ROOT / 'latest'}")
    return 0

if __name__ == "__main__":
    sys.exit(main())