#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fetch_norway_ip_ranges.py

Fetch and merge Norwegian IPv4 ranges.

Outputs:
  - data/norway_ipv4_cidrs.txt        (human-friendly with header comments)
  - data/norway_ipv4_whitelist.txt    (PURE whitelist for ZMap: NO comments)
  - data/norway_ipv4_cidrs.json
  - data/norway_ipv4_sources.json
"""

import argparse
import io
import json
import os
import sys
import textwrap
import zipfile
from datetime import datetime, timezone

import ipaddress
import requests

UTC = timezone.utc


try:
    from bs4 import BeautifulSoup
except ImportError:
    print("This script requires 'requests' and 'beautifulsoup4'. Install with:")
    print("  pip install requests beautifulsoup4")
    sys.exit(1)

HEADERS = {
    "User-Agent": "UiO-SecurityLab-Robot/0.1 (+contact: your_email@uio.no)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Connection": "close",
    "From": "your_email@uio.no",
    "Accept-Language": "en-US,en;q=0.9"
}

IP2LOCATION_URL = "https://lite.ip2location.com/norway-ip-address-ranges?lang=en_US"
RIPE_DELEGATED = "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest"

OUT_DIR = "data"
OUT_TXT = os.path.join(OUT_DIR, "norway_ipv4_cidrs.txt")
OUT_JSON = os.path.join(OUT_DIR, "norway_ipv4_cidrs.json")
META_JSON = os.path.join(OUT_DIR, "norway_ipv4_sources.json")

OUT_WL = os.path.join(OUT_DIR, "norway_ipv4_whitelist.txt")


def ensure_outdir(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)

def now_utc() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def make_session() -> requests.Session:
    """Create a requests session with basic retry/backoff."""
    s = requests.Session()
    try:
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        retry = Retry(
            total=5,
            connect=5,
            read=5,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
    except Exception:
        # If urllib3/Retry isn't available for some reason, fall back to default session.
        pass
    return s


def fetch_ip2location_ranges(session: requests.Session, timeout=60):
    print("[*] Fetching IP ranges from IP2Location (CSV dataset)...")
    url = "https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.CSV.ZIP"
    r = session.get(url, headers=HEADERS, timeout=timeout)
    r.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        csv_name = [n for n in z.namelist() if n.endswith(".CSV")][0]
        with z.open(csv_name) as f:
            lines = f.read().decode("utf-8").splitlines()

    cidrs = []
    for line in lines:
        parts = line.strip().split(",")
        # Skip if not enough columns
        if len(parts) < 4:
            continue

        # Get country code (3rd or 4th column depending on file version)
        country_code = parts[2].strip('"')
        country_name = parts[3].strip('"') if len(parts) > 3 else ""

        if country_code != "NO" and country_name.lower() != "norway":
            continue

        # The first two columns are integer IPs, convert to dotted format
        try:
            start_int = int(parts[0].strip('"'))
            end_int = int(parts[1].strip('"'))
            start_ip = ipaddress.IPv4Address(start_int)
            end_ip = ipaddress.IPv4Address(end_int)
            cidrs.extend([str(n) for n in ipaddress.summarize_address_range(start_ip, end_ip)])
        except Exception:
            continue

    print(f"    -> Found {len(cidrs)} CIDRs from IP2Location CSV.")
    return cidrs


def fetch_ripe_delegated_no(session: requests.Session, timeout=45):
    print("[*] Fetching fallback ranges from RIPE delegated stats...")
    r = session.get(RIPE_DELEGATED, headers=HEADERS, timeout=timeout)
    r.raise_for_status()
    cidrs = []

    for line in r.text.splitlines():
        parts = line.strip().split("|")
        if len(parts) < 7:
            continue
        registry, cc, rtype, start, value, date, status = parts[:7]
        if registry != "ripencc" or cc != "NO" or rtype != "ipv4":
            continue
        try:
            start_ip = ipaddress.IPv4Address(start)
            count = int(value)
        except Exception:
            continue

        cidrs.extend(iprange_to_cidrs(start_ip, count))
    print(f"    -> Derived {len(cidrs)} CIDRs from RIPE delegated data.")
    return cidrs

def iprange_to_cidrs(start_ip, count):
    # start_ip: ipaddress.IPv4Address
    start_int = int(start_ip)
    end_int = start_int + int(count) - 1
    start_addr = ipaddress.IPv4Address(start_int)
    end_addr = ipaddress.IPv4Address(end_int)
    return [str(n) for n in ipaddress.summarize_address_range(start_addr, end_addr)]

def normalize_and_merge(cidrs):
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except Exception:
            pass
    nets_sorted = sorted(nets, key=lambda n: (int(n.network_address), n.prefixlen))
    merged = ipaddress.collapse_addresses(nets_sorted)
    return [str(n) for n in sorted(merged, key=lambda n: (int(n.network_address), n.prefixlen))]


def main() -> int:
    ap = argparse.ArgumentParser(description="Fetch and merge Norwegian IPv4 CIDRs")
    ap.add_argument("--out-dir", default=OUT_DIR, help="Output directory (default: data)")
    ap.add_argument(
        "--sources",
        default="ripe,ip2location",
        help="Comma-separated sources: ripe,ip2location (default: ripe,ip2location)",
    )
    args = ap.parse_args()

    out_dir = args.out_dir
    out_txt = os.path.join(out_dir, "norway_ipv4_cidrs.txt")
    out_wl = os.path.join(out_dir, "norway_ipv4_whitelist.txt")
    out_json = os.path.join(out_dir, "norway_ipv4_cidrs.json")
    meta_json = os.path.join(out_dir, "norway_ipv4_sources.json")

    ensure_outdir(out_dir)
    wanted = {s.strip().lower() for s in args.sources.split(",") if s.strip()}
    if not wanted:
        wanted = {"ripe"}

    session = make_session()
    sources = {}
    all_cidrs = []

    # Fetch sources
    if "ip2location" in wanted:
        try:
            ip2_cidrs = fetch_ip2location_ranges(session)
            if ip2_cidrs:
                sources["ip2location"] = {
                    "url": "https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.CSV.ZIP",
                    "count_raw": len(ip2_cidrs),
                    "fetched_at": now_utc(),
                }
                all_cidrs.extend(ip2_cidrs)
        except Exception as e:
            print(f"[!] IP2Location fetch failed: {e}")

    if "ripe" in wanted:
        try:
            ripe_cidrs = fetch_ripe_delegated_no(session)
            if ripe_cidrs:
                sources["ripe_delegated"] = {
                    "url": RIPE_DELEGATED,
                    "count_raw": len(ripe_cidrs),
                    "fetched_at": now_utc(),
                }
                all_cidrs.extend(ripe_cidrs)
        except Exception as e:
            print(f"[!] RIPE delegated fetch failed: {e}")

    if not all_cidrs:
        print("[!] No ranges could be fetched. Exiting.")
        return 2

    print("[*] Normalizing & merging CIDRs...")
    unique = sorted(set(all_cidrs))
    merged = normalize_and_merge(unique)

    # Add post-merge counts
    sources["_merged"] = {
        "count_unique_raw": len(unique),
        "count_merged": len(merged),
        "generated_at": now_utc(),
    }

    banner = textwrap.dedent(
        f"""
        # Norway IPv4 CIDR ranges (merged)
        # Generated: {now_utc()}
        # Sources: {', '.join([k for k in sources.keys() if not k.startswith('_')])}
        # Note: use norway_ipv4_whitelist.txt for ZMap (no comments).
        """
    ).strip()

    # Human-friendly file (with header)
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write(banner + "\n")
        for c in merged:
            f.write(c + "\n")

    # Pure whitelist for ZMap (no header/comments)
    with open(out_wl, "w", encoding="utf-8") as f:
        for c in merged:
            f.write(c + "\n")

    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({"cidrs": merged, "generated_at": now_utc()}, f, indent=2)

    with open(meta_json, "w", encoding="utf-8") as f:
        json.dump(sources, f, indent=2)

    print(f"[✓] Wrote {len(merged)} merged CIDRs to {out_txt}")
    print(f"[✓] Pure whitelist for ZMap: {out_wl}")
    print(f"[✓] JSON output: {out_json}")
    print(f"[✓] Sources meta: {meta_json}")
    print("\nNext steps:")
    print("  - Use the whitelist file as input for ZMap, e.g.:")
    print(f"      zmap -p 80 -B 10M -i <iface> -w {out_wl} -o results_port80.csv")
    print("  - Or feed open IPs into httpx for validation/fingerprinting in the next pipeline stage.")
    return 0


if __name__ == "__main__":
    sys.exit(main())