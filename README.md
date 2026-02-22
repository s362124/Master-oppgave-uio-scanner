# Non-Web Norway Scanner (SSH/FTP/DNS/VNC)

This project scans Norwegian IPv4 ranges with ZMap, then runs non-web fingerprinting and reporting.

## Project overview

This repository is part of a master thesis workflow for Internet-wide service measurement.
The goal is to measure exposed non-web services in Norwegian IPv4 space, extract service
fingerprints, and generate reproducible summary statistics for analysis.

### Scope

- Target space: Norwegian IPv4 CIDR whitelist (`data/norway_ipv4_whitelist.txt`)
- Services/ports: FTP (21), SSH (22), DNS (53), VNC (5900)
- Output focus: open counts, protocol/banner fingerprints, and per-run comparison data

### Pipeline (high level)

1. `zmap_scan_all.py` discovers responsive hosts per configured port.
2. `grab_nonweb_banners.py` / `grab_dns_banners.py` collect service fingerprint data.
3. Results are stored in `nonweb_banners.sqlite`.
4. `report_nonweb.py` generates `nonweb_report.txt` for human-readable analysis.

### Methodology boundaries

- Default pipeline does **not** perform credential login attempts.
- FTP check uses `USER anonymous` pre-check only (no `PASS` submission).
- SSH auth-method probing is optional/legal-gated (`userauth none` only).

## Current default behavior (`zmap_scan_all.py`)

Running without extra flags:

```bash
sudo python zmap_scan_all.py
```

uses:

- ports: `21,22,53,5900`
- passes: `2`
- bandwidth: `10M`
- DNS mode on port 53: UDP probe with RD enabled
- full postprocess pipeline: enabled (banner grab + SQLite + report)

This default is a balanced profile (better stability than high-rate scans, shorter than 3-pass runs).

## Recommended scan profiles

### 1) Balanced default (recommended for regular runs)

```bash
sudo python zmap_scan_all.py
```

### 2) High-coverage thesis run (stronger coverage, slower)

```bash
sudo python zmap_scan_all.py --bandwidth 8M --passes 3 --seed 1 --seed-step 1000
```

Use this for final thesis result snapshots.

### 3) Fast validation run (small sample)

```bash
sudo python zmap_scan_all.py --max-ips-total 200000 --passes 1 --seed 1
```

## Output location

Each run creates:

- `data/scans/<RUN_ID>/summary.txt`
- `data/scans/<RUN_ID>/nonweb_report.txt`
- `data/scans/<RUN_ID>/nonweb_banners.sqlite`
- `data/scans/<RUN_ID>/open_21.txt`, `open_22.txt`, `open_53.txt`, `open_5900.txt`

`data/scans/latest` points to the most recent run directory.

## Regenerate report from existing SQLite

```bash
python report_nonweb.py --sqlite data/scans/latest/nonweb_banners.sqlite --out data/scans/latest/nonweb_report.txt
```

This does not run a new scan. It only rebuilds the text report from existing DB data.

## FTP/SSH methodology boundaries

- FTP anonymous check in report means: `USER anonymous` only, no `PASS` submission.
- SSH auth probe (optional) uses `userauth none`, no credential login.
- Credential login attempts are not performed by default pipeline.

## Reproducibility guidance for thesis

Do at least 2 repeated full runs with the same command on different times/days, then report per-port variation (min/max/avg open counts).
