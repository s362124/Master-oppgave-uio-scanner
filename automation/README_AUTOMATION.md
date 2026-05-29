# Automation Setup

This project includes:
- `run_nonweb.sh` for lock-safe scheduled runs with logging
- `automation/systemd/nonweb-scan.service` + `automation/systemd/nonweb-scan.timer` for systemd scheduling

## 1) Wrapper script behavior

`run_nonweb.sh`:
- runs `zmap_scan_all.py --full-pipeline`
- writes logs to `data/logs/nonweb_pipeline.log`
- prevents overlapping runs via lock file in `data/locks/`
- when called with `--auto-alternate-profiles`, alternates between:
- `high_coverage`: `--bandwidth 8M --passes 3 --seed 1 --seed-step 1000 --zmap-pass-timeout-sec 12000`
- `balanced`: `--bandwidth 10M --passes 2 --seed 1 --seed-step 1000`
- stores next scheduled profile in `data/automation/nonweb_profile_state.txt`

## 2) Systemd timer setup (Linux)

1. Copy unit files:
   - `sudo cp automation/systemd/nonweb-scan.service /etc/systemd/system/`
   - `sudo cp automation/systemd/nonweb-scan.timer /etc/systemd/system/`
2. Edit `/etc/systemd/system/nonweb-scan.service`:
   - set `User=...`
   - set `WorkingDirectory=...`
   - set `ExecStart=...`
3. Enable timer:
   - `sudo systemctl daemon-reload`
   - `sudo systemctl enable --now nonweb-scan.timer`
4. Check status:
   - `systemctl status nonweb-scan.timer`
   - `journalctl -u nonweb-scan.service -n 100 --no-pager`

## 3) Recommended cadence

Default automation cadence in this repository is every 8 hours.
If full runs are very long, daily scheduling is also acceptable.
The scheduled templates alternate between `high_coverage` and `balanced` runs on each invocation.
