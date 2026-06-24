type:: project
status:: active
tags:: #banshee #wifi #security #cyberdeck
updated:: 2026-06-24

# Banshee

> Flask web UI wrapping aircrack-ng suite for WiFi security testing on the Cyberdeck.
> Auto-synced to Logseq · managed by Claude · source: Projects/banshee/banshee.md

## State

| **Label** | Value |
|-----------|-------|
| Status | Active — all attack paths end-to-end verified |
| Port | 5200 |
| Host | Cyberdeck (Rock 5B, 100.97.104.107) |
| Adapter | RTL8812AU (`wlxe84e06a00bc4`) |
| Wordlists | Multi-select bubble UI; rockyou.txt default (`/usr/share/wordlists/`) |
| UX | Action Deck + capture self-inspection; cracking blocked unless capture/hash verifies |
| Saves | Saved captures can be inspected on demand; new saves write `.json` metadata sidecars |
| Venv | `~/Projects/banshee/venv/` |

## Access

| | |
|--|--|
| UI | `http://localhost:5200` (via Launcher tile) |
| SSH | `ssh slofi@100.97.104.107` |
| Service | `systemctl --user start/stop/restart banshee` |

## Quick Commands

Start manually:
```bash
cd ~/Projects/banshee && venv/bin/python app.py
```

Check logs:
```bash
journalctl --user -u banshee -f
```

Reset monitor mode manually:
```bash
sudo ip link set wlxe84e06a00bc4 down
sudo iw reg set SI
sudo iw dev wlxe84e06a00bc4 set type monitor
sudo ip link set wlxe84e06a00bc4 up
```

Restore managed mode:
```bash
sudo ip link set wlxe84e06a00bc4 down
sudo iw dev wlxe84e06a00bc4 set type managed
sudo ip link set wlxe84e06a00bc4 up
sudo nmcli device set wlxe84e06a00bc4 managed yes
```

## Key Paths

| | |
|--|--|
| App | `~/Projects/banshee/app.py` |
| Frontend | `~/Projects/banshee/static/` |
| Template | `~/Projects/banshee/templates/index.html` |
| Service | `~/.config/systemd/user/banshee.service` |
| Sudoers | `/etc/sudoers.d/banshee` |
| Scan tmp | `/tmp/banshee_scan-*.csv` |
| Cap tmp | `/tmp/banshee_cap_TIMESTAMP-*.cap` (per-session prefix) |
| GitHub | `https://github.com/Slofi/banshee` |

## Pending

- `sudo apt install seclists` — not in standard Armbian repos; use sparse git clone instead (see Remarks). Already have seclists via previous install on CD.

## Remarks

- **Evil Twin — second RTL8812AU needed first.** Evil Twin requires two simultaneous adapters: one for the fake AP, one for continuous deauth + monitoring. Current single-adapter workaround would be unreliable. Get second RTL8812AU + USB extension cable (30-50cm for RF separation) before starting implementation. USB tethering covers internet for the fake AP (no second WiFi needed for uplink). Will also need: `hostapd`, `dnsmasq`, `iptables`, captive portal page.

## Changelog

- **2026-06-24** — Codex UX/autonomy pass: Capture tab now has an Action Deck that summarizes selected AP, channel, observed clients, and WPS state, then offers direct `Capture`, `Force HS`, `PMKID`, and `WPS` actions. Banshee now self-inspects captures: WPA `.cap` files are verified with `aircrack-ng`; PMKID `.pcapng` files are verified with `hcxpcapngtool`. `/api/capture/status`, `/api/pmkid/status`, `/api/saves`, and `/api/capture/inspect` expose validation metadata (`valid`, quality level, label, size/details). UI shows inspection status and saved-file quality badges. Crack start is guarded client-side and server-side so unverified WPA captures do not launch cracking. Verified with Python compile, JS syntax check, and Flask test-client checks; live RTL8812AU capture path still needs CD validation.
- **2026-06-24** — Claude audit follow-up: capture status now avoids the redundant second `aircrack-ng` inspection after handshake confirmation, and PMKID cracking no longer builds a shell-quoted `bash -c` wordlist command; combined wordlists are prepared in Python and `hashcat` is launched with argv.
- **2026-06-24** — Saves inspection/metadata pass: new WPA/PMKID saves now write sidecar `.json` metadata with SSID/BSSID/channel/privacy, save method, timestamp, path, and validation result. Saves tab has an `Inspect` action that validates old `.cap`/`.pcapng` files on demand, updates the sidecar, refreshes quality badges, and mirrors the result into the Action Deck inspection line.
- **2026-06-24** — GitHub save checkpoint: initialized local Git repository, connected `origin` to `git@github.com:Slofi/banshee.git`, added app source/static/templates/notes/curated wordlists with `.gitignore` excluding venv, captures, generated hash/crack outputs, and generated `top-candidates.txt`. Pushed `main` at commit `6872872` (`Initial Banshee app with capture validation UX`). Working tree clean after push.
- **2026-05-29** — Built from scratch: Flask backend wrapping aircrack-ng (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng). 4-tab UI: Scan, Attack, Capture, Crack. Dark/amber theme matching CD stack.
- **2026-05-29** — Launcher tile added (`~/launcher/app.py`), banshee.service created
- **2026-05-29** — Monitor mode fix: bypassed airmon-ng, using `iw dev set type monitor` directly (RTL8812AU driver quirk — doesn't rename interface or report type monitor in iw dev)
- **2026-05-29** — NM unmanage on monitor enable, re-manage on disable (prevents channel lock)
- **2026-05-29** — Regulatory domain set to SI on monitor enable (unlocks 5GHz channels)
- **2026-05-29** — UI: zoom slider + accent colour picker (burger menu), custom toast notifications replacing browser alerts, frontend state sync with backend mode
- **2026-05-29** — 5GHz fix: RTL8812AU driver exposes ~60 non-standard frequencies; airodump-ng was spending near-zero time on actual 5GHz channels. Fix: explicit `--channel` list (38 real WiFi channels, 2.4+5GHz) in scan command. Verified ch149 now visible.
- **2026-05-29** — Handshake detection fix: was checking for 'handshake' in aircrack-ng stdout (wrong). Correct: `'potential targets' in out and '0 potential targets' not in out`
- **2026-05-29** — Capture state sync fix: `capturing` field now based on actual process poll(), not mode string. Deauth no longer breaks handshake polling.
- **2026-05-29** — Per-session cap file isolation: timestamp prefix (`banshee_cap_TIMESTAMP`) per capture session. Prevents root-owned old files from contaminating handshake detection. Startup cleans old files.
- **2026-05-29** — Handshake file locking: `state['handshake_file']` locked in at detection time; always used for cracking regardless of later cap file changes.
- **2026-05-29** — Stale crack cap fix: `loadCrackSaves()` now syncs hidden `crack-capfile` input to dropdown value on load.
- **2026-05-29** — Wordlist multi-select bubble UI: dropdown + bubble tags with ✕, multiple lists joined with comma for aircrack-ng `-w`. Scans WORDLIST_DIRS for available lists.
- **2026-05-29** — Handshake banner ✕ button: resets capture state, lets user capture fresh handshake. Banner reappears when new one detected.
- **2026-05-29** — Signal strength colorization in Scan tab: ≥-50dBm green, -50 to -70 amber, <-70 red.
- **2026-05-29** — End-to-end test complete: scan → select AP → capture → natural handshake (Testbox reconnect) → save → crack (rockyou.txt, runs correctly, MH 15-char random password not in wordlist as expected)
- **2026-05-29** — PMKID capture panel added: hcxdumptool 6.x (`-w`, `-c 149b`, `-p` flags); hcxpcapngtool validates hash count; save as .pcapng; feeds into Crack tab
- **2026-05-29** — PMKID cracking: crack_start detects .pcapng → hcxpcapngtool converts to .hc22000 → hashcat -m 22000. aircrack-ng cannot crack PMKID. hashcat installed (`sudo apt install hashcat`). End-to-end verified: 1 hash captured from "Mostly Harmless" phone hotspot (ch149), rockyou-35 ran in 4s, not found as expected.
- **2026-05-29** — WPS scan: wash 8s scan, WPS badge (green=open, amber=locked) per AP in Scan tab
- **2026-05-29** — WPS / Pixie Dust: reaver -K 1 + pixiewps installed (`sudo apt install pixiewps`). End-to-end verified: pixiewps ran, phone hotspot not vulnerable (correct result). sudoers: `/etc/sudoers.d/banshee-hcx` covers hcxdumptool + reaver + wash.
- **2026-05-29** — Saves tab: type badge (WPA/PMKID), supports both .cap and .pcapng; Crack dropdown shows file type tag
- **2026-05-29** — ISP wordlist: isp-innbox.txt (1.1M entries, INBOX + 5-6 digits); router-defaults.txt expanded (232 entries, EU ISPs); custom wordlist dir added to WORDLIST_DIRS
- **2026-05-29** — Top Candidates builder: pulls top N from frequency-sorted lists + all entries from small lists; skips ISP sequential files; writes to wordlists/top-candidates.txt
- **2026-05-29** — Restart + Shut Down controls added to burger menu
- **2026-05-29** — Crack elapsed timer: JS ticks MM:SS while cracking active, shows "Finished in MM:SS" on completion
- **2026-05-29** — Scan tab target bar: amber bar above AP table shows selected SSID + BSSID; row highlight BSSID matching fixed (vendor text no longer breaks match)

---
---
# ////// FULL REFERENCE //////

## Architecture

Single Flask app, subprocess-based. No database — state lives in a Python dict protected by `threading.Lock`.

**Backend routes:**
- `/api/interface/monitor` POST — enable monitor mode (nmcli unmanage → ip down → iw reg SI → iw monitor → ip up)
- `/api/interface/managed` POST — restore managed mode (ip down → iw managed → ip up → nmcli manage)
- `/api/interface/status` GET — returns monitor_mode, mon_iface, mode, capturing
- `/api/scan/start` POST — launches airodump-ng, clears old /tmp/banshee_scan-* files
- `/api/scan/stop` POST — kills airodump-ng process group
- `/api/scan/results` GET — parses latest airodump CSV, returns APs + clients
- `/api/target` POST/GET — set/get selected AP
- `/api/attack/deauth` POST — launches aireplay-ng deauth
- `/api/attack/stop` POST — kills aireplay-ng
- `/api/capture/start` POST — launches airodump-ng targeted at one BSSID+channel, per-session cap_prefix with timestamp
- `/api/capture/stop` POST — kills capture
- `/api/capture/status` GET — handshake detection via aircrack-ng check (outside lock), cap file path (locked in at detection)
- `/api/capture/reset-handshake` POST — resets handshake state + file, lets user capture again
- `/api/capture/saves` GET — lists saved cap files with path field
- `/api/capture/save` POST — saves cap file to ~/captures/
- `/api/capture/delete` POST — deletes saved cap file
- `/api/wordlists` GET — scans WORDLIST_DIRS, returns name/path/size/group sorted rockyou-first
- `/api/wordlist/build-top` POST — builds top-candidates.txt from all lists
- `/api/crack/start` POST — accepts `wordlists` array, joins with comma for aircrack-ng `-w list1,list2`; also accepts `.pcapng` for PMKID cracking
- `/api/crack/stop` POST — kills crack
- `/api/crack/status` GET — returns log lines (last 60) + result
- `/api/pmkid/start` POST — launches hcxdumptool 6.x: `sudo hcxdumptool -i mon -w file.pcapng -c CHb -p` (b=5GHz band suffix, a=2.4GHz)
- `/api/pmkid/stop` POST — kills hcxdumptool
- `/api/pmkid/status` GET — running flag, PMKID hash count (via hcxpcapngtool, only when stopped), file size during capture
- `/api/pmkid/save` POST — copies tmp pcapng to ~/Projects/banshee/captures/
- `/api/wps/scan` POST — runs wash 8s in background, populates wps_data dict
- `/api/wps/data` GET — returns wps_data dict (bssid → {wps, locked, vendor})
- `/api/wps/start` POST — launches reaver -K 1 (Pixie Dust) against selected BSSID
- `/api/wps/stop` POST — kills reaver
- `/api/wps/status` GET — running flag, result (found:PIN:PSK / not_found), log lines (last 40)
- `/api/system/restart` POST — systemctl --user restart banshee (delayed 0.5s)
- `/api/system/stop` POST — systemctl --user stop banshee

**WORDLIST_DIRS** (scanned for wordlist bubble selector):
```
/usr/share/wordlists                              → group: wordlists
/usr/share/seclists/Passwords                     → group: seclists/Passwords
/usr/share/seclists/Passwords/Common-Credentials  → group: seclists/Common
/usr/share/seclists/Passwords/Leaked-Databases    → group: seclists/Leaked
```

**Handshake detection logic:**
```python
r = subprocess.run(['aircrack-ng', '--bssid', bssid, cap_file],
    capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=8)
return 'potential targets' in r.stdout.lower() and '0 potential targets' not in r.stdout.lower()
```
(aircrack-ng outputs "N potential targets", NOT the word "handshake")

**Process management:** All subprocesses use `preexec_fn=os.setsid` for process group. Kill via `os.killpg(os.getpgid(pid), SIGTERM)`.

## RTL8812AU Driver Notes

- Driver: 88XXau (compiled from source for kernel 6.18, patched)
- Does NOT rename interface on monitor enable (stays `wlxe84e06a00bc4`)
- Does NOT report `type monitor` in `iw dev` even when in monitor mode
- airmon-ng reports "monitor mode enabled" but NM/wpa_supplicant interfere with channel hopping
- Fix: bypass airmon-ng, use `iw dev set type monitor` directly + `nmcli device set managed no`
- Regulatory domain defaults to `country 99` (generic) — 5GHz channels need `iw reg set SI` to be accessible

## Sudoers

`/etc/sudoers.d/banshee`:
```
slofi ALL=(ALL) NOPASSWD: /usr/local/sbin/airmon-ng
slofi ALL=(ALL) NOPASSWD: /usr/local/sbin/airodump-ng
slofi ALL=(ALL) NOPASSWD: /usr/local/sbin/aireplay-ng
slofi ALL=(ALL) NOPASSWD: /usr/bin/nmcli
slofi ALL=(ALL) NOPASSWD: /usr/sbin/iw
slofi ALL=(ALL) NOPASSWD: /usr/sbin/ip
```

`/etc/sudoers.d/banshee-hcx`:
```
slofi ALL=(ALL) NOPASSWD: /usr/bin/hcxdumptool
slofi ALL=(ALL) NOPASSWD: /usr/bin/reaver
slofi ALL=(ALL) NOPASSWD: /usr/bin/wash
```

## Important Workflow Notes

- **Internet on CD during Banshee use:** Requires USB tethering (phone → CD via USB cable). WiFi adapter is exclusively for Banshee when in monitor mode.
- **Hotspot SSID "Mostly Harmless"** = Filip's phone hotspot (not the Pi). Strong signal when phone is next to CD.
- **5GHz scanning:** Driver exposes ~60 non-standard frequencies; airodump-ng default hop visits ch149 almost never. Fix: explicit `--channel` list in scan_start() covering all real 2.4+5GHz channels. Reg domain (`iw reg set SI`) is set on monitor enable but turned out not to be the root cause — country 99 already covers ch149.
