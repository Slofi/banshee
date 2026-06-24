'use strict';

// ── Toast ─────────────────────────────────────────────────────────
function toast(msg, isError = false) {
    const el = document.createElement('div');
    el.className = 'toast' + (isError ? ' error' : '');
    el.textContent = msg;
    document.getElementById('toast-container').appendChild(el);
    requestAnimationFrame(() => { el.classList.add('show'); });
    setTimeout(() => {
        el.classList.remove('show');
        setTimeout(() => el.remove(), 220);
    }, 3000);
}

// ── State ─────────────────────────────────────────────────────────
const s = {
    monitoring:        false,
    scanning:          false,
    capturing:         false,
    cracking:          false,
    selectedAP:        null,
    handshakeCaptured: false,
    captureFile:       null,
    lastValidation:    null,
};

let scanInterval    = null;
let captureInterval = null;
let crackInterval   = null;
let pmkidInterval   = null;
let pmkidFile       = null;
let wpsInterval     = null;
let crackTimerInterval = null;
let crackStartTime     = null;
let lastAPs         = [];
let lastClients     = [];
let apSort          = { col: 'power', dir: -1 };
let clientSort      = { col: 'power', dir: -1 };

const TH_LABELS        = { essid: 'SSID', bssid: 'BSSID', channel: 'CH', power: 'Signal', privacy: 'Privacy' };
const CLIENT_TH_LABELS = { mac: 'MAC', bssid: 'BSSID', power: 'Signal', packets: 'Pkts', probed: 'Probed SSIDs' };

function setSortCol(col) {
    if (apSort.col === col) {
        apSort.dir *= -1;
    } else {
        apSort.col = col;
        apSort.dir = (col === 'power' || col === 'channel') ? -1 : 1;
    }
    renderAPs(lastAPs);
}

function sortedAPs(aps) {
    return [...aps].sort((a, b) => {
        let av = a[apSort.col], bv = b[apSort.col];
        if (apSort.col === 'power' || apSort.col === 'channel') {
            av = parseFloat(av) || 0;
            bv = parseFloat(bv) || 0;
        } else {
            av = String(av || '').toLowerCase();
            bv = String(bv || '').toLowerCase();
        }
        if (av < bv) return -apSort.dir;
        if (av > bv) return apSort.dir;
        return 0;
    });
}

function updateSortHeaders() {
    for (const [col, label] of Object.entries(TH_LABELS)) {
        const th = document.getElementById('th-' + col);
        if (!th) continue;
        const arrow = apSort.col === col ? (apSort.dir === 1 ? ' ↑' : ' ↓') : '';
        th.textContent = label + arrow;
        th.classList.toggle('sort-active', apSort.col === col);
    }
}

function setClientSortCol(col) {
    if (clientSort.col === col) {
        clientSort.dir *= -1;
    } else {
        clientSort.col = col;
        clientSort.dir = (col === 'power' || col === 'packets') ? -1 : 1;
    }
    renderClients(lastClients);
}

function sortedClients(clients) {
    return [...clients].sort((a, b) => {
        let av = a[clientSort.col], bv = b[clientSort.col];
        if (clientSort.col === 'power' || clientSort.col === 'packets') {
            av = parseFloat(av) || 0;
            bv = parseFloat(bv) || 0;
        } else {
            av = String(av || '').toLowerCase();
            bv = String(bv || '').toLowerCase();
        }
        if (av < bv) return -clientSort.dir;
        if (av > bv) return clientSort.dir;
        return 0;
    });
}

function updateClientSortHeaders() {
    for (const [col, label] of Object.entries(CLIENT_TH_LABELS)) {
        const th = document.getElementById('cth-' + col);
        if (!th) continue;
        const arrow = clientSort.col === col ? (clientSort.dir === 1 ? ' ↑' : ' ↓') : '';
        th.textContent = label + arrow;
        th.classList.toggle('sort-active', clientSort.col === col);
    }
}

function selectAPByBSSID(bssid) {
    const ap = lastAPs.find(a => a.bssid === bssid);
    if (ap) selectAP(ap);
}

function getTargetClients() {
    const bssid = (s.selectedAP || {}).bssid;
    return bssid ? lastClients.filter(c => c.bssid === bssid) : [];
}

// ── Client context menu ───────────────────────────────────────────
let clientMenuData = null;

function showClientMenu(e, c) {
    e.stopPropagation();
    clientMenuData = c;
    const menu = document.getElementById('client-menu');
    const ap = lastAPs.find(a => a.bssid === c.bssid);
    const apLabel = ap ? (ap.essid || ap.bssid) : c.bssid;

    document.getElementById('cm-mac').textContent    = c.mac;
    document.getElementById('cm-vendor').textContent = c.vendor || '—';
    document.getElementById('cm-ap').textContent     = apLabel || '(not associated)';

    const linked = c.bssid && c.bssid !== '(not associated)' && c.bssid.length === 17;
    document.getElementById('cm-select-ap').style.display      = linked ? '' : 'none';
    document.getElementById('cm-deauth').style.display         = linked ? '' : 'none';
    document.getElementById('cm-deauth-capture').style.display = linked ? '' : 'none';

    // Position near click — use getBoundingClientRect for real viewport dimensions (zoom-safe)
    menu.style.left = '0';
    menu.style.top  = '0';
    menu.style.display = 'block';
    const rect = menu.getBoundingClientRect();
    const mw = rect.width  || 220;
    const mh = rect.height || 180;
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    let x = e.clientX + 8;
    let y = e.clientY + 8;
    if (x + mw > vw - 4) x = e.clientX - mw - 8;
    if (y + mh > vh - 4) y = e.clientY - mh - 8;
    x = Math.max(4, Math.min(vw - mw - 4, x));
    y = Math.max(4, Math.min(vh - mh - 4, y));
    menu.style.left = x + 'px';
    menu.style.top  = y + 'px';
}

function closeClientMenu() {
    document.getElementById('client-menu').style.display = 'none';
    clientMenuData = null;
}

function cmSelectAP() {
    if (clientMenuData) selectAPByBSSID(clientMenuData.bssid);
    closeClientMenu();
}

function cmCopyMAC() {
    if (!clientMenuData) return;
    navigator.clipboard.writeText(clientMenuData.mac).then(() => {
        toast('MAC copied: ' + clientMenuData.mac);
    });
    closeClientMenu();
}

async function cmDeauth() {
    if (!clientMenuData) return;
    const c = clientMenuData;
    closeClientMenu();
    const ap = lastAPs.find(a => a.bssid === c.bssid);
    if (ap) await selectAP(ap);
    const r = await post('/api/attack/deauth', { client: c.mac, count: 5 });
    if (r.ok) toast(`Deauth sent to ${c.mac}`);
    else toast(r.error || 'Deauth failed', true);
}

async function cmDeauthCapture() {
    if (!clientMenuData) return;
    const c = clientMenuData;
    closeClientMenu();
    const ap = lastAPs.find(a => a.bssid === c.bssid);
    if (!ap) { toast('AP not found in scan', true); return; }
    await selectAP(ap);
    // Start capture first, then deauth to force handshake
    const rc = await post('/api/capture/start');
    if (!rc.ok) { toast(rc.error || 'Failed to start capture', true); return; }
    // Sync frontend capture state so pollCapture starts
    s.capturing = true;
    const btnCap = document.getElementById('btn-capture');
    if (btnCap) { btnCap.textContent = 'Stop Capture'; btnCap.classList.add('active'); }
    if (!captureInterval) captureInterval = setInterval(pollCapture, 3000);
    toast(`Capturing on ${ap.essid || ap.bssid} — deauthing ${c.mac}...`);
    await new Promise(r => setTimeout(r, 1500));
    await post('/api/attack/deauth', { client: c.mac, count: 5 });
    // Switch to Capture tab so user can watch for handshake
    const captureBtn = document.querySelector('.tab[onclick*="capture"]');
    if (captureBtn) showTab('capture', captureBtn);
}

// ── API ───────────────────────────────────────────────────────────
function post(url, data = {}) {
    return fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    }).then(r => r.json()).catch(e => ({ ok: false, error: String(e) }));
}

function get(url) {
    return fetch(url).then(r => r.json()).catch(() => ({}));
}

async function inspectCaptureFile(capFile) {
    if (!capFile) return null;
    const validation = await post('/api/capture/inspect', {
        cap_file: capFile,
        bssid: (s.selectedAP || {}).bssid || document.getElementById('crack-bssid')?.value || '',
    });
    renderValidation(validation);
    return validation;
}

// ── Tabs ──────────────────────────────────────────────────────────
function showTab(name, btn) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
    btn.classList.add('active');
    renderTargetCards();
    updateActionDeck();
    if (name === 'crack') { loadCrackSaves(); loadWordlists(); }
}

// ── Dots / labels ─────────────────────────────────────────────────
function dot(id, color) {
    const el = document.getElementById(id);
    if (el) el.className = 'dot' + (color ? ' ' + color : '');
}

function label(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

// ── Signal bar ────────────────────────────────────────────────────
function pwrBar(pwr) {
    const val = parseInt(pwr);
    if (isNaN(val) || val > -2) return '<span class="pwr-bar"></span>';
    const pct = Math.round(Math.max(2, Math.min(100, ((val + 100) / 70) * 100)));
    const color = val >= -50 ? '#22c55e' : val >= -70 ? '#f59e0b' : '#ef4444';
    return `<span class="pwr-bar" style="background:linear-gradient(to right,${color} ${pct}%,#2a2a2a ${pct}%)"></span>`;
}

// ── Monitor toggle ────────────────────────────────────────────────
async function toggleMonitor() {
    const btn = document.getElementById('btn-monitor');
    btn.disabled = true;
    btn.textContent = '...';
    if (s.monitoring) {
        await post('/api/interface/managed');
    } else {
        await post('/api/interface/monitor');
    }
    await refreshStatus();
    btn.disabled = false;
}

async function refreshStatus() {
    const data = await get('/api/interface/status');
    s.monitoring = data.monitor_mode || false;
    const btn = document.getElementById('btn-monitor');
    if (s.monitoring) {
        dot('dot-monitor', 'green');
        label('label-mode', 'monitor: ' + (data.mon_iface || ''));
        btn.textContent = 'Monitor ON';
        btn.classList.add('active');
    } else {
        dot('dot-monitor', '');
        label('label-mode', 'managed');
        btn.textContent = 'Monitor OFF';
        btn.classList.remove('active');
    }
    // Sync scan state — backend may be scanning without the UI knowing
    const mode = data.mode || 'idle';
    const btnScan = document.getElementById('btn-scan');
    if (mode === 'scanning' && !s.scanning) {
        s.scanning = true;
        btnScan.textContent = 'Stop Scan';
        btnScan.classList.add('active');
        if (!scanInterval) {
            setTimeout(pollScan, 500);
            scanInterval = setInterval(pollScan, 3500);
        }
    } else if (mode !== 'scanning' && s.scanning) {
        s.scanning = false;
        btnScan.textContent = 'Start Scan';
        btnScan.classList.remove('active');
        clearInterval(scanInterval);
        scanInterval = null;
    }
    // Sync capture state — backend may be capturing without the UI knowing
    const backendCapturing = data.capturing || false;
    const btnCap = document.getElementById('btn-capture');
    if (backendCapturing && !s.capturing) {
        s.capturing = true;
        if (btnCap) { btnCap.textContent = 'Stop Capture'; btnCap.classList.add('active'); }
        if (!captureInterval) captureInterval = setInterval(pollCapture, 3000);
    } else if (!backendCapturing && s.capturing) {
        s.capturing = false;
        if (btnCap) { btnCap.textContent = 'Start Capture'; btnCap.classList.remove('active'); }
        clearInterval(captureInterval);
        captureInterval = null;
    }
    updateActionDeck();
}

// ── Scan ──────────────────────────────────────────────────────────
async function toggleScan() {
    const btn = document.getElementById('btn-scan');
    if (s.scanning) {
        await post('/api/scan/stop');
        s.scanning = false;
        btn.textContent = 'Start Scan';
        btn.classList.remove('active');
        clearInterval(scanInterval);
        scanInterval = null;
    } else {
        if (!s.monitoring) { toast('Enable monitor mode first.', true); return; }
        const r = await post('/api/scan/start');
        if (!r.ok) { toast(r.error || 'Failed to start scan', true); return; }
        s.scanning = true;
        btn.textContent = 'Stop Scan';
        btn.classList.add('active');
        setTimeout(pollScan, 2000);
        scanInterval = setInterval(pollScan, 3500);
    }
}

async function pollScan() {
    const data = await get('/api/scan/results');
    lastAPs     = data.aps     || [];
    lastClients = data.clients || [];
    renderAPs(lastAPs);
    renderClients(lastClients);
    updateDeauthClientList();
    updateActionDeck();
}

function renderAPs(aps) {
    const tbody = document.getElementById('ap-tbody');
    if (!aps.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty">Scanning for networks...</td></tr>';
        updateSortHeaders();
        return;
    }
    tbody.innerHTML = sortedAPs(aps).map(ap => {
        const isSel  = s.selectedAP && s.selectedAP.bssid === ap.bssid ? 'selected' : '';
        const essid  = ap.essid || '<hidden>';
        const apJson = JSON.stringify(ap);
        const vendor = ap.vendor ? `<br><span class="vendor">${escHtml(ap.vendor)}</span>` : '';
        const cc = lastClients.filter(c => c.bssid === ap.bssid).length;
        const clientBadge = cc > 0 ? `<span class="client-count">${cc}</span>` : '';
        const wps = ap.wps;
        const wpsBadge = wps
            ? `<span class="wps-scan-badge ${wps.locked ? 'locked' : 'open'}">${wps.locked ? 'WPS⚿' : 'WPS'}</span>`
            : '';
        return `<tr class="ap-row ${isSel}" onclick='selectAP(${apJson.replace(/'/g,"&#39;")})'>
            <td>${escHtml(essid)}${clientBadge}${wpsBadge}</td>
            <td style="color:var(--text-dim)">${ap.bssid}${vendor}</td>
            <td>${ap.channel}</td>
            <td>${pwrBar(ap.power)}${ap.power}</td>
            <td>${ap.privacy}</td>
        </tr>`;
    }).join('');
    updateSortHeaders();
}

function renderClients(clients) {
    const tbody = document.getElementById('client-tbody');
    if (!clients.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty">No clients detected</td></tr>';
        updateClientSortHeaders();
        return;
    }
    tbody.innerHTML = sortedClients(clients).map(c => {
        const cJson = JSON.stringify(c).replace(/'/g, "&#39;");
        const cvendor = c.vendor ? `<br><span class="vendor">${escHtml(c.vendor)}</span>` : '';
        return `<tr class="client-row clickable" onclick='showClientMenu(event, ${cJson})'>
            <td>${c.mac}${cvendor}</td>
            <td style="color:var(--text-dim)">${c.bssid}</td>
            <td>${pwrBar(c.power)}${c.power}</td>
            <td>${c.packets}</td>
            <td style="color:var(--text-dim)">${escHtml(c.probed)}</td>
        </tr>`;
    }).join('');
    updateClientSortHeaders();
}

function escHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

async function selectAP(ap) {
    s.selectedAP = ap;
    await post('/api/target', ap);
    // update highlight without full re-render
    document.querySelectorAll('.ap-row').forEach(row => row.classList.remove('selected'));
    // find the row by BSSID text and select it
    document.querySelectorAll('.ap-row').forEach(row => {
        if (row.cells[1] && row.cells[1].textContent.trim().split('\n')[0].trim() === ap.bssid) {
            row.classList.add('selected');
        }
    });
    renderTargetCards();
    updateDeauthClientList();
    updateWPSBadge();
    updateActionDeck();
    // auto-fill crack form
    document.getElementById('crack-bssid').value   = ap.bssid;
}

function renderTargetCards() {
    const html = s.selectedAP
        ? `<div class="target-info">
            <div class="target-field">
                <span class="target-label">SSID</span>
                <span class="target-value">${escHtml(s.selectedAP.essid || '<hidden>')}</span>
            </div>
            <div class="target-field">
                <span class="target-label">BSSID</span>
                <span class="target-value">${s.selectedAP.bssid}</span>
            </div>
            <div class="target-field">
                <span class="target-label">Channel</span>
                <span class="target-value">${s.selectedAP.channel}</span>
            </div>
            <div class="target-field">
                <span class="target-label">Privacy</span>
                <span class="target-value">${s.selectedAP.privacy}</span>
            </div>
           </div>`
        : '<span class="empty">No target — select an AP from the Scan tab</span>';
    document.getElementById('capture-target').innerHTML = html;
    const bar = document.getElementById('scan-target-bar');
    if (bar) {
        if (s.selectedAP) {
            bar.textContent = `Target: ${s.selectedAP.essid || '<hidden>'} — ${s.selectedAP.bssid}`;
            bar.className = 'scan-target-bar';
        } else {
            bar.className = 'scan-target-bar hidden';
        }
    }
    updateActionDeck();
}

function updateActionDeck() {
    const nameEl = document.getElementById('action-target-name');
    if (!nameEl) return;
    const chEl = document.getElementById('action-target-channel');
    const clientsEl = document.getElementById('action-target-clients');
    const wpsEl = document.getElementById('action-target-wps');
    const readyEl = document.getElementById('action-ready');
    const hintEl = document.getElementById('action-hint');
    const target = s.selectedAP;
    const clients = getTargetClients();
    const ready = Boolean(target && s.monitoring);

    nameEl.textContent = target ? (target.essid || '<hidden>') : 'No target';
    chEl.textContent = target ? target.channel : '—';
    clientsEl.textContent = String(clients.length);
    if (!target || !target.wps) wpsEl.textContent = 'unknown';
    else wpsEl.textContent = target.wps.locked ? 'locked' : 'open';

    if (readyEl) {
        readyEl.textContent = ready ? 'ready' : (target ? 'monitor off' : 'no target');
        readyEl.className = ready ? 'panel-hint ready' : 'panel-hint';
    }
    if (hintEl) {
        if (!target) hintEl.textContent = 'Pick an AP in Scan, then come back here.';
        else if (!s.monitoring) hintEl.textContent = 'Turn monitor mode on to unlock actions.';
        else if (clients.length) hintEl.textContent = `${clients.length} client${clients.length === 1 ? '' : 's'} seen. Force HS can target a live client.`;
        else hintEl.textContent = 'No clients seen. PMKID is the cleanest first try.';
    }

    ['quick-capture', 'quick-force', 'quick-pmkid', 'quick-wps'].forEach((id) => {
        const btn = document.getElementById(id);
        if (btn) btn.disabled = !ready;
    });
}

function renderValidation(validation) {
    const el = document.getElementById('action-inspect');
    if (!el || !validation) return;
    const details = (validation.details || []).filter(Boolean).join(' · ');
    el.className = 'inspect-line ' + (validation.level || 'unknown');
    el.textContent = details ? `${validation.label} · ${details}` : validation.label;
    s.lastValidation = validation;
}

// ── Deauth ────────────────────────────────────────────────────────
function updateDeauthClientList() {
    const sel  = document.getElementById('cap-deauth-client');
    const warn = document.getElementById('cap-no-clients');
    if (!sel) return;
    const bssid = (s.selectedAP || {}).bssid;
    const apClients = bssid
        ? lastClients.filter(c => c.bssid === bssid)
        : [];
    sel.innerHTML = '<option value="FF:FF:FF:FF:FF:FF">All clients (broadcast)</option>';
    apClients.forEach(c => {
        const opt = document.createElement('option');
        opt.value = c.mac;
        opt.textContent = c.vendor ? `${c.mac}  (${c.vendor})` : c.mac;
        sel.appendChild(opt);
    });
    if (warn) warn.style.display = apClients.length === 0 ? '' : 'none';
}

async function sendDeauth() {
    if (!s.selectedAP) { toast('Select a target AP in the Scan tab first.', true); return; }
    if (!s.monitoring)  { toast('Enable monitor mode first.', true); return; }
    if (!s.capturing)   { toast('Tip: start capture first so the handshake gets recorded.', false); }
    const client = document.getElementById('cap-deauth-client').value;
    const count  = parseInt(document.getElementById('cap-deauth-count').value) || 0;
    const r = await post('/api/attack/deauth', { bssid: s.selectedAP.bssid, client, count });
    const el = document.getElementById('deauth-status');
    if (r.ok) {
        el.textContent = count === 0
            ? `Continuous deauth → ${s.selectedAP.essid || s.selectedAP.bssid}...`
            : `Sent ${count} packets → ${client === 'FF:FF:FF:FF:FF:FF' ? 'all clients' : client}`;
        el.style.color = 'var(--accent)';
    } else {
        el.textContent = 'Error: ' + (r.error || 'unknown');
        el.style.color = 'var(--red)';
    }
}

async function quickCapture() {
    if (!s.selectedAP) { toast('Select a target AP in the Scan tab first.', true); return; }
    if (!s.monitoring)  { toast('Enable monitor mode first.', true); return; }
    if (!s.capturing) await toggleCapture();
    const captureBtn = document.querySelector('.tab[onclick*="capture"]');
    if (captureBtn) showTab('capture', captureBtn);
}

async function quickForceHandshake() {
    if (!s.selectedAP) { toast('Select a target AP in the Scan tab first.', true); return; }
    if (!s.monitoring)  { toast('Enable monitor mode first.', true); return; }
    if (!s.capturing) {
        await quickCapture();
        if (!s.capturing) return;
        await new Promise(r => setTimeout(r, 1200));
    }
    const clients = getTargetClients();
    const client = clients[0]?.mac || 'FF:FF:FF:FF:FF:FF';
    document.getElementById('cap-deauth-client').value = client;
    document.getElementById('cap-deauth-count').value = clients.length ? 5 : 8;
    await sendDeauth();
    toast(clients.length ? `Capturing + deauthing ${client}` : 'Capturing + broadcast deauth');
}

async function stopAttack() {
    await post('/api/attack/stop');
    const el = document.getElementById('deauth-status');
    if (el) { el.textContent = 'Stopped.'; el.style.color = 'var(--text-dim)'; }
}

// ── Capture ───────────────────────────────────────────────────────
async function toggleCapture() {
    const btn = document.getElementById('btn-capture');
    if (s.capturing) {
        await post('/api/capture/stop');
        s.capturing = false;
        btn.textContent = 'Start Capture';
        btn.classList.remove('active');
        clearInterval(captureInterval);
        captureInterval = null;
    } else {
        if (!s.selectedAP) { toast('Select a target AP in the Scan tab first.', true); return; }
        if (!s.monitoring)  { toast('Enable monitor mode first.', true); return; }
        const r = await post('/api/capture/start', {
            bssid:   s.selectedAP.bssid,
            channel: s.selectedAP.channel,
        });
        if (!r.ok) { toast(r.error || 'Failed to start capture', true); return; }
        s.capturing          = true;
        s.handshakeCaptured  = false;
        btn.textContent = 'Stop Capture';
        btn.classList.add('active');
        setHandshakeUI(false);
        captureInterval = setInterval(pollCapture, 3000);
    }
}

async function pollCapture() {
    const data = await get('/api/capture/status');
    if (data.cap_file) {
        s.captureFile = data.cap_file;
        document.getElementById('cap-file').textContent = 'File: ' + data.cap_file;
        document.getElementById('crack-capfile').value  = data.cap_file;
        // Enable save as soon as we have any capture data, not just on handshake
        document.getElementById('btn-save-cap').disabled = false;
    }
    if (data.validation) renderValidation(data.validation);
    if (data.handshake && !s.handshakeCaptured) {
        s.handshakeCaptured = true;
        setHandshakeUI(true);
        toast('Verified handshake captured');
    }
    // Stop polling if backend stopped capture externally (e.g. auto-stop on handshake)
    if (!data.capturing && s.capturing) {
        s.capturing = false;
        const btn = document.getElementById('btn-capture');
        if (btn) {
            btn.textContent = 'Start Capture';
            btn.classList.remove('active');
            // Keep disabled if handshake is captured — user must reset first
            if (!s.handshakeCaptured) btn.disabled = false;
        }
        clearInterval(captureInterval);
        captureInterval = null;
    }
}

function setHandshakeUI(captured) {
    const el    = document.getElementById('handshake-status');
    const btnCap = document.getElementById('btn-capture');
    if (captured) {
        el.className = 'handshake-indicator captured';
        el.innerHTML = '<span class="hs-icon">&#10003;</span><span class="hs-label">HANDSHAKE CAPTURED — auto-saved</span><button class="hs-reset" onclick="resetHandshake()" title="Reset — capture again">✕</button>';
        if (btnCap) { btnCap.disabled = true; btnCap.title = 'Reset handshake first'; }
    } else {
        el.className = 'handshake-indicator';
        el.innerHTML = '<span class="hs-icon">&#9675;</span><span class="hs-label">Waiting for handshake...</span>';
        if (btnCap) { btnCap.disabled = false; btnCap.title = ''; }
    }
}

async function resetHandshake() {
    await post('/api/capture/reset-handshake');
    s.handshakeCaptured = false;
    setHandshakeUI(false);
    document.getElementById('btn-save-cap').disabled = true;
    document.getElementById('cap-file').textContent  = '';
}

// ── Wordlist bubbles ──────────────────────────────────────────────
let selectedWordlists = [];

async function loadWordlists() {
    const sel = document.getElementById('wordlist-select');
    if (!sel) return;
    const data = await get('/api/wordlists');
    const currentPaths = selectedWordlists.map(w => w.path);
    // Auto-select rockyou if nothing selected yet
    if (selectedWordlists.length === 0 && data && data.length > 0) {
        const rky = data.find(w => w.name === 'rockyou.txt');
        if (rky) { selectedWordlists.push({ name: rky.name, path: rky.path }); renderWordlistBubbles(); }
    }
    let lastGroup = null;
    sel.innerHTML = '<option value="">Add wordlist...</option>';
    (data || []).forEach(w => {
        if (currentPaths.includes(w.path)) return;
        if (w.group !== lastGroup) {
            const og = document.createElement('optgroup');
            og.label = w.group;
            sel.appendChild(og);
            lastGroup = w.group;
        }
        const size = w.size < 1048576
            ? (w.size / 1024).toFixed(0) + ' KB'
            : (w.size / 1048576).toFixed(1) + ' MB';
        const opt = document.createElement('option');
        opt.value = w.path;
        opt.dataset.name = w.name;
        opt.textContent = `${w.name.replace(/\.(txt|lst)$/i, '')} (${size})`;
        sel.lastElementChild.appendChild(opt);
    });
}

function addWordlistFromSelect(sel) {
    if (!sel.value) return;
    const opt = sel.options[sel.selectedIndex];
    addWordlist(sel.value, opt.dataset.name || opt.textContent);
    sel.value = '';
    loadWordlists();
}

function addWordlist(path, name) {
    if (selectedWordlists.find(w => w.path === path)) return;
    selectedWordlists.push({ path, name });
    renderWordlistBubbles();
}

function removeWordlist(path) {
    selectedWordlists = selectedWordlists.filter(w => w.path !== path);
    renderWordlistBubbles();
    loadWordlists();
}

function renderWordlistBubbles() {
    const c = document.getElementById('wordlist-bubbles');
    if (!c) return;
    c.innerHTML = selectedWordlists.map(w => {
        const safePath = w.path.replace(/'/g, "\\'");
        const display  = escHtml(w.name.replace(/\.(txt|lst)$/i, ''));
        return `<span class="wordlist-bubble">${display}<button class="bubble-x" onclick="removeWordlist('${safePath}')" title="Remove">✕</button></span>`;
    }).join('');
}

function getSelectedWordlists() {
    return selectedWordlists.map(w => w.path);
}

async function buildTopCandidates() {
    const btn    = document.getElementById('btn-build-top');
    const status = document.getElementById('top-candidates-status');
    const n      = Math.max(100, Math.min(10000, parseInt(document.getElementById('top-n-input').value) || 1000));
    btn.disabled = true;
    status.textContent = 'Building…';
    try {
        const r = await fetch('/api/wordlist/build-top', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ top_n: n }),
        });
        const d = await r.json();
        if (d.ok) {
            status.textContent = `${d.count.toLocaleString()} passwords`;
            await loadWordlists();
            // Auto-add the generated file as a bubble
            addWordlist(d.path, 'top-candidates.txt');
        } else {
            status.textContent = 'Failed: ' + (d.error || '?');
        }
    } catch (e) {
        status.textContent = 'Error';
    }
    btn.disabled = false;
}

// ── Crack saves dropdown ──────────────────────────────────────────
async function loadCrackSaves() {
    const sel = document.getElementById('crack-save-select');
    if (!sel) return;
    const current = sel.value;
    const data = await get('/api/saves');
    sel.innerHTML = '<option value="">— current capture —</option>';
    (data || []).forEach(f => {
        const d = new Date(f.modified * 1000);
        const lbl = d.toLocaleString('en-GB', { day:'2-digit', month:'2-digit',
            hour:'2-digit', minute:'2-digit' }).replace(',','');
        const size = f.size < 1024 ? f.size + ' B' : (f.size / 1024).toFixed(0) + ' KB';
        const typeTag = f.type === 'pmkid' ? '[PMKID] ' : '';
        const opt = document.createElement('option');
        opt.value = f.path;
        opt.textContent = `${lbl} — ${typeTag}${f.name.replace(/\.(cap|pcapng)$/, '')} (${size})`;
        if (f.path === current) opt.selected = true;
        sel.appendChild(opt);
    });
    // Always sync the hidden input to whatever is now selected
    document.getElementById('crack-capfile').value = sel.value;
}

function onCrackSaveSelect(sel) {
    document.getElementById('crack-capfile').value = sel.value;
}

// ── Crack timer ───────────────────────────────────────────────────
function startCrackTimer() {
    crackStartTime = Date.now();
    const el = document.getElementById('crack-elapsed');
    el.className = 'status-line';
    clearInterval(crackTimerInterval);
    crackTimerInterval = setInterval(() => {
        const secs = Math.floor((Date.now() - crackStartTime) / 1000);
        const m = String(Math.floor(secs / 60)).padStart(2, '0');
        const s = String(secs % 60).padStart(2, '0');
        el.textContent = `Running… ${m}:${s}`;
    }, 1000);
}
function stopCrackTimer() {
    clearInterval(crackTimerInterval);
    crackTimerInterval = null;
    const el = document.getElementById('crack-elapsed');
    if (el && crackStartTime) {
        const secs = Math.floor((Date.now() - crackStartTime) / 1000);
        const m = String(Math.floor(secs / 60)).padStart(2, '0');
        const s = String(secs % 60).padStart(2, '0');
        el.textContent = `Finished in ${m}:${s}`;
    }
}

// ── Crack ─────────────────────────────────────────────────────────
async function toggleCrack() {
    const btn = document.getElementById('btn-crack');
    if (s.cracking) {
        await post('/api/crack/stop');
        s.cracking = false;
        btn.textContent = 'Start Crack';
        btn.classList.remove('active');
        clearInterval(crackInterval);
        crackInterval = null;
        stopCrackTimer();
        return;
    }
    let capFile = document.getElementById('crack-capfile').value.trim();
    if (!capFile) capFile = s.captureFile || '';
    if (!capFile) { toast('No capture file — run a capture first or select a saved one.', true); return; }
    const validation = await inspectCaptureFile(capFile);
    if (validation && validation.valid === false) {
        toast(validation.label || 'Capture is not verified yet.', true);
        return;
    }
    const wordlists = getSelectedWordlists();
    if (!wordlists.length) { toast('Add at least one wordlist.', true); return; }
    const bssid = document.getElementById('crack-bssid').value.trim();

    document.getElementById('crack-result').className = 'crack-result hidden';
    document.getElementById('crack-log').textContent  = '';
    document.getElementById('crack-elapsed').className = 'status-line hidden';

    const r = await post('/api/crack/start', { cap_file: capFile, wordlists, bssid });
    if (!r.ok) { toast(r.error || 'Failed to start', true); return; }
    s.cracking = true;
    btn.textContent = 'Stop';
    btn.classList.add('active');
    startCrackTimer();
    crackInterval = setInterval(pollCrack, 2000);
}

async function pollCrack() {
    const data = await get('/api/crack/status');
    const logEl = document.getElementById('crack-log');
    if (data.log && data.log.length) {
        logEl.textContent = data.log.join('\n');
        logEl.scrollTop   = logEl.scrollHeight;
    }
    const resultEl = document.getElementById('crack-result');
    if (data.result && data.result !== 'running') {
        if (data.result.startsWith('found:')) {
            resultEl.className   = 'crack-result found';
            resultEl.textContent = 'KEY FOUND: ' + data.result.replace('found:', '').trim();
        } else {
            resultEl.className   = 'crack-result not-found';
            resultEl.textContent = 'Key not found in wordlist';
        }
        if (!data.cracking) {
            s.cracking = false;
            document.getElementById('btn-crack').textContent = 'Start Crack';
            document.getElementById('btn-crack').classList.remove('active');
            clearInterval(crackInterval);
            crackInterval = null;
            stopCrackTimer();
        }
    }
}

// ── Saves ─────────────────────────────────────────────────────────
async function saveCapture() {
    const r = await post('/api/capture/save');
    if (r.ok) {
        toast('Saved: ' + r.file);
    } else {
        toast(r.error || 'Save failed', true);
    }
}

async function loadSaves() {
    const tbody = document.getElementById('saves-tbody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="5" class="empty">Loading...</td></tr>';
    const data = await get('/api/saves');
    if (!data.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty">No saved captures</td></tr>';
        return;
    }
    tbody.innerHTML = data.map(f => {
        const date = new Date(f.modified * 1000).toLocaleString();
        const size = f.size < 1024 ? f.size + ' B' : (f.size / 1024).toFixed(1) + ' KB';
        const name = escHtml(f.name);
        const safePath = escHtml(f.path).replace(/'/g, "&#39;");
        const safeName = escHtml(f.name).replace(/'/g, "&#39;");
        const typeBadge = f.type === 'pmkid'
            ? '<span class="save-type pmkid">PMKID</span>'
            : '<span class="save-type wpa">WPA</span>';
        const v = f.validation || {};
        const quality = `<span class="save-quality ${v.level || 'unknown'}">${escHtml(v.label || 'Saved')}</span>`;
        const crackBtn = f.type !== 'pmkid'
            ? `<button class="btn btn-primary btn-sm" onclick="crackSave('${safeName}','${safePath}')">Crack</button>`
            : `<button class="btn btn-primary btn-sm" onclick="crackSave('${safeName}','${safePath}')">Crack</button>`;
        const inspectBtn = `<button class="btn btn-secondary btn-sm" onclick="inspectSave('${safeName}')">Inspect</button>`;
        return `<tr>
            <td style="font-family:monospace;font-size:11px">${name}</td>
            <td>${typeBadge} ${quality}</td>
            <td style="color:var(--text-dim)">${size}</td>
            <td style="color:var(--text-dim)">${date}</td>
            <td>
                ${crackBtn}
                ${inspectBtn}
                <button class="btn btn-danger btn-sm" onclick="deleteSave('${safeName}')">Delete</button>
            </td>
        </tr>`;
    }).join('');
}

async function deleteSave(filename) {
    if (!confirm('Delete ' + filename + '?')) return;
    const r = await fetch('/api/saves/' + encodeURIComponent(filename), { method: 'DELETE' });
    const data = await r.json().catch(() => ({}));
    if (data.ok) {
        toast('Deleted: ' + filename);
        loadSaves();
    } else {
        toast(data.error || 'Delete failed', true);
    }
}

async function inspectSave(filename) {
    const r = await post('/api/saves/' + encodeURIComponent(filename) + '/inspect');
    if (r.ok) {
        renderValidation(r.validation);
        toast(r.validation?.label || 'Inspection complete');
        await loadSaves();
    } else {
        toast(r.error || 'Inspect failed', true);
    }
}

async function crackSave(filename, capFile) {
    if (!capFile) capFile = '/home/slofi/Projects/banshee/captures/' + filename; // fallback
    // Switch to Crack tab
    const crackBtn = document.querySelector('.tab[onclick*="crack"]');
    if (crackBtn) showTab('crack', crackBtn);
    // Load dropdown and select this file
    await loadCrackSaves();
    document.getElementById('crack-capfile').value = capFile;
    const sel = document.getElementById('crack-save-select');
    if (sel) sel.value = capFile;
    const wordlists = getSelectedWordlists();
    if (!wordlists.length) wordlists.push('/usr/share/wordlists/rockyou.txt');
    const bssid = (s.selectedAP || {}).bssid || '';
    const validation = await inspectCaptureFile(capFile);
    if (validation && validation.valid === false) {
        toast(validation.label || 'Capture is not verified yet.', true);
        return;
    }
    const r = await post('/api/crack/start', { cap_file: capFile, wordlists, bssid });
    if (r.ok) {
        toast('Cracking ' + filename + '...');
        s.cracking = true;
        document.getElementById('btn-crack').textContent = 'Stop Crack';
        document.getElementById('btn-crack').classList.add('active');
        if (!crackInterval) crackInterval = setInterval(pollCrack, 2000);
    } else {
        toast(r.error || 'Crack failed', true);
    }
}

// ── WPS scan ──────────────────────────────────────────────────────
async function scanWPS() {
    const btn = document.getElementById('btn-wps-scan');
    if (!s.monitoring) { toast('Enable monitor mode first.', true); return; }
    btn.disabled = true;
    btn.textContent = 'Scanning…';
    const r = await post('/api/wps/scan');
    if (!r.ok) {
        toast(r.error || 'WPS scan failed', true);
        btn.disabled = false;
        btn.textContent = 'Scan WPS';
        return;
    }
    // wash runs for 8 seconds; poll results after 9s
    setTimeout(async () => {
        const data = await get('/api/scan/results');
        if (data.aps) { lastAPs = data.aps; renderAPs(lastAPs); }
        updateWPSBadge();
        btn.disabled = false;
        btn.textContent = 'Scan WPS';
        toast('WPS scan complete');
    }, 9000);
}

function updateWPSBadge() {
    const badge = document.getElementById('wps-target-badge');
    if (!badge) return;
    if (!s.selectedAP) { badge.textContent = ''; badge.className = 'wps-badge'; return; }
    const wps = s.selectedAP.wps;
    if (!wps)              { badge.textContent = 'WPS: unknown'; badge.className = 'wps-badge dim'; }
    else if (wps.locked)   { badge.textContent = 'WPS: LOCKED';  badge.className = 'wps-badge warn'; }
    else                   { badge.textContent = 'WPS: ON';       badge.className = 'wps-badge on'; }
}

// ── PMKID ─────────────────────────────────────────────────────────
async function togglePmkid() {
    const btn = document.getElementById('btn-pmkid');
    if (pmkidInterval) {
        // Stop
        await post('/api/pmkid/stop');
        clearInterval(pmkidInterval);
        pmkidInterval = null;
        btn.textContent = 'Start PMKID';
        btn.classList.remove('active');
        // Do a final status poll to get count
        await pollPmkid();
        return;
    }
    if (!s.selectedAP) { toast('Select a target AP in the Scan tab first.', true); return; }
    if (!s.monitoring)  { toast('Enable monitor mode first.', true); return; }
    const r = await post('/api/pmkid/start');
    if (!r.ok) { toast(r.error || 'Failed to start PMKID capture', true); return; }
    pmkidFile = null;
    setPmkidUI('running', 0, null);
    btn.textContent = 'Stop PMKID';
    btn.classList.add('active');
    document.getElementById('btn-save-pmkid').disabled  = true;
    document.getElementById('btn-crack-pmkid').disabled = true;
    pmkidInterval = setInterval(pollPmkid, 2000);
    pollPmkid();
}

async function pollPmkid() {
    const data = await get('/api/pmkid/status');
    if (data.file) pmkidFile = data.file;
    setPmkidUI(data.running ? 'running' : (data.count > 0 ? 'found' : 'idle'),
               data.count || 0, data.file || null, data.size || 0);
    if (data.validation) renderValidation(data.validation);
    if (!data.running && pmkidInterval) {
        clearInterval(pmkidInterval);
        pmkidInterval = null;
        const btn = document.getElementById('btn-pmkid');
        if (btn) { btn.textContent = 'Start PMKID'; btn.classList.remove('active'); }
    }
}

function setPmkidUI(uiState, count, file, size) {
    const el     = document.getElementById('pmkid-status');
    const fileEl = document.getElementById('pmkid-file');
    const savBtn = document.getElementById('btn-save-pmkid');
    const crkBtn = document.getElementById('btn-crack-pmkid');
    if (!el) return;

    if (uiState === 'running') {
        const kb = size ? ` · ${(size/1024).toFixed(1)} KB` : '';
        el.className = 'handshake-indicator';
        el.innerHTML = `<span class="hs-icon">&#9675;</span><span class="hs-label">Capturing PMKID…${kb}</span><span id="pmkid-count-badge" class="pmkid-count hidden"></span>`;
    } else if (uiState === 'found') {
        const label = count + ' hash' + (count !== 1 ? 'es' : '');
        el.className = 'handshake-indicator captured';
        el.innerHTML = `<span class="hs-icon">&#10003;</span><span class="hs-label">PMKID captured</span><span id="pmkid-count-badge" class="pmkid-count">${label}</span>`;
        if (savBtn) savBtn.disabled = false;
        if (crkBtn) crkBtn.disabled = false;
    } else {
        el.className = 'handshake-indicator';
        el.innerHTML = `<span class="hs-icon">&#9675;</span><span class="hs-label">Idle</span><span id="pmkid-count-badge" class="pmkid-count hidden"></span>`;
    }
    if (fileEl) fileEl.textContent = file ? 'File: ' + file : '';
}

async function savePmkid() {
    const r = await post('/api/pmkid/save');
    if (r.ok) {
        toast('Saved: ' + r.file);
        pmkidFile = r.path;
    } else {
        toast(r.error || 'Save failed', true);
    }
}

async function sendPmkidToCrack() {
    if (!pmkidFile) { toast('No PMKID file available.', true); return; }
    // Switch to Crack tab and populate the cap file field
    const crackBtn = document.querySelector('.tab[onclick*="crack"]');
    if (crackBtn) showTab('crack', crackBtn);
    await loadCrackSaves();
    document.getElementById('crack-capfile').value = pmkidFile;
    const sel = document.getElementById('crack-save-select');
    if (sel) sel.value = pmkidFile;
    toast('PMKID file loaded in Crack tab');
}

// ── WPS / Pixie Dust ──────────────────────────────────────────────
async function toggleWPS() {
    const btn = document.getElementById('btn-wps');
    if (wpsInterval) {
        await stopWPS();
        return;
    }
    if (!s.selectedAP) { toast('Select a target AP in the Scan tab first.', true); return; }
    if (!s.monitoring)  { toast('Enable monitor mode first.', true); return; }
    const r = await post('/api/wps/start');
    if (!r.ok) { toast(r.error || 'Failed to start WPS attack', true); return; }
    document.getElementById('wps-result').className = 'crack-result hidden';
    document.getElementById('wps-log').textContent  = '';
    btn.textContent = 'Stop';
    btn.classList.add('active');
    wpsInterval = setInterval(pollWPS, 2000);
}

async function stopWPS() {
    await post('/api/wps/stop');
    clearInterval(wpsInterval);
    wpsInterval = null;
    const btn = document.getElementById('btn-wps');
    if (btn) { btn.textContent = 'Start Pixie Dust'; btn.classList.remove('active'); }
}

async function pollWPS() {
    const data = await get('/api/wps/status');
    if (data.log && data.log.length) {
        const logEl = document.getElementById('wps-log');
        logEl.textContent = data.log.join('\n');
        logEl.scrollTop   = logEl.scrollHeight;
    }
    if (data.result && data.result !== 'running') {
        const resultEl = document.getElementById('wps-result');
        if (data.result.startsWith('found:')) {
            const parts = data.result.split(':');
            const pin = parts[1] || '?';
            const psk = parts.slice(2).join(':') || '?';
            resultEl.className   = 'crack-result found';
            resultEl.textContent = `PIN: ${pin}  |  PSK: ${psk}`;
        } else {
            resultEl.className   = 'crack-result not-found';
            resultEl.textContent = 'WPS Pixie Dust not successful — router may not be vulnerable';
        }
        if (!data.running) {
            clearInterval(wpsInterval);
            wpsInterval = null;
            const btn = document.getElementById('btn-wps');
            if (btn) { btn.textContent = 'Start Pixie Dust'; btn.classList.remove('active'); }
        }
    }
}

// ── Burger ────────────────────────────────────────────────────────
function toggleBurger() {
    document.getElementById('burger-panel').classList.toggle('open');
}
function closeBurger() {
    document.getElementById('burger-panel').classList.remove('open');
}
document.addEventListener('click', function(e) {
    const panel = document.getElementById('burger-panel');
    if (panel.classList.contains('open') &&
        !panel.contains(e.target) &&
        !document.getElementById('burger-btn').contains(e.target)) {
        closeBurger();
    }
    const menu = document.getElementById('client-menu');
    if (menu && menu.style.display !== 'none' && !menu.contains(e.target)) {
        closeClientMenu();
    }
});

// ── UI Zoom ───────────────────────────────────────────────────────
const DEFAULT_ACCENT = '#f59e0b';

function getUiZoom() {
    return parseInt(document.getElementById('ui-zoom-slider').value) || 100;
}
function setUiZoom(val) {
    val = Math.min(150, Math.max(70, parseInt(val) || 100));
    document.body.style.zoom = val + '%';
    document.body.style.height = (10000 / val).toFixed(2) + 'vh';
    const slider = document.getElementById('ui-zoom-slider');
    if (slider) slider.value = val;
    const display = document.getElementById('ui-zoom-display');
    if (display) display.textContent = val + '%';
    localStorage.setItem('bansheeUiZoom', val);
}
function loadUiZoom() {
    const saved = parseInt(localStorage.getItem('bansheeUiZoom'));
    if (saved) setUiZoom(saved);
}

// ── Accent Colour ─────────────────────────────────────────────────
function _hexToHsl(hex) {
    const r = parseInt(hex.slice(1,3),16)/255, g = parseInt(hex.slice(3,5),16)/255, b = parseInt(hex.slice(5,7),16)/255;
    const max = Math.max(r,g,b), min = Math.min(r,g,b);
    let h=0, s=0, l=(max+min)/2;
    if (max !== min) {
        const d = max - min;
        s = l > 0.5 ? d/(2-max-min) : d/(max+min);
        switch(max) {
            case r: h=((g-b)/d+(g<b?6:0))/6; break;
            case g: h=((b-r)/d+2)/6; break;
            case b: h=((r-g)/d+4)/6; break;
        }
    }
    return [Math.round(h*360), Math.round(s*100), Math.round(l*100)];
}
function _hslToHex(h, s, l) {
    s/=100; l/=100;
    const a = s*Math.min(l,1-l);
    const f = n => { const k=(n+h/30)%12, c=l-a*Math.max(Math.min(k-3,9-k,1),-1); return Math.round(255*c).toString(16).padStart(2,'0'); };
    return `#${f(0)}${f(8)}${f(4)}`;
}
function _hexToRgb(hex) {
    return [parseInt(hex.slice(1,3),16), parseInt(hex.slice(3,5),16), parseInt(hex.slice(5,7),16)];
}

function applyAccentColor(hex) {
    if (!/^#[0-9a-fA-F]{6}$/.test(hex)) return;
    const [h, s, l] = _hexToHsl(hex);
    const accentL   = Math.max(l, 45);
    const accentHex = _hslToHex(h, s, accentL);
    const [r, g, b] = _hexToRgb(accentHex);
    const root = document.documentElement;
    root.style.setProperty('--accent',       accentHex);
    root.style.setProperty('--accent-faint', `rgba(${r},${g},${b},0.10)`);
    root.style.setProperty('--accent-mid',   `rgba(${r},${g},${b},0.30)`);
    root.style.setProperty('--accent-bg',    `rgba(${r},${g},${b},0.07)`);
    root.style.setProperty('--accent-muted', _hslToHex(h, Math.round(s*0.6), Math.round(accentL*0.65)));
    const sw = document.getElementById('accent-swatch');
    if (sw) sw.style.background = accentHex;
}
function loadAccentColor() {
    const saved = localStorage.getItem('bansheeAccentColor');
    if (saved) applyAccentColor(saved);
}

let _pendingAccent = null;
const ACCENT_PRESETS = [
    '#f59e0b','#deaf4a','#fb923c','#f87171',
    '#e879f9','#a78bfa','#60a5fa','#34d399',
    '#4ade80','#a3e635','#facc15','#94a3b8',
    '#e2e8f0','#f8fafc',
];

function openAccentPicker() {
    closeBurger();
    _pendingAccent = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim();
    const grid = document.getElementById('accent-preset-grid');
    grid.innerHTML = ACCENT_PRESETS.map(c =>
        `<div class="accent-preset${c.toLowerCase()===_pendingAccent.toLowerCase()?' selected':''}"
             style="background:${c}" title="${c}"
             onclick="selectAccentPreset('${c}')"></div>`
    ).join('');
    document.getElementById('accent-custom-input').value = _pendingAccent;
    document.getElementById('accent-hex-display').textContent = _pendingAccent;
    document.getElementById('accent-picker-overlay').classList.add('show');
}
function closeAccentPicker() {
    if (_pendingAccent) {
        applyAccentColor(_pendingAccent);
        _pendingAccent = null;
    }
    document.getElementById('accent-picker-overlay').classList.remove('show');
}
function selectAccentPreset(hex) {
    document.querySelectorAll('.accent-preset').forEach(p => p.classList.remove('selected'));
    event.target.classList.add('selected');
    document.getElementById('accent-custom-input').value = hex;
    document.getElementById('accent-hex-display').textContent = hex;
    applyAccentColor(hex);
}
function previewAccent(hex) {
    document.getElementById('accent-hex-display').textContent = hex;
    if (/^#[0-9a-fA-F]{6}$/.test(hex)) applyAccentColor(hex);
}
function confirmAccentColor() {
    const hex = document.getElementById('accent-custom-input').value;
    if (!/^#[0-9a-fA-F]{6}$/.test(hex)) return;
    applyAccentColor(hex);
    localStorage.setItem('bansheeAccentColor', hex);
    _pendingAccent = null;
    document.getElementById('accent-picker-overlay').classList.remove('show');
}
function resetAccentColor() {
    applyAccentColor(DEFAULT_ACCENT);
    localStorage.removeItem('bansheeAccentColor');
    const sw = document.getElementById('accent-swatch');
    if (sw) sw.style.background = DEFAULT_ACCENT;
}

// ── App control ───────────────────────────────────────────────────
async function bansheeRestart() {
    closeBurger();
    toast('Restarting…');
    await fetch('/api/system/restart', { method: 'POST' }).catch(() => {});
    setTimeout(() => location.reload(), 4000);
}

async function bansheeStop() {
    if (!confirm('Shut down Banshee?')) return;
    closeBurger();
    await fetch('/api/system/stop', { method: 'POST' }).catch(() => {});
    document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:monospace;color:#6b7280;font-size:14px">Banshee stopped.</div>';
}

// ── Init ──────────────────────────────────────────────────────────
async function init() {
    await refreshStatus();
    renderTargetCards();
    loadUiZoom();
    loadAccentColor();
    setInterval(refreshStatus, 15000);
}

init();
