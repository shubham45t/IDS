/* ── SENTINEL IDS — APP.JS ── */

const scheme   = window.location.protocol === 'https:' ? 'https' : 'http';
const wsScheme = window.location.protocol === 'https:' ? 'wss'   : 'ws';
const API_URL  = `${scheme}://${window.location.hostname}:8000`;
const WS_URL   = `${wsScheme}://${window.location.hostname}:8000/ws/alerts`;

let severityChart, timelineChart;
let feedPaused = false;
let feedFilter = 'all';
let timelineFilter = 'all';
let allAlerts = [];
let demoInterval = null;
let wsConnection = null;

// ── Boot Sequence ──────────────────────────────────────────────
const bootMessages = [
    'LOADING KERNEL MODULES...',
    'INITIALIZING PACKET SNIFFER...',
    'BINDING NETWORK INTERFACES...',
    'LOADING THREAT SIGNATURES...',
    'STARTING WEBSOCKET SERVER...',
    'CONNECTING TO BACKEND API...',
    'SENTINEL IDS ONLINE ✓'
];

function runBoot() {
    const bar = document.getElementById('boot-bar');
    const status = document.getElementById('boot-status');
    let step = 0;
    const total = bootMessages.length;

    const interval = setInterval(() => {
        if (step >= total) {
            clearInterval(interval);
            setTimeout(() => {
                document.getElementById('boot-screen').style.transition = 'opacity .6s';
                document.getElementById('boot-screen').style.opacity = '0';
                setTimeout(() => {
                    document.getElementById('boot-screen').style.display = 'none';
                    document.getElementById('app').style.display = 'flex';
                    document.getElementById('app').style.animation = 'fadeSlideUp .5s ease';
                    initDashboard();
                    startClock();
                    initParticles();
                    animateAttackBars();
                    buildGeoGrid();
                }, 600);
            }, 400);
            return;
        }
        status.textContent = bootMessages[step];
        bar.style.width = `${((step + 1) / total) * 100}%`;
        step++;
    }, 280);
}

// ── Clock ──────────────────────────────────────────────────────
function startClock() {
    function tick() {
        const now = new Date();
        document.getElementById('clock').textContent = now.toTimeString().slice(0, 8);
        document.getElementById('clock-date').textContent = now.toLocaleDateString('en-GB').replace(/\//g, '/');
    }
    tick();
    setInterval(tick, 1000);
}

// ── Particles ─────────────────────────────────────────────────
function initParticles() {
    const canvas = document.getElementById('particles-canvas');
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });

    const dots = Array.from({ length: 60 }, () => ({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        r: Math.random() * 1.5 + 0.3,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        color: Math.random() > 0.5 ? '#00d4ff' : '#00ff88'
    }));

    function draw() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        dots.forEach(d => {
            d.x += d.vx;
            d.y += d.vy;

            if (d.x < 0) d.x = canvas.width;
            if (d.x > canvas.width) d.x = 0;
            if (d.y < 0) d.y = canvas.height;
            if (d.y > canvas.height) d.y = 0;

            ctx.beginPath();
            ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
            ctx.fillStyle = d.color;
            ctx.fill();
        });

        for (let i = 0; i < dots.length; i++) {
            for (let j = i + 1; j < dots.length; j++) {
                const dist = Math.hypot(dots[i].x - dots[j].x, dots[i].y - dots[j].y);
                if (dist < 120) {
                    ctx.beginPath();
                    ctx.moveTo(dots[i].x, dots[i].y);
                    ctx.lineTo(dots[j].x, dots[j].y);
                    ctx.strokeStyle = `rgba(0,212,255,${0.08 * (1 - dist / 120)})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }
        }

        requestAnimationFrame(draw);
    }

    draw();
}

// ── Geo Grid ──────────────────────────────────────────────────
function buildGeoGrid() {
    const grid = document.getElementById('geo-grid');
    const levels = ['', 'hot1', 'hot2', 'hot3', 'med1', 'med2', ''];
    const weights = [40, 15, 10, 5, 12, 10, 8];

    for (let i = 0; i < 80; i++) {
        const cell = document.createElement('div');
        cell.className = 'geo-cell';

        const r = Math.random() * 100;
        let acc = 0;

        for (let l = 0; l < levels.length; l++) {
            acc += weights[l];
            if (r < acc) {
                if (levels[l]) cell.classList.add(levels[l]);
                break;
            }
        }

        grid.appendChild(cell);
    }

    setInterval(() => {
        const cells = grid.querySelectorAll('.geo-cell');
        const idx = Math.floor(Math.random() * cells.length);
        cells[idx].className = 'geo-cell';
        const lvl = ['', 'hot1', 'hot2', 'hot3'][Math.floor(Math.random() * 4)];
        if (lvl) cells[idx].classList.add(lvl);
    }, 600);
}

// ── Attack Bars ───────────────────────────────────────────────
function animateAttackBars() {
    document.querySelectorAll('.atk-fill').forEach(bar => {
        const target = bar.style.width;
        bar.style.width = '0%';
        setTimeout(() => {
            bar.style.width = target;
        }, 200);
    });
}

// ── Toast Notifications ───────────────────────────────────────
function showToast(msg, type = 'blue') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icons = { red: '🚨', green: '✅', amber: '⚠️', blue: 'ℹ️' };
    toast.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span>${msg}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('toast-out');
        setTimeout(() => toast.remove(), 400);
    }, 4000);
}

// ── Threat Level ──────────────────────────────────────────────
function updateThreatLevel(counts) {
    const crit = counts.CRITICAL || 0;
    const high = counts.HIGH || 0;
    const bars = document.querySelectorAll('.tl-bar');
    const txt = document.getElementById('threat-level-text');

    let active = 1;
    let label = 'LOW';
    let isHigh = false;

    if (crit > 5) {
        active = 5;
        label = 'CRITICAL';
        isHigh = true;
    } else if (crit > 2) {
        active = 4;
        label = 'HIGH';
        isHigh = true;
    } else if (high > 10) {
        active = 3;
        label = 'ELEVATED';
    } else if (high > 3) {
        active = 2;
        label = 'MODERATE';
    }

    bars.forEach((b, i) => {
        b.className = 'tl-bar' + (i < active ? ' active' + (isHigh ? ' high' : '') : '');
    });

    txt.textContent = label;
    txt.style.color = isHigh ? 'var(--glow-red)' : active >= 3 ? 'var(--glow-amber)' : 'var(--glow-green)';
}

// ── Counter Animation ─────────────────────────────────────────
function animateCounter(el, newVal) {
    const oldVal = parseInt(el.textContent) || 0;
    if (oldVal === newVal) return;

    el.classList.remove('num-flash');
    void el.offsetWidth;
    el.classList.add('num-flash');

    let start = null;
    const dur = 600;

    function step(ts) {
        if (!start) start = ts;
        const p = Math.min((ts - start) / dur, 1);
        el.textContent = Math.round(oldVal + (newVal - oldVal) * p);
        if (p < 1) requestAnimationFrame(step);
    }

    requestAnimationFrame(step);
}

// ── Alert Identity / Dedup ────────────────────────────────────
function getAlertKey(alert) {
    return [
        alert.timestamp || '',
        alert.attack_type || '',
        alert.severity || '',
        alert.src_ip || '',
        alert.src_port ?? '',
        alert.dst_ip || '',
        alert.dst_port ?? '',
        alert.details?.reason || ''
    ].join('|');
}

function alertExists(alert) {
    const key = getAlertKey(alert);
    return allAlerts.some(a => getAlertKey(a) === key);
}

// ── Fetch Data ────────────────────────────────────────────────
async function fetchHistory() {
    try {
        const res = await fetch(`${API_URL}/api/alerts`);
        if (!res.ok) throw new Error('Failed to fetch alerts');

        const alerts = await res.json();
        const feed = document.getElementById('live-feed');
        feed.innerHTML = '';

        allAlerts = [];
        alerts.forEach(alert => {
            if (!alertExists(alert)) {
                allAlerts.push(alert);
            }
        });

        allAlerts.slice(-20).forEach(a => appendAlert(a, feed, false));
        return true;
    } catch {
        return false;
    }
}

async function fetchStats() {
    try {
        const res = await fetch(`${API_URL}/api/stats`);
        if (!res.ok) throw new Error('Failed to fetch stats');

        const data = await res.json();
        updateAllStats(data);
        return true;
    } catch {
        return false;
    }
}

// ── Demo Data ─────────────────────────────────────────────────
function loadDemoStats() {
    const demo = {
        total_alerts: 1247,
        severity_counts: { LOW: 543, MEDIUM: 412, HIGH: 218, CRITICAL: 74 },
        blocked_ips: ['45.33.32.156', '192.168.1.99', '10.0.0.78', '103.21.244.0', '198.51.100.4'],
        timeline: generateTimeline(),
        events_per_min: 24
    };
    updateAllStats(demo);
}

function generateTimeline() {
    const tl = [];
    for (let i = 9; i >= 0; i--) {
        const d = new Date();
        d.setMinutes(d.getMinutes() - i);
        tl.push({ time: d.toTimeString().slice(0, 5), count: Math.floor(Math.random() * 30) + 5 });
    }
    return tl;
}

function loadDemoAlerts() {
    const types = ['Port Scan', 'Brute Force / DoS', 'Malicious IP', 'SSH Brute Force', 'HTTP Flood', 'Suspicious Port'];
    const sevs = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const geos = ['US', 'CN', 'RU', 'DE', 'BR', 'IN', 'FR', 'KR'];
    const msgs = [
        'Multiple connection attempts on port 22',
        'Excessive SYN packets detected',
        'Known C2 server communication',
        'Credential stuffing pattern detected',
        'Anomalous HTTP request volume',
        'Unexpected open port access attempt'
    ];

    const feed = document.getElementById('live-feed');
    feed.innerHTML = '';
    allAlerts = [];

    for (let i = 0; i < 12; i++) {
        const t = types[Math.floor(Math.random() * types.length)];
        const s = sevs[Math.floor(Math.random() * sevs.length)];
        const alert = {
            timestamp: new Date(Date.now() - i * 15000).toISOString(),
            attack_type: t,
            severity: s,
            message: msgs[Math.floor(Math.random() * msgs.length)],
            geo: geos[Math.floor(Math.random() * geos.length)],
            src_ip: `${rand(1,254)}.${rand(1,254)}.${rand(1,254)}.${rand(1,254)}`,
            src_port: rand(1024, 65535),
            dst_ip: `10.0.${rand(0,255)}.${rand(1,254)}`,
            dst_port: [22, 80, 443, 3306, 8080][Math.floor(Math.random() * 5)],
            details: { reason: t }
        };

        allAlerts.push(alert);
        appendAlert(alert, feed, false);
    }
}

function rand(a, b) {
    return Math.floor(Math.random() * (b - a + 1)) + a;
}

// ── Update Stats ──────────────────────────────────────────────
function updateAllStats(data) {
    animateCounter(document.getElementById('total-alerts'), data.total_alerts || 0);
    animateCounter(document.getElementById('blocked-count'), data.blocked_ips?.length || 0);
    animateCounter(document.getElementById('events-per-min'), data.events_per_min || 0);

    const crit = data.severity_counts?.CRITICAL || 0;
    const critEl = document.getElementById('critical-alerts');
    animateCounter(critEl, crit);

    document.getElementById('donut-total').textContent = data.total_alerts || 0;

    const sc = data.severity_counts || {};
    ['low', 'med', 'high', 'crit'].forEach((k, i) => {
        const key = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][i];
        document.getElementById(`leg-${k}`).textContent = sc[key] || 0;
    });

    updateSeverityChart(sc);
    updateTimelineChart(data.timeline || generateTimeline());
    updateBlockedList(data.blocked_ips || []);
    updateThreatLevel(sc);
}

// ── Charts ────────────────────────────────────────────────────
function updateSeverityChart(counts) {
    const ctx = document.getElementById('severityChart').getContext('2d');
    const values = [counts.LOW || 0, counts.MEDIUM || 0, counts.HIGH || 0, counts.CRITICAL || 0];

    if (severityChart) {
        severityChart.data.datasets[0].data = values;
        severityChart.update('active');
        return;
    }

    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Low', 'Medium', 'High', 'Critical'],
            datasets: [{
                data: values,
                backgroundColor: ['rgba(59,130,246,.8)', 'rgba(245,158,11,.8)', 'rgba(239,68,68,.8)', 'rgba(185,28,28,.9)'],
                borderColor: ['#3b82f6', '#f59e0b', '#ef4444', '#b91c1c'],
                borderWidth: 2,
                hoverOffset: 8,
                hoverBorderWidth: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '72%',
            animation: { animateRotate: true, duration: 1200 },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#0c1220',
                    borderColor: '#1a2540',
                    borderWidth: 1,
                    titleColor: '#e8f0fe',
                    bodyColor: '#94a3b8',
                    titleFont: { family: 'Orbitron', size: 11 },
                    callbacks: {
                        label: ctx => ` ${ctx.label}: ${ctx.parsed}`
                    }
                }
            }
        }
    });
}

function updateTimelineChart(timeline) {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    const labels = timeline.map(t => t.time);
    const values = timeline.map(t => t.count);

    if (timelineChart) {
        timelineChart.data.labels = labels;
        timelineChart.data.datasets[0].data = values;
        timelineChart.update('active');
        return;
    }

    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: 'Events/Min',
                data: values,
                borderColor: '#ef4444',
                backgroundColor: (ctx) => {
                    const g = ctx.chart.ctx.createLinearGradient(0, 0, 0, 250);
                    g.addColorStop(0, 'rgba(239,68,68,.35)');
                    g.addColorStop(1, 'rgba(239,68,68,.0)');
                    return g;
                },
                borderWidth: 2.5,
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#ef4444',
                pointBorderColor: '#0c1220',
                pointBorderWidth: 2,
                pointRadius: 4,
                pointHoverRadius: 7,
                pointHoverBorderColor: '#ef4444',
                pointHoverBackgroundColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 800 },
            interaction: { intersect: false, mode: 'index' },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#0c1220',
                    borderColor: '#1a2540',
                    borderWidth: 1,
                    titleColor: '#e8f0fe',
                    bodyColor: '#ef4444',
                    callbacks: {
                        title: (i) => `⏱ ${i[0].label}`,
                        label: c => ` Events: ${c.parsed.y}`
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(26,37,64,.8)', drawBorder: false },
                    ticks: { color: '#6888bb', font: { family: 'Share Tech Mono', size: 10 }, stepSize: 5 }
                },
                x: {
                    grid: { color: 'rgba(26,37,64,.4)', drawBorder: false },
                    ticks: { color: '#6888bb', font: { family: 'Share Tech Mono', size: 10 } }
                }
            }
        }
    });
}

// ── Blocked IPs ───────────────────────────────────────────────
function updateBlockedList(ips) {
    const list = document.getElementById('blocked-list');
    animateCounter(document.getElementById('blocked-count'), ips.length);
    list.innerHTML = '';

    if (!ips.length) {
        list.innerHTML = '<div class="no-blocks">✅ No IPs blocked</div>';
        return;
    }

    ips.forEach(ip => {
        const d = document.createElement('div');
        d.className = 'blocked-ip';
        d.textContent = ip;
        list.appendChild(d);
    });
}

// ── WebSocket ─────────────────────────────────────────────────
function setupWebSocket() {
    return new Promise((resolve, reject) => {
        const ws = new WebSocket(WS_URL);
        const feed = document.getElementById('live-feed');
        let opened = false;

        ws.onopen = () => {
            opened = true;
            wsConnection = ws;
            resolve(ws);
        };

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);

            if (data.type === 'update') {
                if (data.alert) {
                    if (!alertExists(data.alert)) {
                        allAlerts.push(data.alert);
                        if (!feedPaused) appendAlert(data.alert, feed, true);
                    }

                    if (data.alert.severity === 'CRITICAL') {
                        showToast(`🚨 CRITICAL: ${data.alert.message}`, 'red');
                    }
                }

                if (data.stats) {
                    updateAllStats(data.stats);
                }
            }
        };

        ws.onerror = () => {
            if (!opened) {
                reject(new Error('WebSocket failed'));
            }
        };

        ws.onclose = () => {
            wsConnection = null;
            setTimeout(() => {
                setupWebSocket().catch(() => {});
            }, 3000);
        };
    });
}

// ── Feed Filter ───────────────────────────────────────────────
function filterFeed(filter) {
    feedFilter = filter;

    ['all', 'crit', 'high'].forEach(f => {
        document.getElementById(`btn-${f === 'all' ? 'all' : f === 'crit' ? 'crit' : 'high'}`)?.classList.remove('active');
    });

    const map = { all: 'btn-all', critical: 'btn-crit', high: 'btn-high' };
    document.getElementById(map[filter])?.classList.add('active');

    const feed = document.getElementById('live-feed');
    feed.innerHTML = '';

    allAlerts.slice(-30).forEach(a => {
        if (filter === 'all' || a.severity?.toLowerCase() === filter) {
            appendAlert(a, feed, false);
        }
    });
}

function filterTimeline(filter) {
    timelineFilter = filter;
    document.querySelectorAll('.panel-controls .ctrl-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    updateTimelineChart(generateTimeline());
}

function togglePause() {
    feedPaused = !feedPaused;
    const btn = document.getElementById('btn-pause');
    btn.textContent = feedPaused ? '▶ RESUME' : '⏸ PAUSE';
    btn.classList.toggle('active', feedPaused);
}

// ── Append Alert ──────────────────────────────────────────────
function appendAlert(alert, feed, prepend = true) {
    const severity = (alert.severity || 'LOW').toLowerCase();
    const attackType = alert.attack_type || 'Unknown';

    if (feedFilter !== 'all' && severity !== feedFilter) return;

    const entry = document.createElement('div');
    entry.className = `log-entry ${severity}`;

    const time = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : '--:--:--';

    const typeClassMap = {
        'Port Scan': 'scan',
        'Brute Force / DoS': 'brute',
        'Malicious IP': 'alert',
        'SSH Brute Force': 'ssh',
        'HTTP Flood': 'http',
        'Suspicious Port': 'sus'
    };

    const typeClass = typeClassMap[attackType] || '';

    entry.innerHTML = `
        <span class="log-timestamp">[${time}]</span>
        <span class="badge ${typeClass}">${attackType}</span>
        <strong>[${alert.severity || 'LOW'}]</strong> ${alert.message || 'Threat Detected'}
        <span class="geo">(${alert.geo || '??'})</span>
        <br/>
        <span class="log-detail">
            SRC: ${alert.src_ip || 'N/A'}:${alert.src_port ?? 'N/A'} →
            DST: ${alert.dst_ip || 'N/A'}:${alert.dst_port ?? 'N/A'} |
            ${alert.details?.reason || attackType}
        </span>`;

    if (prepend) {
        feed.prepend(entry);
    } else {
        feed.appendChild(entry);
    }

    while (feed.children.length > 60) {
        feed.removeChild(feed.lastChild);
    }
}

// ── Simulate Live Events (demo mode only) ─────────────────────
function startDemoSimulation() {
    if (demoInterval) return;

    const types = ['Port Scan', 'Brute Force / DoS', 'Malicious IP', 'SSH Brute Force', 'HTTP Flood', 'Suspicious Port'];
    const sevs = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'LOW', 'LOW', 'MEDIUM', 'HIGH'];
    const geos = ['US', 'CN', 'RU', 'DE', 'BR', 'IN', 'FR', 'KR', 'AU', 'NL'];
    const msgs = [
        'SYN flood detected on port 443',
        'Repeated authentication failures',
        'Known malicious IP contacted C2',
        'SSH brute force pattern matched',
        'Anomalous HTTP request rate',
        'Unexpected privileged port scan'
    ];

    demoInterval = setInterval(() => {
        if (feedPaused) return;

        const t = types[rand(0, types.length - 1)];
        const s = sevs[rand(0, sevs.length - 1)];
        const alert = {
            timestamp: new Date().toISOString(),
            attack_type: t,
            severity: s,
            message: msgs[rand(0, msgs.length - 1)],
            geo: geos[rand(0, geos.length - 1)],
            src_ip: `${rand(1,254)}.${rand(1,254)}.${rand(1,254)}.${rand(1,254)}`,
            src_port: rand(1024, 65535),
            dst_ip: `10.0.${rand(0,255)}.${rand(1,254)}`,
            dst_port: [22, 80, 443, 3306, 8080][rand(0,4)],
            details: { reason: t }
        };

        if (!alertExists(alert)) {
            allAlerts.push(alert);
            appendAlert(alert, document.getElementById('live-feed'), true);
        }

        const totalEl = document.getElementById('total-alerts');
        animateCounter(totalEl, (parseInt(totalEl.textContent) || 0) + 1);
        document.getElementById('donut-total').textContent = (parseInt(document.getElementById('total-alerts').textContent) || 0);

        if (s === 'CRITICAL') {
            showToast(`🚨 CRITICAL: ${alert.message} from ${alert.geo}`, 'red');
            const critEl = document.getElementById('critical-alerts');
            animateCounter(critEl, (parseInt(critEl.textContent) || 0) + 1);
        }

        const epmEl = document.getElementById('events-per-min');
        animateCounter(epmEl, rand(15, 40));

    }, rand(1800, 3500));
}

function stopDemoSimulation() {
    if (demoInterval) {
        clearInterval(demoInterval);
        demoInterval = null;
    }
}

// ── Ticker duplication for smooth loop ───────────────────────
function setupTicker() {
    const track = document.getElementById('ticker-track');
    if (!track.dataset.duplicated) {
        track.innerHTML += track.innerHTML;
        track.dataset.duplicated = 'true';
    }
}

// ── Init ──────────────────────────────────────────────────────
async function initDashboard() {
    setupTicker();

    const statsOk = await fetchStats();
    const historyOk = await fetchHistory();

    let backendConnected = false;

    try {
        await setupWebSocket();
        backendConnected = true;
        stopDemoSimulation();
        console.log('Connected to real backend');
    } catch {
        backendConnected = false;
        console.log('Backend unavailable, starting demo mode');
    }

    if (!statsOk) {
        loadDemoStats();
    }

    if (!historyOk) {
        loadDemoAlerts();
    }

    if (!backendConnected) {
        startDemoSimulation();
    }
}

document.addEventListener('DOMContentLoaded', runBoot);
