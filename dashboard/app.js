const API_URL = window.location.hostname === 'localhost' ? 'http://localhost:8000' : '/api';
const WS_URL = window.location.hostname === 'localhost' ? 'ws://localhost:8000/ws/alerts' : `ws://${window.location.host}/ws/alerts`;

let severityChart;
let timelineChart;

async function initDashboard() {
    await fetchStats();
    setupWebSocket();
}

async function fetchStats() {
    try {
        const response = await fetch(`${API_URL}/api/stats`);
        const data = await response.json();
        updateAllStats(data);
    } catch (error) {
        console.error("Error fetching stats:", error);
    }
}

function updateAllStats(data) {
    document.getElementById('total-alerts').textContent = data.total_alerts || 0;
            
    const c = data.severity_counts?.CRITICAL || 0;
    const b = data.blocked_ips?.length || 0;
    document.getElementById('critical-alerts').textContent = `${c} / ${b}`;
    
    updateSeverityChart(data.severity_counts || {});
    updateTimelineChart(data.timeline || []);
    updateBlockedTable(data.blocked_ips || []);
}

function updateSeverityChart(counts) {
    const ctx = document.getElementById('severityChart').getContext('2d');
    
    if (severityChart) {
        severityChart.data.datasets[0].data = [
            counts.LOW || 0,
            counts.MEDIUM || 0,
            counts.HIGH || 0,
            counts.CRITICAL || 0
        ];
        severityChart.update();
        return;
    }

    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Low', 'Medium', 'High', 'Critical'],
            datasets: [{
                data: [
                    counts.LOW || 0,
                    counts.MEDIUM || 0,
                    counts.HIGH || 0,
                    counts.CRITICAL || 0
                ],
                backgroundColor: ['#3b82f6', '#f59e0b', '#ef4444', '#b91c1c'],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#e2e8f0' } }
            }
        }
    });
}

function updateTimelineChart(timeline) {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    
    const labels = timeline.map(t => t.time);
    const data = timeline.map(t => t.count);

    if (timelineChart) {
        timelineChart.data.labels = labels;
        timelineChart.data.datasets[0].data = data;
        timelineChart.update();
        return;
    }

    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Events/Min',
                data: data,
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, grid: { color: '#1e293b' }, ticks: { color: '#94a3b8', stepSize: 1 } },
                x: { grid: { color: '#1e293b' }, ticks: { color: '#94a3b8' } }
            }
        }
    });
}

function updateBlockedTable(ips) {
    const tbody = document.getElementById('blocked-table').getElementsByTagName('tbody')[0];
    tbody.innerHTML = '';
    
    if (ips.length === 0) {
        tbody.innerHTML = '<tr><td style="color: #94a3b8; border:none;">No IPs blocked currently.</td></tr>';
        return;
    }
    
    ips.forEach(ip => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td style="color: #ef4444; font-weight: bold; border-bottom: 1px solid #1e293b;">🚫 ${ip}</td>`;
        tbody.appendChild(tr);
    });
}

function setupWebSocket() {
    const ws = new WebSocket(WS_URL);
    const feed = document.getElementById('live-feed');
    
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        if (data.type === 'update') {
            if (data.alert) appendAlert(data.alert, feed);
            if (data.stats) updateAllStats(data.stats);
        } else {
            // legacy fallback
            appendAlert(data, feed);
        }
    };
    
    ws.onclose = () => {
        console.log("WebSocket connection closed. Attempting reconnect...");
        setTimeout(setupWebSocket, 3000);
    };
}

function appendAlert(alert, feed) {
    const entry = document.createElement('div');
    entry.className = `log-entry ${alert.severity.toLowerCase()}`;
    
    const time = new Date(alert.timestamp).toLocaleTimeString();
    
    let typeClass = '';
    if (alert.attack_type === 'Port Scan') typeClass = 'scan';
    else if (alert.attack_type === 'Brute Force / DoS') typeClass = 'brute';
    else if (alert.attack_type === 'Malicious IP') typeClass = 'alert';
    
    entry.innerHTML = `
        <span class="log-timestamp">[${time}]</span>
        <span class="badge ${typeClass}">${alert.attack_type || 'Unknown'}</span>
        <strong>[${alert.severity}]</strong> ${alert.message} 
        <span class="geo">(${alert.geo || 'Unknown'})</span>
        <br/><span style="color:#94a3b8; font-size: 0.8rem; padding-left: 5px;">SRC: ${alert.src_ip}:${alert.src_port || 'N/A'} -> DST: ${alert.dst_ip}:${alert.dst_port || 'N/A'} | Reason: ${alert.details?.reason || 'N/A'}</span>
    `;
    
    feed.prepend(entry);
    
    if (feed.children.length > 50) {
        feed.removeChild(feed.lastChild);
    }
}

document.addEventListener('DOMContentLoaded', initDashboard);
