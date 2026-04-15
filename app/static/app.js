/**
 * Honeypot v2 — Dashboard Application Logic
 * Handles tab navigation, data fetching, charts, and all UI interactions.
 */

// ═══════════════════════════════════════════════
// TAB NAVIGATION
// ═══════════════════════════════════════════════

let currentTab = 'overview';
let chartInstances = {};

document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        const tabName = tab.dataset.tab;
        switchTab(tabName);
    });
});

function switchTab(tabName) {
    currentTab = tabName;
    // Update nav
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    const activeTab = document.querySelector(`[data-tab="${tabName}"]`);
    if (activeTab) activeTab.classList.add('active');
    // Update pages
    document.querySelectorAll('.page-section').forEach(s => s.classList.remove('active'));
    const activePage = document.getElementById(`page-${tabName}`);
    if (activePage) activePage.classList.add('active');
    // Load tab-specific data
    loadTabData(tabName);
}

function loadTabData(tab) {
    switch(tab) {
        case 'overview': fetchStats(); fetchLogs(); break;
        case 'sessions': loadSessions('all'); break;
        case 'replay': loadSessionList(); break;
        case 'attacks': loadAttackTypes(); break;
        case 'mitre': loadMitre(); break;
        case 'blocked': fetchBlocked(); break;
        case 'honeytokens': loadHoneytokens(); break;
        case 'export': loadAlerts(); break;
    }
}

// ═══════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════

function escapeHTML(str) {
    if (!str) return '';
    return String(str).replace(/[&<>'"]/g, tag => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
    }[tag]));
}

function formatTime(iso) {
    if (!iso) return '-';
    try {
        return new Date(iso).toLocaleString('en-US', {
            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
    } catch { return iso; }
}

function formatShort(iso) {
    if (!iso) return '-';
    try {
        return new Date(iso).toLocaleString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch { return iso; }
}

function scoreBadge(score) {
    if (score > 80) return `<span class="badge badge-critical">🔴 ${score.toFixed(0)}</span>`;
    if (score > 50) return `<span class="badge badge-high">🟡 ${score.toFixed(0)}</span>`;
    return `<span class="badge badge-low">🟢 ${score.toFixed(0)}</span>`;
}

function threatBadge(level) {
    const map = {
        'CRITICAL': 'badge-critical',
        'HIGH': 'badge-high',
        'MEDIUM': 'badge-medium',
        'LOW': 'badge-low'
    };
    return `<span class="badge ${map[level] || 'badge-low'}">${level}</span>`;
}

function attackBadge(type) {
    if (!type) return '<span class="text-gray-500 text-xs">benign</span>';
    const colors = {
        'sql_injection': 'badge-critical',
        'xss': 'badge-high',
        'rce_attempt': 'badge-critical',
        'brute_force': 'badge-high',
        'directory_traversal': 'badge-medium',
        'bot_scanner': 'badge-purple',
        'credential_stuffing': 'badge-high',
    };
    return `<span class="badge ${colors[type] || 'badge-medium'}">${type.replace(/_/g, ' ')}</span>`;
}

function truncate(str, len) {
    if (!str) return '';
    return str.length > len ? str.substring(0, len) + '...' : str;
}


// ═══════════════════════════════════════════════
// OVERVIEW TAB
// ═══════════════════════════════════════════════

async function fetchStats() {
    try {
        const res = await fetch('/api/admin/stats');
        const d = await res.json();

        document.getElementById('stats-container').innerHTML = `
            <div class="stat-card text-center">
                <div class="text-xs text-gray-500 uppercase tracking-wider mb-1">Total Requests</div>
                <div class="text-2xl font-bold text-accent">${d.total_attacks || 0}</div>
            </div>
            <div class="stat-card text-center">
                <div class="text-xs text-gray-500 uppercase tracking-wider mb-1">Blocked IPs</div>
                <div class="text-2xl font-bold text-rose-400">${d.blocked_count || 0}</div>
            </div>
            <div class="stat-card text-center">
                <div class="text-xs text-gray-500 uppercase tracking-wider mb-1">Active Sessions</div>
                <div class="text-2xl font-bold text-green-400">${d.active_sessions || 0}</div>
            </div>
            <div class="stat-card text-center">
                <div class="text-xs text-gray-500 uppercase tracking-wider mb-1">Fingerprints</div>
                <div class="text-2xl font-bold text-purple-400">${d.unique_fingerprints || 0}</div>
            </div>
            <div class="stat-card text-center">
                <div class="text-xs text-gray-500 uppercase tracking-wider mb-1">Avg Score</div>
                <div class="text-2xl font-bold ${d.average_threat_score > 50 ? 'text-rose-400' : 'text-green-400'}">${(d.average_threat_score || 0).toFixed(1)}</div>
            </div>
            <div class="stat-card text-center">
                <div class="text-xs text-gray-500 uppercase tracking-wider mb-1">Tokens Triggered</div>
                <div class="text-2xl font-bold ${d.honeytokens_triggered > 0 ? 'text-rose-400' : 'text-gray-400'}">${d.honeytokens_triggered || 0}</div>
            </div>
        `;

        // Top paths
        const tc = document.getElementById('targets-container');
        tc.innerHTML = '';
        (d.top_paths || []).forEach(p => {
            tc.innerHTML += `
                <div class="flex justify-between items-center p-2 rounded-lg hover:bg-white/5 transition-colors">
                    <span class="font-mono text-xs text-gray-300 truncate max-w-[180px]">${escapeHTML(p.path)}</span>
                    <span class="badge badge-critical">${p.count}</span>
                </div>`;
        });

        // Top IPs
        const ic = document.getElementById('top-ips-container');
        ic.innerHTML = '';
        (d.top_ips || []).forEach(ip => {
            ic.innerHTML += `
                <div class="flex justify-between items-center p-2 rounded-lg hover:bg-white/5 transition-colors">
                    <span class="font-mono text-xs text-gray-300">${escapeHTML(ip.ip)}</span>
                    <span class="badge badge-high">${ip.count}</span>
                </div>`;
        });

        // Attack chart
        renderAttackChart(d.attack_distribution || []);

    } catch (e) { console.error('Stats fetch error:', e); }
}

function renderAttackChart(data) {
    const ctx = document.getElementById('attackChart');
    if (!ctx) return;

    if (chartInstances.attackChart) chartInstances.attackChart.destroy();

    const colors = {
        'sql_injection': '#f43f5e', 'xss': '#fb923c', 'brute_force': '#fbbf24',
        'directory_traversal': '#38bdf8', 'rce_attempt': '#ef4444', 'bot_scanner': '#a78bfa',
        'credential_stuffing': '#f97316'
    };

    chartInstances.attackChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map(d => (d.type || '').replace(/_/g, ' ')),
            datasets: [{
                data: data.map(d => d.count),
                backgroundColor: data.map(d => colors[d.type] || '#64748b'),
                borderRadius: 8,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { display: false }, ticks: { color: '#64748b', font: { size: 11 } } },
                y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#64748b' } }
            }
        }
    });
}

async function fetchLogs() {
    try {
        const res = await fetch('/api/admin/logs?limit=30');
        const logs = await res.json();
        const tbody = document.getElementById('logs-body');
        tbody.innerHTML = '';

        logs.forEach(log => {
            tbody.innerHTML += `
                <tr>
                    <td class="text-xs text-gray-500">${formatTime(log.timestamp)}</td>
                    <td class="font-mono text-xs">${escapeHTML(log.ip_address)}</td>
                    <td class="text-xs">
                        <span class="font-semibold text-gray-200">${log.method}</span>
                        <span class="font-mono text-gray-400 ml-1">${escapeHTML(truncate(log.path, 30))}</span>
                    </td>
                    <td>${attackBadge(log.attack_type)}</td>
                    <td>${scoreBadge(log.threat_score)}</td>
                    <td>
                        <button onclick="blockIP('${escapeHTML(log.ip_address)}')" class="btn btn-danger text-xs">Block</button>
                    </td>
                </tr>`;
        });
    } catch (e) { console.error('Logs fetch error:', e); }
}


// ═══════════════════════════════════════════════
// SESSIONS TAB
// ═══════════════════════════════════════════════

async function loadSessions(mode) {
    try {
        const url = mode === 'active' ? '/api/admin/sessions/active' : '/api/admin/sessions?limit=50';
        const res = await fetch(url);
        const sessions = await res.json();
        const tbody = document.getElementById('sessions-body');
        tbody.innerHTML = '';

        if (!sessions.length) {
            tbody.innerHTML = '<tr><td colspan="9" class="text-center text-gray-500 py-8">No sessions found</td></tr>';
            return;
        }

        sessions.forEach(s => {
            const attacks = (s.attack_types || []).map(a => attackBadge(a)).join(' ');
            const mitre = (s.mitre_techniques || []).map(t =>
                `<span class="badge badge-purple">${t}</span>`
            ).join(' ');

            tbody.innerHTML += `
                <tr>
                    <td class="font-mono text-xs">${s.id.substring(0, 8)}...</td>
                    <td class="font-mono text-xs">${(s.fingerprint_id || '').substring(0, 12)}...</td>
                    <td class="text-xs text-gray-400">${formatTime(s.started_at)}</td>
                    <td class="text-sm font-semibold">${s.total_requests}</td>
                    <td>${scoreBadge(s.max_threat_score)}</td>
                    <td>${attacks || '<span class="text-gray-600 text-xs">-</span>'}</td>
                    <td>${mitre || '<span class="text-gray-600 text-xs">-</span>'}</td>
                    <td>${s.is_active
                        ? '<span class="badge badge-low"><span class="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span> Active</span>'
                        : '<span class="text-gray-600 text-xs">Closed</span>'}</td>
                    <td>
                        <button onclick="viewReplay('${s.id}')" class="btn btn-primary text-xs">📂 Replay</button>
                        <button onclick="viewIncident('${s.id}')" class="btn btn-purple text-xs ml-1">📄 Report</button>
                    </td>
                </tr>`;
        });
    } catch (e) { console.error('Sessions error:', e); }
}


// ═══════════════════════════════════════════════
// SESSION REPLAY TAB
// ═══════════════════════════════════════════════

async function loadSessionList() {
    try {
        const res = await fetch('/api/admin/sessions?limit=50');
        const sessions = await res.json();
        const select = document.getElementById('replay-session-select');
        select.innerHTML = '<option value="">Select a session...</option>';
        sessions.forEach(s => {
            const label = `${s.id.substring(0, 8)} | ${s.total_requests} reqs | Score: ${s.max_threat_score.toFixed(0)}`;
            select.innerHTML += `<option value="${s.id}">${label}</option>`;
        });
    } catch (e) { console.error('Session list error:', e); }
}

async function loadReplay(sessionId) {
    if (!sessionId) return;
    const container = document.getElementById('replay-container');
    container.innerHTML = '<p class="text-gray-400 text-center py-4">Loading timeline...</p>';

    try {
        const res = await fetch(`/api/admin/sessions/${sessionId}/timeline`);
        const events = await res.json();

        if (!events.length) {
            container.innerHTML = '<p class="text-gray-500 italic text-center py-8">No events found for this session.</p>';
            return;
        }

        // Path flow visualization
        let pathFlow = events.map(e => `<span class="font-mono text-xs px-2 py-1 rounded bg-surface">${e.method} ${e.path}</span>`).join(' <span class="text-accent">→</span> ');

        let html = `
            <div class="mb-6 p-4 rounded-xl bg-surface/50">
                <h3 class="text-sm font-semibold text-gray-400 mb-2">Attack Path</h3>
                <div class="flex flex-wrap items-center gap-1">${pathFlow}</div>
            </div>
            <div class="space-y-0">`;

        events.forEach((e, i) => {
            const isDanger = e.threat_score > 60;
            html += `
                <div class="timeline-node ${isDanger ? 'danger' : ''}">
                    <div class="flex items-start justify-between">
                        <div>
                            <div class="flex items-center gap-2 mb-1">
                                <span class="text-sm font-semibold text-gray-200">${e.method} <span class="font-mono text-accent">${escapeHTML(e.path)}</span></span>
                                ${e.attack_type ? attackBadge(e.attack_type) : ''}
                                ${scoreBadge(e.threat_score)}
                            </div>
                            ${e.payload_snippet ? `<div class="font-mono text-xs text-rose-300/70 mt-1 max-w-2xl truncate">${escapeHTML(e.payload_snippet)}</div>` : ''}
                        </div>
                        <div class="text-right text-xs text-gray-500 whitespace-nowrap">
                            <div>${formatShort(e.timestamp)}</div>
                            ${e.time_delta_ms > 0 ? `<div class="text-gray-600">+${e.time_delta_ms}ms</div>` : ''}
                            ${e.response_code ? `<div class="text-gray-600">${e.response_code}</div>` : ''}
                        </div>
                    </div>
                </div>`;
        });

        html += '</div>';
        container.innerHTML = html;

    } catch (e) {
        container.innerHTML = '<p class="text-red-400 text-center py-4">Error loading timeline.</p>';
        console.error('Replay error:', e);
    }
}

function viewReplay(sessionId) {
    switchTab('replay');
    const select = document.getElementById('replay-session-select');
    // Try to set the value
    loadSessionList().then(() => {
        select.value = sessionId;
        loadReplay(sessionId);
    });
}


// ═══════════════════════════════════════════════
// ATTACK CLASSIFICATION TAB
// ═══════════════════════════════════════════════

async function loadAttackTypes() {
    try {
        const res = await fetch('/api/admin/attack-types');
        const data = await res.json();
        const tbody = document.getElementById('attack-types-body');
        tbody.innerHTML = '';

        data.forEach(d => {
            tbody.innerHTML += `
                <tr>
                    <td>${attackBadge(d.attack_type)}</td>
                    <td class="text-lg font-bold">${d.count}</td>
                    <td class="text-gray-400">${(d.avg_confidence * 100).toFixed(1)}%</td>
                </tr>`;
        });

        // Pie chart
        renderAttackPie(data);
    } catch (e) { console.error('Attack types error:', e); }
}

function renderAttackPie(data) {
    const ctx = document.getElementById('attackPieChart');
    if (!ctx) return;
    if (chartInstances.attackPie) chartInstances.attackPie.destroy();

    const colors = ['#f43f5e', '#fb923c', '#fbbf24', '#38bdf8', '#a78bfa', '#34d399', '#f97316', '#64748b'];

    chartInstances.attackPie = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.map(d => (d.attack_type || '').replace(/_/g, ' ')),
            datasets: [{
                data: data.map(d => d.count),
                backgroundColor: colors.slice(0, data.length),
                borderWidth: 0,
                spacing: 2,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            cutout: '60%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', padding: 16, font: { size: 11 } }
                }
            }
        }
    });
}


// ═══════════════════════════════════════════════
// MITRE ATT&CK TAB
// ═══════════════════════════════════════════════

async function loadMitre() {
    try {
        const res = await fetch('/api/admin/mitre');
        const data = await res.json();
        const container = document.getElementById('mitre-container');
        container.innerHTML = '';

        if (!data.length) {
            container.innerHTML = '<div class="col-span-3 text-center text-gray-500 py-12">No MITRE ATT&CK techniques detected yet. Send some attack traffic to see mappings.</div>';
            return;
        }

        const tacticColors = {
            'Initial Access': 'from-rose-500/20 to-transparent border-rose-500/30',
            'Credential Access': 'from-amber-500/20 to-transparent border-amber-500/30',
            'Execution': 'from-red-600/20 to-transparent border-red-600/30',
            'Discovery': 'from-sky-500/20 to-transparent border-sky-500/30',
            'Reconnaissance': 'from-violet-500/20 to-transparent border-violet-500/30',
            'Collection': 'from-emerald-500/20 to-transparent border-emerald-500/30',
            'Persistence': 'from-orange-500/20 to-transparent border-orange-500/30',
        };

        data.forEach(m => {
            const gradient = tacticColors[m.tactic] || 'from-gray-500/20 to-transparent border-gray-500/30';
            container.innerHTML += `
                <div class="mitre-card bg-gradient-to-br ${gradient}">
                    <div class="flex items-center justify-between mb-2">
                        <span class="badge badge-purple">${m.technique_id}</span>
                        <span class="text-xs text-gray-500">${m.count} occurrence${m.count > 1 ? 's' : ''}</span>
                    </div>
                    <h3 class="text-sm font-semibold text-gray-200 mb-1">${escapeHTML(m.technique_name)}</h3>
                    <div class="text-xs text-gray-400 mb-2">${escapeHTML(m.tactic)}</div>
                    <div class="flex items-center gap-2">
                        <div class="flex-grow h-1.5 rounded-full bg-gray-700">
                            <div class="h-1.5 rounded-full gradient-accent" style="width:${(m.avg_confidence * 100).toFixed(0)}%"></div>
                        </div>
                        <span class="text-xs text-gray-400">${(m.avg_confidence * 100).toFixed(0)}%</span>
                    </div>
                </div>`;
        });
    } catch (e) { console.error('MITRE error:', e); }
}


// ═══════════════════════════════════════════════
// BLOCKED IPS TAB
// ═══════════════════════════════════════════════

async function fetchBlocked() {
    try {
        const res = await fetch('/api/admin/blocked');
        const blocked = await res.json();
        const tbody = document.getElementById('blocked-body');
        tbody.innerHTML = '';

        if (!blocked.length) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center text-gray-500 py-8">No IPs currently blocked.</td></tr>';
            return;
        }

        blocked.forEach(b => {
            tbody.innerHTML += `
                <tr>
                    <td class="font-mono text-sm text-rose-400">${escapeHTML(b.ip_address)}</td>
                    <td class="text-xs text-gray-400 max-w-sm truncate">${escapeHTML(b.reason || '')}</td>
                    <td class="text-xs text-gray-500">${formatTime(b.blocked_at)}</td>
                    <td>
                        <button onclick="unblockIP('${escapeHTML(b.ip_address)}')" class="btn btn-green text-xs">Unblock</button>
                    </td>
                </tr>`;
        });
    } catch (e) { console.error('Blocked fetch error:', e); }
}


// ═══════════════════════════════════════════════
// HONEYTOKENS TAB
// ═══════════════════════════════════════════════

async function loadHoneytokens() {
    try {
        const res = await fetch('/api/admin/honeytokens');
        const tokens = await res.json();
        const tbody = document.getElementById('honeytokens-body');
        tbody.innerHTML = '';

        if (!tokens.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-gray-500 py-8">No honeytokens generated yet. Honeytokens are created when attackers visit honeypot pages.</td></tr>';
            return;
        }

        tokens.forEach(t => {
            tbody.innerHTML += `
                <tr class="${t.triggered ? 'bg-rose-500/5' : ''}">
                    <td><span class="badge badge-purple">${t.token_type}</span></td>
                    <td class="font-mono text-xs text-gray-400">${escapeHTML(t.token_value)}</td>
                    <td class="font-mono text-xs text-gray-500">${t.session_id ? t.session_id.substring(0, 8) + '...' : '-'}</td>
                    <td class="text-xs text-gray-500">${formatTime(t.created_at)}</td>
                    <td>${t.triggered
                        ? '<span class="badge badge-critical">🚨 TRIGGERED</span>'
                        : '<span class="badge badge-low">Dormant</span>'}</td>
                    <td class="font-mono text-xs">${t.triggered_by_ip ? escapeHTML(t.triggered_by_ip) : '-'}</td>
                </tr>`;
        });
    } catch (e) { console.error('Honeytokens error:', e); }
}


// ═══════════════════════════════════════════════
// EXPORT & ALERTS TAB
// ═══════════════════════════════════════════════

function downloadExport(format) {
    window.open(`/api/admin/export/${format}?days=30`, '_blank');
}

async function loadAlerts() {
    try {
        const res = await fetch('/api/admin/alerts?limit=20');
        const alerts = await res.json();
        const tbody = document.getElementById('alerts-body');
        tbody.innerHTML = '';

        if (!alerts.length) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-gray-500 py-8">No alerts sent yet.</td></tr>';
            return;
        }

        alerts.forEach(a => {
            tbody.innerHTML += `
                <tr>
                    <td class="text-xs text-gray-500">${formatTime(a.sent_at)}</td>
                    <td><span class="badge badge-medium">${a.alert_type}</span></td>
                    <td class="text-xs text-gray-300">${escapeHTML(truncate(a.trigger_reason, 50))}</td>
                    <td class="font-mono text-xs text-gray-500">${a.session_id ? a.session_id.substring(0, 8) + '...' : '-'}</td>
                    <td>${a.success ? '<span class="text-green-400 text-xs">✓ Sent</span>' : '<span class="text-rose-400 text-xs">✗ Failed</span>'}</td>
                </tr>`;
        });
    } catch (e) { console.error('Alerts error:', e); }
}


// ═══════════════════════════════════════════════
// INCIDENT REPORT
// ═══════════════════════════════════════════════

function viewIncident(sessionId) {
    window.open(`/api/admin/incident/${sessionId}`, '_blank');
}


// ═══════════════════════════════════════════════
// ACTIONS
// ═══════════════════════════════════════════════

async function blockIP(ip) {
    if (!confirm(`Block IP: ${ip}?`)) return;
    await fetch('/api/admin/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
    });
    refreshData();
}

async function unblockIP(ip) {
    if (!confirm(`Unblock IP: ${ip}?`)) return;
    await fetch('/api/admin/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
    });
    refreshData();
}

async function retrainModel() {
    if (!confirm('Retrain both AI models? This may take a moment.')) return;
    try {
        const [r1, r2] = await Promise.all([
            fetch('/api/admin/retrain', { method: 'POST' }),
            fetch('/api/admin/retrain-classifier', { method: 'POST' })
        ]);
        const d1 = await r1.json();
        const d2 = await r2.json();
        alert(`Anomaly Model: ${d1.message}\nClassifier: ${d2.message}`);
    } catch (e) {
        alert('Retraining error: ' + e.message);
    }
}


// ═══════════════════════════════════════════════
// DATA REFRESH
// ═══════════════════════════════════════════════

function refreshData() {
    loadTabData(currentTab);
}

// Initial load
refreshData();

// Auto-refresh every 5 seconds
setInterval(refreshData, 5000);
