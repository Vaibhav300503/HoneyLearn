/**
 * Honeypot v2 — Dashboard Application Logic
 * Handles tab navigation, data fetching, charts, and all UI interactions.
 * Redesigned for the warm card-based Crextio-style dashboard.
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
    if (!type) return '<span style="color:var(--text-muted);font-size:0.72rem;">benign</span>';
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

function getScoreClass(score) {
    if (score > 70) return 'high';
    if (score > 40) return 'medium';
    return 'low';
}

function getThreatIcon(type) {
    const icons = {
        'sql_injection': '💉',
        'xss': '⚡',
        'rce_attempt': '💀',
        'brute_force': '🔨',
        'directory_traversal': '📁',
        'bot_scanner': '🤖',
        'credential_stuffing': '🔑',
    };
    return icons[type] || '⚠️';
}

function getThreatSeverity(score) {
    if (score > 80) return 'critical';
    if (score > 60) return 'high';
    if (score > 40) return 'medium';
    return 'low';
}


// ═══════════════════════════════════════════════
// COLLAPSIBLE SECTIONS
// ═══════════════════════════════════════════════

function toggleSection(name) {
    const section = document.getElementById(`section-${name}`);
    if (!section) return;
    const content = section.querySelector('.section-content');
    const chevron = section.querySelector('.chevron');
    if (content) {
        content.classList.toggle('collapsed');
    }
    if (chevron) {
        chevron.classList.toggle('up');
    }
}


// ═══════════════════════════════════════════════
// OVERVIEW TAB
// ═══════════════════════════════════════════════

async function fetchStats() {
    try {
        const res = await fetch('/api/admin/stats');
        const d = await res.json();

        // Counter numbers with animation
        animateCounter('stat-total', d.total_attacks || 0);
        animateCounter('stat-blocked', d.blocked_count || 0);
        animateCounter('stat-sessions', d.active_sessions || 0);

        // Profile section values
        document.getElementById('stat-fingerprints').textContent = d.unique_fingerprints || 0;
        document.getElementById('stat-tokens').textContent = d.honeytokens_triggered || 0;

        // Quick stats
        document.getElementById('qs-blocked').textContent = d.blocked_count || 0;
        const avgScore = d.average_threat_score || 0;
        if (avgScore > 70) {
            document.getElementById('qs-threat-level').textContent = 'CRITICAL';
            document.getElementById('qs-threat-level').className = 'quick-stat-pill pill-danger';
        } else if (avgScore > 40) {
            document.getElementById('qs-threat-level').textContent = 'HIGH';
            document.getElementById('qs-threat-level').className = 'quick-stat-pill pill-warning';
        } else {
            document.getElementById('qs-threat-level').textContent = 'LOW';
            document.getElementById('qs-threat-level').className = 'quick-stat-pill pill-success';
        }

        // Avg Score Badge
        const avgEl = document.getElementById('avg-score-value');
        avgEl.textContent = avgScore.toFixed(1);

        // Gauge
        updateGauge(avgScore);

        // Tracker stats
        document.getElementById('tracker-active').textContent = d.active_sessions || 0;
        document.getElementById('tracker-anomalies').textContent = d.total_attacks || 0;

        // Top IPs
        const ic = document.getElementById('top-ips-container');
        ic.innerHTML = '';
        (d.top_ips || []).forEach(ip => {
            ic.innerHTML += `
                <div class="ip-item">
                    <span class="ip-text">${escapeHTML(ip.ip)}</span>
                    <span class="ip-count">${ip.count}</span>
                </div>`;
        });

        // Top paths
        const tc = document.getElementById('targets-container');
        tc.innerHTML = '';
        (d.top_paths || []).forEach(p => {
            tc.innerHTML += `
                <div class="path-item">
                    <span class="path-text">${escapeHTML(p.path)}</span>
                    <span class="path-count">${p.count}</span>
                </div>`;
        });

        // Attack chart
        renderAttackChart(d.attack_distribution || []);

        // Detection bars
        renderDetectionBars(d.attack_distribution || [], d.total_attacks || 0);

    } catch (e) { console.error('Stats fetch error:', e); }
}

function animateCounter(elementId, target) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const start = parseInt(el.textContent) || 0;
    const duration = 800;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(start + (target - start) * eased);
        el.textContent = current;
        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
}

function updateGauge(score) {
    const fill = document.getElementById('gauge-fill');
    const value = document.getElementById('gauge-value');
    if (!fill || !value) return;

    const circumference = 2 * Math.PI * 52; // r=52
    const offset = circumference - (score / 100) * circumference;
    fill.style.strokeDashoffset = offset;

    // Color based on score
    fill.classList.remove('high', 'medium', 'low');
    fill.classList.add(getScoreClass(score));

    value.textContent = score.toFixed(1);
}

function renderDetectionBars(distribution, total) {
    const container = document.getElementById('detection-bars');
    if (!container) return;

    if (!distribution.length || total === 0) {
        container.innerHTML = '<p style="color:var(--text-muted);font-size:0.78rem;padding:8px 0;">No attack data available yet.</p>';
        document.getElementById('detection-pct').textContent = '0%';
        return;
    }

    const attackTotal = distribution.reduce((sum, d) => sum + d.count, 0);
    const pct = total > 0 ? ((attackTotal / total) * 100).toFixed(0) : 0;
    document.getElementById('detection-pct').textContent = `${pct}%`;

    const colors = ['accent', 'info', 'dark', 'muted'];
    container.innerHTML = '';
    distribution.slice(0, 4).forEach((d, i) => {
        const barPct = total > 0 ? ((d.count / total) * 100).toFixed(0) : 0;
        container.innerHTML += `
            <div class="detection-bar-item">
                <span class="det-bar-label">${barPct}%</span>
                <div class="det-bar-track">
                    <div class="det-bar-fill ${colors[i % colors.length]}" style="width:${barPct}%"></div>
                </div>
                <span class="det-bar-pct" style="font-size:0.68rem;color:var(--text-muted);">${(d.type || '').replace(/_/g, ' ')}</span>
            </div>`;
    });
}

function renderAttackChart(data) {
    const ctx = document.getElementById('attackChart');
    if (!ctx) return;

    if (chartInstances.attackChart) chartInstances.attackChart.destroy();

    const colors = {
        'sql_injection': '#e74c3c',
        'xss': '#f39c12',
        'brute_force': '#d4a843',
        'directory_traversal': '#3498db',
        'rce_attempt': '#c0392b',
        'bot_scanner': '#8e44ad',
        'credential_stuffing': '#e67e22'
    };

    chartInstances.attackChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map(d => (d.type || '').replace(/_/g, ' ')),
            datasets: [{
                data: data.map(d => d.count),
                backgroundColor: data.map(d => colors[d.type] || '#9e9690'),
                borderRadius: 10,
                borderSkipped: false,
                barThickness: 32,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#2a2a2a',
                    titleColor: '#f0ece6',
                    bodyColor: '#a09890',
                    borderColor: 'rgba(212,168,67,0.3)',
                    borderWidth: 1,
                    cornerRadius: 10,
                    padding: 12,
                    titleFont: { weight: '700' },
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: '#9e9690', font: { size: 11, weight: '500' } },
                    border: { display: false }
                },
                y: {
                    grid: { color: 'rgba(0,0,0,0.04)', drawBorder: false },
                    ticks: { color: '#9e9690', font: { size: 11 } },
                    border: { display: false }
                }
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

        // Populate threat list (recent threats in the dark card)
        populateThreatList(logs);

        logs.forEach(log => {
            tbody.innerHTML += `
                <tr>
                    <td style="font-size:0.75rem;color:var(--text-muted);">${formatTime(log.timestamp)}</td>
                    <td style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;">${escapeHTML(log.ip_address)}</td>
                    <td>
                        <span style="font-weight:600;color:var(--text-primary);">${log.method}</span>
                        <span style="font-family:'JetBrains Mono',monospace;color:var(--text-muted);margin-left:4px;font-size:0.78rem;">${escapeHTML(truncate(log.path, 30))}</span>
                    </td>
                    <td>${attackBadge(log.attack_type)}</td>
                    <td>${scoreBadge(log.threat_score)}</td>
                    <td>
                        <button onclick="blockIP('${escapeHTML(log.ip_address)}')" class="btn btn-danger" style="font-size:0.72rem;padding:4px 12px;">Block</button>
                    </td>
                </tr>`;
        });
    } catch (e) { console.error('Logs fetch error:', e); }
}

function populateThreatList(logs) {
    const list = document.getElementById('threat-list');
    const countEl = document.getElementById('threat-count');
    const totalEl = document.getElementById('threat-total');
    if (!list) return;

    const threats = logs.filter(l => l.attack_type && l.attack_type !== 'benign').slice(0, 8);
    countEl.textContent = threats.length;
    totalEl.textContent = logs.length;

    if (threats.length === 0) {
        list.innerHTML = '<p style="color:var(--text-on-dark-muted);font-size:0.78rem;text-align:center;padding:24px 0;">No threats detected yet.</p>';
        return;
    }

    list.innerHTML = '';
    threats.forEach(t => {
        const severity = getThreatSeverity(t.threat_score);
        const statusClass = t.threat_score > 80 ? 'blocked' : (t.threat_score > 50 ? 'watching' : 'active');
        list.innerHTML += `
            <div class="threat-item">
                <div class="threat-type-icon ${severity}">${getThreatIcon(t.attack_type)}</div>
                <div class="threat-details">
                    <div class="threat-name">${(t.attack_type || '').replace(/_/g, ' ')}</div>
                    <div class="threat-meta">${escapeHTML(t.ip_address)} · ${formatShort(t.timestamp)}</div>
                </div>
                <div class="threat-status-dot ${statusClass}" title="Score: ${t.threat_score.toFixed(0)}"></div>
            </div>`;
    });
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
            tbody.innerHTML = '<tr><td colspan="9" class="empty-state">No sessions found</td></tr>';
            return;
        }

        sessions.forEach(s => {
            const attacks = (s.attack_types || []).map(a => attackBadge(a)).join(' ');
            const mitre = (s.mitre_techniques || []).map(t =>
                `<span class="badge badge-purple">${t}</span>`
            ).join(' ');

            tbody.innerHTML += `
                <tr>
                    <td style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;">${s.id.substring(0, 8)}...</td>
                    <td style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;">${(s.fingerprint_id || '').substring(0, 12)}...</td>
                    <td style="font-size:0.75rem;color:var(--text-muted);">${formatTime(s.started_at)}</td>
                    <td style="font-weight:700;">${s.total_requests}</td>
                    <td>${scoreBadge(s.max_threat_score)}</td>
                    <td>${attacks || '<span style="color:var(--text-muted);font-size:0.72rem;">-</span>'}</td>
                    <td>${mitre || '<span style="color:var(--text-muted);font-size:0.72rem;">-</span>'}</td>
                    <td>${s.is_active
                        ? '<span class="badge badge-low"><span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:#27ae60;margin-right:4px;"></span> Active</span>'
                        : '<span style="color:var(--text-muted);font-size:0.72rem;">Closed</span>'}</td>
                    <td>
                        <button onclick="viewReplay('${s.id}')" class="btn btn-outline" style="font-size:0.72rem;padding:4px 10px;">📂 Replay</button>
                        <button onclick="viewIncident('${s.id}')" class="btn btn-purple" style="font-size:0.72rem;padding:4px 10px;margin-left:4px;">📄 Report</button>
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
    container.innerHTML = '<p class="empty-state">Loading timeline...</p>';

    try {
        const res = await fetch(`/api/admin/sessions/${sessionId}/timeline`);
        const events = await res.json();

        if (!events.length) {
            container.innerHTML = '<p class="empty-state">No events found for this session.</p>';
            return;
        }

        // Path flow visualization
        let pathFlow = events.map(e => `<span style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;padding:4px 10px;background:var(--bg-input);border-radius:var(--radius-sm);display:inline-block;">${e.method} ${e.path}</span>`).join(' <span style="color:var(--accent);font-weight:700;">→</span> ');

        let html = `
            <div style="margin-bottom:24px;padding:16px;border-radius:var(--radius-md);background:var(--bg-input);">
                <h3 style="font-size:0.82rem;font-weight:600;color:var(--text-muted);margin-bottom:10px;">Attack Path</h3>
                <div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;">${pathFlow}</div>
            </div>
            <div>`;

        events.forEach((e, i) => {
            const isDanger = e.threat_score > 60;
            html += `
                <div class="timeline-node ${isDanger ? 'danger' : ''}">
                    <div style="display:flex;align-items:flex-start;justify-content:space-between;">
                        <div>
                            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
                                <span style="font-size:0.85rem;font-weight:600;color:var(--text-primary);">${e.method} <span style="font-family:'JetBrains Mono',monospace;color:var(--accent-dark);">${escapeHTML(e.path)}</span></span>
                                ${e.attack_type ? attackBadge(e.attack_type) : ''}
                                ${scoreBadge(e.threat_score)}
                            </div>
                            ${e.payload_snippet ? `<div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:var(--danger);margin-top:4px;max-width:600px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHTML(e.payload_snippet)}</div>` : ''}
                        </div>
                        <div style="text-align:right;font-size:0.72rem;color:var(--text-muted);white-space:nowrap;">
                            <div>${formatShort(e.timestamp)}</div>
                            ${e.time_delta_ms > 0 ? `<div style="color:var(--text-light);">+${e.time_delta_ms}ms</div>` : ''}
                            ${e.response_code ? `<div style="color:var(--text-light);">${e.response_code}</div>` : ''}
                        </div>
                    </div>
                </div>`;
        });

        html += '</div>';
        container.innerHTML = html;

    } catch (e) {
        container.innerHTML = '<p class="empty-state" style="color:var(--danger);">Error loading timeline.</p>';
        console.error('Replay error:', e);
    }
}

function viewReplay(sessionId) {
    switchTab('replay');
    const select = document.getElementById('replay-session-select');
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
                    <td style="font-size:1rem;font-weight:700;">${d.count}</td>
                    <td style="color:var(--text-muted);">${(d.avg_confidence * 100).toFixed(1)}%</td>
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

    const colors = ['#e74c3c', '#f39c12', '#d4a843', '#3498db', '#8e44ad', '#27ae60', '#e67e22', '#9e9690'];

    chartInstances.attackPie = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.map(d => (d.attack_type || '').replace(/_/g, ' ')),
            datasets: [{
                data: data.map(d => d.count),
                backgroundColor: colors.slice(0, data.length),
                borderWidth: 0,
                spacing: 3,
                borderRadius: 4,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#6b6560',
                        padding: 16,
                        font: { size: 11, weight: '500' },
                        usePointStyle: true,
                        pointStyleWidth: 8,
                    }
                },
                tooltip: {
                    backgroundColor: '#2a2a2a',
                    titleColor: '#f0ece6',
                    bodyColor: '#a09890',
                    borderColor: 'rgba(212,168,67,0.3)',
                    borderWidth: 1,
                    cornerRadius: 10,
                    padding: 12,
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
            container.innerHTML = '<div style="grid-column:1/-1;text-align:center;color:var(--text-muted);padding:48px 16px;">No MITRE ATT&CK techniques detected yet. Send some attack traffic to see mappings.</div>';
            return;
        }

        data.forEach(m => {
            container.innerHTML += `
                <div class="mitre-card">
                    <div class="mitre-card-header">
                        <span class="badge badge-purple">${m.technique_id}</span>
                        <span style="font-size:0.72rem;color:var(--text-muted);">${m.count} occurrence${m.count > 1 ? 's' : ''}</span>
                    </div>
                    <div class="mitre-technique">${escapeHTML(m.technique_name)}</div>
                    <div class="mitre-tactic">${escapeHTML(m.tactic)}</div>
                    <div style="display:flex;align-items:center;gap:8px;">
                        <div class="mitre-bar-track" style="flex:1;">
                            <div class="mitre-bar-fill" style="width:${(m.avg_confidence * 100).toFixed(0)}%"></div>
                        </div>
                        <span style="font-size:0.72rem;color:var(--text-muted);font-weight:600;">${(m.avg_confidence * 100).toFixed(0)}%</span>
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
            tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No IPs currently blocked.</td></tr>';
            return;
        }

        blocked.forEach(b => {
            tbody.innerHTML += `
                <tr>
                    <td style="font-family:'JetBrains Mono',monospace;font-size:0.82rem;color:var(--danger);font-weight:600;">${escapeHTML(b.ip_address)}</td>
                    <td style="font-size:0.78rem;color:var(--text-muted);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHTML(b.reason || '')}</td>
                    <td style="font-size:0.75rem;color:var(--text-muted);">${formatTime(b.blocked_at)}</td>
                    <td>
                        <button onclick="unblockIP('${escapeHTML(b.ip_address)}')" class="btn btn-success" style="font-size:0.72rem;padding:4px 12px;">Unblock</button>
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
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No honeytokens generated yet. Honeytokens are created when attackers visit honeypot pages.</td></tr>';
            return;
        }

        tokens.forEach(t => {
            tbody.innerHTML += `
                <tr style="${t.triggered ? 'background:var(--danger-light);' : ''}">
                    <td><span class="badge badge-purple">${t.token_type}</span></td>
                    <td style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:var(--text-muted);">${escapeHTML(t.token_value)}</td>
                    <td style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:var(--text-muted);">${t.session_id ? t.session_id.substring(0, 8) + '...' : '-'}</td>
                    <td style="font-size:0.75rem;color:var(--text-muted);">${formatTime(t.created_at)}</td>
                    <td>${t.triggered
                        ? '<span class="badge badge-critical">🚨 TRIGGERED</span>'
                        : '<span class="badge badge-low">Dormant</span>'}</td>
                    <td style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;">${t.triggered_by_ip ? escapeHTML(t.triggered_by_ip) : '-'}</td>
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
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No alerts sent yet.</td></tr>';
            return;
        }

        alerts.forEach(a => {
            tbody.innerHTML += `
                <tr>
                    <td style="font-size:0.75rem;color:var(--text-muted);">${formatTime(a.sent_at)}</td>
                    <td><span class="badge badge-medium">${a.alert_type}</span></td>
                    <td style="font-size:0.78rem;color:var(--text-secondary);">${escapeHTML(truncate(a.trigger_reason, 50))}</td>
                    <td style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:var(--text-muted);">${a.session_id ? a.session_id.substring(0, 8) + '...' : '-'}</td>
                    <td>${a.success
                        ? '<span style="color:var(--success);font-size:0.78rem;font-weight:600;">✓ Sent</span>'
                        : '<span style="color:var(--danger);font-size:0.78rem;font-weight:600;">✗ Failed</span>'}</td>
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
