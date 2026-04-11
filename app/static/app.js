async function fetchStats() {
    try {
        const res = await fetch('/api/admin/stats');
        const data = await res.json();
        
        const container = document.getElementById('stats-container');
        container.innerHTML = `
            <div class="glass p-4 rounded-xl flex flex-col justify-center items-center">
                <span class="text-sm text-gray-400">Total Attacks Detected</span>
                <span class="text-3xl font-bold text-accent mt-2">${data.total_attacks}</span>
            </div>
            <div class="glass p-4 rounded-xl flex flex-col justify-center items-center">
                <span class="text-sm text-gray-400">Blocked IPs</span>
                <span class="text-3xl font-bold text-danger mt-2">${data.blocked_count}</span>
            </div>
            <div class="glass p-4 rounded-xl flex flex-col justify-center items-center">
                <span class="text-sm text-gray-400">Avg Threat Score</span>
                <span class="text-3xl font-bold ${data.average_threat_score > 50 ? 'text-danger' : 'text-green-400'} mt-2">${data.average_threat_score.toFixed(1)}</span>
            </div>
            <div class="glass p-4 rounded-xl flex flex-col justify-center items-center">
                <span class="text-sm text-gray-400">System Status</span>
                <span class="text-xl font-bold text-green-400 mt-2 flex items-center gap-2">
                    <span class="w-3 h-3 rounded-full bg-green-500 animate-pulse"></span> Active
                </span>
            </div>
        `;

        const targetsContainer = document.getElementById('targets-container');
        targetsContainer.innerHTML = '';
        data.top_paths.forEach(p => {
            targetsContainer.innerHTML += `
                <li class="flex justify-between items-center text-sm p-2 hover:bg-gray-800 rounded">
                    <span class="text-gray-300 font-mono truncate w-48">${p.path}</span>
                    <span class="badge badge-red">${p.count} hits</span>
                </li>
            `;
        });
    } catch (e) { console.error('Fetch stats error', e); }
}

async function fetchLogs() {
    try {
        const res = await fetch('/api/admin/logs?limit=50');
        const logs = await res.json();
        const tbody = document.getElementById('logs-body');
        tbody.innerHTML = '';

        logs.forEach(log => {
            const date = new Date(log.timestamp).toLocaleString();
            let scoreClass = 'threat-low';
            if(log.threat_score > 50) scoreClass = 'threat-med';
            if(log.threat_score > 80) scoreClass = 'threat-high';
            
            const payloadDisp = log.payload ? (log.payload.length > 50 ? log.payload.substring(0, 50) + '...' : log.payload) : '<span class="text-gray-500 italic">None</span>';
            const flagBadge = log.anomaly_flag ? `<span class="badge badge-red ml-2">Anomaly</span>` : '';

            tbody.innerHTML += `
                <tr>
                    <td class="text-xs text-gray-400">${date}</td>
                    <td class="font-mono text-sm">${log.ip_address}</td>
                    <td class="text-sm">
                        <span class="font-bold text-gray-300 ml-1">${log.method}</span>
                        <span class="font-mono text-gray-400 ml-1">${log.path}</span>
                    </td>
                    <td class="text-xs font-mono text-pink-400 max-w-xs truncate">${escapeHTML(payloadDisp)}</td>
                    <td class="${scoreClass}">${log.threat_score.toFixed(0)} ${flagBadge}</td>
                    <td>
                        <button onclick="blockIP('${log.ip_address}')" class="text-xs bg-red-600 hover:bg-red-500 text-white px-2 py-1 rounded transition-colors">Block</button>
                    </td>
                </tr>
            `;
        });
    } catch (e) { console.error('Fetch logs error', e); }
}

async function fetchBlocked() {
    try {
        const res = await fetch('/api/admin/blocked');
        const blocked = await res.json();
        const list = document.getElementById('blocked-container');
        list.innerHTML = '';
        
        if (blocked.length === 0) {
            list.innerHTML = '<li class="text-sm text-gray-500 italic">No IPs currently blocked.</li>';
        }

        blocked.forEach(b => {
            const date = new Date(b.blocked_at).toLocaleDateString();
            list.innerHTML += `
                <li class="flex justify-between items-center text-sm p-2 border border-gray-700 bg-gray-800 rounded">
                    <div>
                        <div class="font-mono text-red-400">${b.ip_address}</div>
                        <div class="text-xs text-gray-500">${date}</div>
                    </div>
                    <button onclick="unblockIP('${b.ip_address}')" class="text-xs bg-gray-600 hover:bg-gray-500 text-white px-2 py-1 rounded transition-colors">Unblock</button>
                </li>
            `;
        });
    } catch (e) { console.error('Fetch blocked error', e); }
}

async function blockIP(ip) {
    if(!confirm(`Block IP: ${ip}?`)) return;
    await fetch('/api/admin/block', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ip})
    });
    refreshData();
}

async function unblockIP(ip) {
    if(!confirm(`Unblock IP: ${ip}?`)) return;
    await fetch('/api/admin/unblock', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ip})
    });
    refreshData();
}

async function retrainModel() {
    alert("Triggering AI Retraining asynchronously...");
    try {
        const res = await fetch('/api/admin/retrain', { method: 'POST' });
        const data = await res.json();
        alert(data.message);
    } catch (e) {
        alert("Retraining failed: " + e.message);
    }
}

function escapeHTML(str) {
    return str.replace(/[&<>'"]/g, 
        tag => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            "'": '&#39;',
            '"': '&quot;'
        }[tag]));
}

function refreshData() {
    fetchStats();
    fetchLogs();
    fetchBlocked();
}

// Initial load & Polling
refreshData();
setInterval(refreshData, 5000); // 5 sec live refresh
