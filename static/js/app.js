/* -------------------------------------------------------------
   🔐 CYBERSECURITY SYSTEM - FRONTEND APP CONTROLLER
   Handles SPA View Switching, REST API Integrations, Live Gauges, Modals,
   Attack Simulator Engine, MFA Verification, & Chart.js Analytics
------------------------------------------------------------- */

let currentView = 'dashboard-view';
let currentMFAData = null;
let activityChart = null;
let riskTrendChart = null;

document.addEventListener('DOMContentLoaded', () => {
    initViewNavigation();
    fetchDashboardData();
    setInterval(fetchDashboardData, 15000); // Polling every 15 seconds
});

// -------------------------------------------------------------
// 1. VIEW NAVIGATION (SPA)
// -------------------------------------------------------------
function initViewNavigation() {
    document.querySelectorAll('.menu-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const targetView = item.getAttribute('data-view');
            if (targetView) {
                switchView(targetView);
            }
        });
    });
}

function switchView(viewId) {
    currentView = viewId;

    // Update Sidebar Active state
    document.querySelectorAll('.menu-item').forEach(item => {
        item.classList.remove('active');
        if (item.getAttribute('data-view') === viewId) {
            item.classList.add('active');
        }
    });

    // Update Views Visibility
    document.querySelectorAll('.view-section').forEach(section => {
        section.classList.remove('active');
    });

    const activeSection = document.getElementById(viewId);
    if (activeSection) {
        activeSection.classList.add('active');
    }

    // Update Top Header Titles
    const titles = {
        'dashboard-view': { title: '🛡️ VERIX Security Control Center', subtitle: 'Real-time Account Protection & Threat Detection Monitoring' },
        'accounts-view': { title: '🔗 Linked Platform Accounts', subtitle: 'Monitor third-party linked accounts and authorization tokens' },
        'devices-view': { title: '📱 Device Security Management', subtitle: 'Manage trusted, unverified, and blocked devices' },
        'requests-view': { title: '🚨 Login Authorization Requests', subtitle: 'Review and approve/deny new login attempts' },
        'simulator-view': { title: '⚡ Attack Scenario Studio', subtitle: 'Interactive simulation engine for threat detection & risk scoring' },
        'analytics-view': { title: '📊 Threat Analytics & Trends', subtitle: 'Historical risk trends and login activity telemetry' },
        'history-view': { title: '📜 Security Audit Trail', subtitle: 'Complete immutable log of all access requests and security events' },
        'alerts-view': { title: '🔔 Security Notification Center', subtitle: 'System alerts and high-severity security warnings' },
        'sessions-view': { title: '💻 Active User Sessions', subtitle: 'Monitor active sessions and remote sign-out controls' },
        'rules-view': { title: '🔐 Security Policy Engine Rules', subtitle: 'Configure automated security rules and risk threshold policies' }
    };

    if (titles[viewId]) {
        document.getElementById('view-title').innerHTML = titles[viewId].title;
        document.getElementById('view-subtitle').innerText = titles[viewId].subtitle;
    }

    // Load View Data
    if (viewId === 'dashboard-view') fetchDashboardData();
    else if (viewId === 'accounts-view') fetchAccountsData();
    else if (viewId === 'devices-view') fetchDevicesData();
    else if (viewId === 'requests-view') fetchRequestsData();
    else if (viewId === 'analytics-view') fetchAnalyticsData();
    else if (viewId === 'history-view') fetchHistoryLogs();
    else if (viewId === 'alerts-view') fetchAlertsData();
    else if (viewId === 'sessions-view') fetchSessionsData();
    else if (viewId === 'rules-view') fetchRulesData();
}

// -------------------------------------------------------------
// 2. DASHBOARD DATA & GAUGES
// -------------------------------------------------------------
async function fetchDashboardData() {
    try {
        const res = await fetch('/api/dashboard');
        const data = await res.json();

        // Update Stat Cards
        document.getElementById('card-linked-count').innerText = data.summary.linked_accounts;
        document.getElementById('card-trusted-count').innerText = data.summary.trusted_devices;
        document.getElementById('card-pending-count').innerText = data.summary.pending_requests;
        document.getElementById('card-alerts-count').innerText = data.summary.threat_alerts;

        // Sidebar Badges
        document.getElementById('sidebar-pending-count').innerText = data.summary.pending_requests;
        document.getElementById('sidebar-alerts-count').innerText = data.summary.threat_alerts;

        // Risk Gauge & Status Banner
        const score = data.summary.overall_risk_score;
        const level = data.summary.overall_risk_level;
        document.getElementById('dash-risk-score').innerText = score;

        const circle = document.getElementById('dash-risk-circle');
        const badge = document.getElementById('dash-risk-badge');
        const desc = document.getElementById('dash-risk-description');

        if (score <= 30) {
            circle.style.background = `conic-gradient(var(--risk-low) 0% ${score}%, rgba(255, 255, 255, 0.1) ${score}% 100%)`;
            circle.style.boxShadow = 'var(--risk-low-glow)';
            badge.className = 'risk-badge-pill low';
            badge.innerText = '🟢 LOW RISK';
            desc.innerText = 'No critical threats detected. All linked accounts and trusted devices are operating normally.';
        } else if (score <= 70) {
            circle.style.background = `conic-gradient(var(--risk-med) 0% ${score}%, rgba(255, 255, 255, 0.1) ${score}% 100%)`;
            circle.style.boxShadow = 'var(--risk-med-glow)';
            badge.className = 'risk-badge-pill med';
            badge.innerText = '🟡 MEDIUM RISK';
            desc.innerText = 'Unverified login request pending approval. Caution advised before granting access.';
        } else {
            circle.style.background = `conic-gradient(var(--risk-high) 0% ${score}%, rgba(255, 255, 255, 0.1) ${score}% 100%)`;
            circle.style.boxShadow = 'var(--risk-high-glow)';
            badge.className = 'risk-badge-pill high';
            badge.innerText = '🔴 HIGH RISK';
            desc.innerText = 'High-severity threat detected! Suspicious access attempt blocked automatically.';
        }

        // Render Pending Requests Card
        renderPendingRequests(data.pending_requests);
        renderAlertsPreview(data.recent_alerts);
        fetchAccountsPreview();
    } catch (err) {
        console.error('Failed to fetch dashboard data:', err);
    }
}

function renderPendingRequests(requests) {
    const container = document.getElementById('dash-pending-container');
    if (!requests || requests.length === 0) {
        container.innerHTML = `
            <div style="text-align: center; padding: 2rem; color: var(--text-muted);">
                <i class="fa-solid fa-circle-check" style="font-size: 2.5rem; color: var(--risk-low); margin-bottom: 0.75rem;"></i>
                <p style="font-size: 0.95rem;">No pending login authorization requests. All accounts secured!</p>
            </div>
        `;
        return;
    }

    let html = '';
    requests.forEach(req => {
        const isHigh = req.risk_level === 'HIGH';
        const factorsHtml = (req.factors || []).map(f => `
            <span class="factor-chip ${f.type}">
                <i class="fa-solid fa-triangle-exclamation"></i> ${f.signal} (+${f.points})
            </span>
        `).join('');

        html += `
            <div class="login-request-card ${isHigh ? 'high-risk' : ''}">
                <div class="request-header">
                    <h3>
                        <i class="fa-solid fa-mobile-retro"></i>
                        🚨 NEW LOGIN AUTHORIZATION REQUEST
                    </h3>
                    <span class="risk-badge-pill ${req.risk_level.toLowerCase()}">
                        Risk Score: ${req.risk_score}/100 — ${req.risk_level}
                    </span>
                </div>

                <div class="request-grid-details">
                    <div class="detail-box">
                        <label>Device Name</label>
                        <span>${req.device_name}</span>
                    </div>
                    <div class="detail-box">
                        <label>Device ID Code</label>
                        <span class="mono">${req.device_id_code}</span>
                    </div>
                    <div class="detail-box">
                        <label>Location (Approx)</label>
                        <span><i class="fa-solid fa-location-dot" style="color: var(--accent-cyan);"></i> ${req.location}</span>
                    </div>
                    <div class="detail-box">
                        <label>IP Address</label>
                        <span class="mono">${req.ip_address}</span>
                    </div>
                    <div class="detail-box">
                        <label>Request Time</label>
                        <span>${req.request_time}</span>
                    </div>
                </div>

                <div class="request-factors-list">
                    <h5>Risk Signals Analyzed by Threat Engine:</h5>
                    ${factorsHtml || '<span style="color: var(--text-dim);">No abnormal signals detected</span>'}
                </div>

                <div class="request-actions">
                    <button class="btn-cyber btn-success" onclick="handleDecision('${req.request_code}', 'APPROVE')">
                        <i class="fa-solid fa-check"></i> APPROVE & TRUST DEVICE
                    </button>
                    <button class="btn-cyber btn-danger" onclick="handleDecision('${req.request_code}', 'DENY')">
                        <i class="fa-solid fa-ban"></i> DENY & BLOCK DEVICE
                    </button>
                </div>
            </div>
        `;
    });
    container.innerHTML = html;
}

function renderAlertsPreview(alerts) {
    const container = document.getElementById('dash-alerts-preview');
    if (!alerts || alerts.length === 0) {
        container.innerHTML = '<p style="color: var(--text-dim); font-size: 0.85rem;">No alerts recorded.</p>';
        return;
    }

    let html = '';
    alerts.forEach(a => {
        const iconClass = a.severity === 'HIGH' ? 'fa-solid fa-circle-exclamation' : 'fa-solid fa-bell';
        const colorStyle = a.severity === 'HIGH' ? 'color: var(--risk-high);' : 'color: var(--accent-cyan);';
        html += `
            <div style="display: flex; gap: 0.75rem; padding: 0.6rem 0; border-bottom: 1px solid var(--border-color);">
                <i class="${iconClass}" style="${colorStyle} font-size: 1.1rem; margin-top: 2px;"></i>
                <div style="flex: 1;">
                    <div style="display: flex; justify-content: space-between; font-size: 0.85rem; font-weight: 600;">
                        <span>${a.title}</span>
                        <span style="font-size: 0.72rem; color: var(--text-dim);">${a.timestamp}</span>
                    </div>
                    <p style="font-size: 0.78rem; color: var(--text-muted); margin-top: 2px;">${a.description}</p>
                </div>
            </div>
        `;
    });
    container.innerHTML = html;
}

// -------------------------------------------------------------
// 3. PENDING LOGIN DECISION WORKFLOW
// -------------------------------------------------------------
async function handleDecision(requestCode, decision) {
    try {
        const res = await fetch('/api/login-requests/decision', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ request_code: requestCode, decision: decision })
        });
        const data = await res.json();

        if (res.ok) {
            showToast(data.message, decision === 'APPROVE' ? 'success' : 'danger');
            fetchDashboardData();
            if (currentView === 'devices-view') fetchDevicesData();
            if (currentView === 'requests-view') fetchRequestsData();
        } else {
            showToast(data.error || 'Operation failed', 'danger');
        }
    } catch (err) {
        showToast('Network error handling decision', 'danger');
    }
}

// -------------------------------------------------------------
// 4. LINKED ACCOUNTS MANAGEMENT
// -------------------------------------------------------------
async function fetchAccountsData() {
    try {
        const res = await fetch('/api/accounts');
        const data = await res.json();
        renderAccountsGrid('all-accounts-grid', data.accounts);
    } catch (err) {
        console.error(err);
    }
}

async function fetchAccountsPreview() {
    try {
        const res = await fetch('/api/accounts');
        const data = await res.json();
        renderAccountsGrid('dash-accounts-preview', data.accounts);
    } catch (err) {
        console.error(err);
    }
}

function renderAccountsGrid(elementId, accounts) {
    const container = document.getElementById(elementId);
    if (!container) return;

    let html = '';
    accounts.forEach(acc => {
        const isConn = acc.status === 'Connected';
        html += `
            <div class="account-card">
                <div class="account-left">
                    <div class="account-icon"><i class="${acc.icon_class}"></i></div>
                    <div class="account-info">
                        <h4>${acc.service_name}</h4>
                        <p title="${acc.account_identifier || 'Synced'}">${acc.account_identifier || 'Synced'}</p>
                    </div>
                </div>
                <button class="btn-cyber-outline" style="padding: 0.35rem 0.75rem; font-size: 0.75rem;" onclick="toggleAccount(${acc.id}, '${acc.status}')">
                    <span class="status-indicator ${isConn ? 'connected' : 'disconnected'}">
                        ● ${acc.status}
                    </span>
                </button>
            </div>
        `;
    });
    container.innerHTML = html;
}

async function toggleAccount(accountId, currentStatus) {
    try {
        const res = await fetch('/api/accounts/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ account_id: accountId, status: currentStatus })
        });
        if (res.ok) {
            showToast('Account connection status toggled.', 'success');
            fetchAccountsData();
            fetchDashboardData();
        }
    } catch (err) {
        showToast('Failed to toggle account', 'danger');
    }
}

function openAddAccountModal() {
    document.getElementById('add-account-modal').classList.add('active');
}

async function submitAddAccount() {
    const service = document.getElementById('new-account-service').value;
    const handle = document.getElementById('new-account-handle').value || 'user@example.com';
    const icons = {
        'Facebook': 'fa-brands fa-facebook',
        'Instagram': 'fa-brands fa-instagram',
        'WhatsApp': 'fa-brands fa-whatsapp',
        'Email': 'fa-solid fa-envelope',
        'Twitter / X': 'fa-brands fa-x-twitter'
    };

    try {
        const res = await fetch('/api/accounts/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ service_name: service, identifier: handle, icon_class: icons[service] || 'fa-solid fa-link' })
        });
        if (res.ok) {
            showToast(`${service} account linked!`, 'success');
            closeModal('add-account-modal');
            fetchAccountsData();
            fetchDashboardData();
        }
    } catch (err) {
        showToast('Error linking account', 'danger');
    }
}

// -------------------------------------------------------------
// 5. DEVICE MANAGEMENT
// -------------------------------------------------------------
async function fetchDevicesData() {
    try {
        const res = await fetch('/api/devices');
        const data = await res.json();

        renderDeviceList('trusted-devices-list', data.trusted, 'Trusted');
        renderDeviceList('new-devices-list', data.new, 'New');
        renderDeviceList('blocked-devices-list', data.blocked, 'Blocked');
    } catch (err) {
        console.error('Failed to fetch devices:', err);
    }
}

function renderDeviceList(containerId, devices, category) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!devices || devices.length === 0) {
        container.innerHTML = `<p style="color: var(--text-dim); font-size: 0.85rem; padding: 0.5rem 0;">No ${category.toLowerCase()} devices.</p>`;
        return;
    }

    let html = '';
    devices.forEach(dev => {
        let actionsHtml = '';
        if (category === 'Trusted') {
            actionsHtml = `
                <button class="btn-cyber-outline" style="padding: 0.35rem 0.6rem; font-size: 0.75rem;" onclick="deviceAction('${dev.device_id_code}', 'signout')">Sign Out</button>
                <button class="btn-cyber-outline" style="padding: 0.35rem 0.6rem; font-size: 0.75rem; color: var(--risk-high);" onclick="deviceAction('${dev.device_id_code}', 'block')">Block</button>
            `;
        } else if (category === 'New') {
            actionsHtml = `
                <button class="btn-cyber btn-success" style="padding: 0.35rem 0.6rem; font-size: 0.75rem;" onclick="deviceAction('${dev.device_id_code}', 'trust')">Trust</button>
                <button class="btn-cyber btn-danger" style="padding: 0.35rem 0.6rem; font-size: 0.75rem;" onclick="deviceAction('${dev.device_id_code}', 'block')">Block</button>
            `;
        } else { // Blocked
            actionsHtml = `
                <button class="btn-cyber-outline" style="padding: 0.35rem 0.6rem; font-size: 0.75rem; color: var(--risk-low);" onclick="deviceAction('${dev.device_id_code}', 'trust')">Unblock & Trust</button>
                <button class="btn-cyber-outline" style="padding: 0.35rem 0.6rem; font-size: 0.75rem;" onclick="deviceAction('${dev.device_id_code}', 'remove')">Remove</button>
            `;
        }

        const icon = dev.device_type === 'Mobile' ? 'fa-mobile-screen' : (dev.device_type === 'Tablet' ? 'fa-tablet-screen-button' : 'fa-laptop');

        html += `
            <div class="device-item-card">
                <div class="device-item-left">
                    <div class="device-avatar-icon"><i class="fa-solid ${icon}"></i></div>
                    <div class="device-details">
                        <h4>
                            ${dev.device_name}
                            <span class="mono" style="font-size: 0.72rem; color: var(--accent-cyan); font-weight: 500;">(${dev.device_id_code})</span>
                        </h4>
                        <div class="device-meta">
                            <span><i class="fa-solid fa-globe"></i> ${dev.os_info} / ${dev.browser_info}</span>
                            <span><i class="fa-solid fa-location-dot"></i> ${dev.location}</span>
                            <span><i class="fa-solid fa-network-wired"></i> ${dev.ip_address}</span>
                            <span><i class="fa-solid fa-clock"></i> ${dev.last_active}</span>
                        </div>
                    </div>
                </div>
                <div class="device-actions">
                    ${actionsHtml}
                </div>
            </div>
        `;
    });
    container.innerHTML = html;
}

async function deviceAction(deviceCode, action) {
    try {
        const res = await fetch('/api/devices/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ device_id_code: deviceCode, action: action })
        });
        if (res.ok) {
            showToast(`Device action '${action}' completed.`, 'success');
            fetchDevicesData();
            fetchDashboardData();
        }
    } catch (err) {
        showToast('Error performing device action', 'danger');
    }
}

// -------------------------------------------------------------
// 6. INTERACTIVE ATTACK SCENARIO SIMULATOR
// -------------------------------------------------------------
async function runSimulation(scenario) {
    try {
        showToast(`Running Attack Scenario Simulation: ${scenario}...`, 'warning');
        const res = await fetch('/api/simulate-login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario: scenario })
        });
        const data = await res.json();

        // Render Simulation Results Output
        const card = document.getElementById('sim-result-card');
        card.style.display = 'block';

        const badge = document.getElementById('sim-result-badge');
        badge.className = `risk-badge-pill ${data.risk_assessment.risk_level.toLowerCase()}`;
        badge.innerText = `${data.risk_assessment.badge}`;

        document.getElementById('sim-score-text').innerText = `${data.risk_assessment.risk_score}/100`;
        document.getElementById('sim-action-text').innerText = `${data.risk_assessment.recommended_action} — ${data.risk_assessment.action_detail}`;

        const factorsContainer = document.getElementById('sim-factors-list');
        const factorsHtml = data.risk_assessment.factors.map(f => `
            <div class="factor-chip ${f.type}" style="margin-bottom: 0.5rem; display: block;">
                <i class="fa-solid fa-circle-small"></i> ${f.signal} (+${f.points} points)
            </div>
        `).join('');
        factorsContainer.innerHTML = factorsHtml || '<p style="color: var(--risk-low);">No threat signals triggered.</p>';

        if (data.system_response.require_mfa) {
            currentMFAData = data;
            setTimeout(() => openMFAModal(data.system_response.request_code), 800);
        }

        fetchDashboardData();
    } catch (err) {
        showToast('Failed to run attack simulation', 'danger');
    }
}

// -------------------------------------------------------------
// 7. MULTI-FACTOR AUTHENTICATION (MFA) WORKFLOW
// -------------------------------------------------------------
function openMFAModal(requestCode) {
    document.getElementById('mfa-modal').classList.add('active');
    document.getElementById('mfa-otp-input').value = '';
    document.getElementById('mfa-otp-input').focus();
}

async function submitMFA() {
    const otp = document.getElementById('mfa-otp-input').value.trim();
    if (!otp) {
        showToast('Please enter verification OTP code', 'warning');
        return;
    }

    try {
        const res = await fetch('/api/verify-mfa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ otp: otp })
        });
        const data = await res.json();

        if (res.ok) {
            showToast(data.message, 'success');
            closeModal('mfa-modal');
            switchView('dashboard-view');
        } else {
            showToast(data.message || 'Verification Failed', 'danger');
        }
    } catch (err) {
        showToast('Error verifying MFA', 'danger');
    }
}

// -------------------------------------------------------------
// 8. SECURITY AUDIT TRAIL & LOGS
// -------------------------------------------------------------
async function fetchHistoryLogs() {
    const statusFilter = document.getElementById('filter-status').value;
    try {
        const res = await fetch(`/api/logs?status=${statusFilter}`);
        const data = await res.json();

        const tbody = document.getElementById('history-table-body');
        let html = '';
        data.logs.forEach(log => {
            const riskClass = log.risk_level === 'HIGH' ? 'var(--risk-high)' : (log.risk_level === 'MEDIUM' ? 'var(--risk-med)' : 'var(--risk-low)');
            html += `
                <tr>
                    <td class="mono" style="color: var(--accent-cyan);">${log.event_id}</td>
                    <td>${log.timestamp}</td>
                    <td>${log.device_name}</td>
                    <td>${log.location}</td>
                    <td class="mono">${log.ip_address}</td>
                    <td><strong style="color: ${riskClass};">${log.risk_score}/100 (${log.risk_level})</strong></td>
                    <td><span class="status-indicator ${log.status === 'Approved' ? 'connected' : 'disconnected'}">● ${log.status}</span></td>
                    <td>
                        <button class="btn-cyber-outline" style="padding: 0.25rem 0.5rem; font-size: 0.72rem;" onclick="inspectEvent('${log.event_id}')">
                            <i class="fa-solid fa-eye"></i> Details
                        </button>
                    </td>
                </tr>
            `;
        });
        tbody.innerHTML = html || '<tr><td colspan="8" style="text-align: center; color: var(--text-dim);">No history logs found.</td></tr>';
    } catch (err) {
        console.error(err);
    }
}

async function inspectEvent(eventId) {
    try {
        const res = await fetch(`/api/event/${eventId}`);
        const data = await res.json();

        const content = document.getElementById('event-modal-content');
        const reasonsHtml = (data.reasons || []).map(r => `<li>${r}</li>`).join('');

        content.innerHTML = `
            <div class="request-grid-details" style="margin-bottom: 1.25rem;">
                <div class="detail-box"><label>Event ID</label><span class="mono">${data.event_id}</span></div>
                <div class="detail-box"><label>Device Name</label><span>${data.device_name}</span></div>
                <div class="detail-box"><label>Device Code</label><span class="mono">${data.device_id_code}</span></div>
                <div class="detail-box"><label>IP Address</label><span class="mono">${data.ip_address}</span></div>
                <div class="detail-box"><label>Location</label><span>${data.location}</span></div>
                <div class="detail-box"><label>Risk Score</label><span>${data.risk_score}/100 (${data.risk_level})</span></div>
            </div>
            <h4 style="font-size: 0.88rem; color: var(--text-muted); margin-bottom: 0.5rem;">Detected Risk Signals & Reasons:</h4>
            <ul style="padding-left: 1.25rem; font-size: 0.85rem; color: var(--text-main); margin-bottom: 1.25rem;">
                ${reasonsHtml || '<li>Normal access parameters.</li>'}
            </ul>
            <div style="text-align: right;">
                <button class="btn-cyber-outline" onclick="closeModal('event-modal')">Close</button>
            </div>
        `;

        document.getElementById('event-modal').classList.add('active');
    } catch (err) {
        showToast('Error fetching event details', 'danger');
    }
}

// -------------------------------------------------------------
// 9. ACTIVE SESSIONS
// -------------------------------------------------------------
async function fetchSessionsData() {
    try {
        const res = await fetch('/api/sessions');
        const data = await res.json();

        const container = document.getElementById('active-sessions-list');
        let html = '';
        data.sessions.forEach(s => {
            html += `
                <div class="device-item-card">
                    <div class="device-item-left">
                        <div class="device-avatar-icon"><i class="fa-solid fa-laptop-code"></i></div>
                        <div class="device-details">
                            <h4>${s.device_name} ${s.is_current ? '<span class="risk-badge-pill low" style="font-size: 0.65rem;">Current Device</span>' : ''}</h4>
                            <div class="device-meta">
                                <span><i class="fa-solid fa-location-dot"></i> ${s.location}</span>
                                <span><i class="fa-solid fa-network-wired"></i> ${s.ip_address}</span>
                                <span><i class="fa-solid fa-clock"></i> ${s.last_active}</span>
                            </div>
                        </div>
                    </div>
                    ${!s.is_current ? `<button class="btn-cyber-outline" style="color: var(--risk-high); font-size: 0.75rem;" onclick="signoutSession(${s.id})">Sign Out</button>` : ''}
                </div>
            `;
        });
        container.innerHTML = html;
    } catch (err) {
        console.error(err);
    }
}

async function signoutSession(sessionId) {
    try {
        const res = await fetch('/api/sessions/signout', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId })
        });
        if (res.ok) {
            showToast('Session signed out successfully.', 'success');
            fetchSessionsData();
        }
    } catch (err) {
        showToast('Failed to sign out session', 'danger');
    }
}

async function signoutAllOthers() {
    try {
        const res = await fetch('/api/sessions/signout', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ all_others: true })
        });
        if (res.ok) {
            showToast('Signed out from all other devices.', 'success');
            fetchSessionsData();
        }
    } catch (err) {
        showToast('Error terminating sessions', 'danger');
    }
}

// -------------------------------------------------------------
// 10. SECURITY RULES POLICY ENGINE
// -------------------------------------------------------------
async function fetchRulesData() {
    try {
        const res = await fetch('/api/rules');
        const data = await res.json();

        const container = document.getElementById('security-rules-list');
        let html = '';
        data.rules.forEach(r => {
            const isChecked = r.is_enabled ? 'checked' : '';
            html += `
                <div class="device-item-card">
                    <div class="device-details">
                        <h4>${r.rule_name}</h4>
                        <p style="font-size: 0.8rem; color: var(--text-muted); margin-top: 2px;">${r.description}</p>
                    </div>
                    <div>
                        <input type="checkbox" ${isChecked} onchange="toggleRule(${r.id}, this.checked)" style="transform: scale(1.3); cursor: pointer;">
                    </div>
                </div>
            `;
        });
        container.innerHTML = html;
    } catch (err) {
        console.error(err);
    }
}

async function toggleRule(ruleId, isEnabled) {
    try {
        await fetch('/api/rules/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule_id: ruleId, is_enabled: isEnabled })
        });
        showToast('Security policy rule updated.', 'success');
    } catch (err) {
        showToast('Failed to toggle rule', 'danger');
    }
}

// -------------------------------------------------------------
// 11. ANALYTICS & CHART.JS
// -------------------------------------------------------------
async function fetchAnalyticsData() {
    try {
        const res = await fetch('/api/analytics');
        const data = await res.json();

        renderAnalyticsCharts(data);
    } catch (err) {
        console.error('Analytics chart error:', err);
    }
}

function renderAnalyticsCharts(data) {
    const ctx1 = document.getElementById('chart-login-activity').getContext('2d');
    const ctx2 = document.getElementById('chart-risk-trend').getContext('2d');

    if (activityChart) activityChart.destroy();
    if (riskTrendChart) riskTrendChart.destroy();

    activityChart = new Chart(ctx1, {
        type: 'bar',
        data: {
            labels: data.labels,
            datasets: [
                { label: 'Successful', data: data.activity.successful, backgroundColor: '#10b981' },
                { label: 'Failed', data: data.activity.failed, backgroundColor: '#f59e0b' },
                { label: 'Blocked', data: data.activity.blocked, backgroundColor: '#ef4444' }
            ]
        },
        options: {
            responsive: true,
            plugins: { legend: { labels: { color: '#9ca3af' } } },
            scales: {
                x: { ticks: { color: '#9ca3af' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                y: { ticks: { color: '#9ca3af' }, grid: { color: 'rgba(255,255,255,0.05)' } }
            }
        }
    });

    riskTrendChart = new Chart(ctx2, {
        type: 'line',
        data: {
            labels: data.labels,
            datasets: [{
                label: 'Overall Risk Score',
                data: data.risk_trend,
                borderColor: '#06b6d4',
                backgroundColor: 'rgba(6, 182, 212, 0.1)',
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { labels: { color: '#9ca3af' } } },
            scales: {
                x: { ticks: { color: '#9ca3af' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                y: { ticks: { color: '#9ca3af' }, grid: { color: 'rgba(255,255,255,0.05)' }, min: 0, max: 100 }
            }
        }
    });
}

// -------------------------------------------------------------
// UTILITIES (Modals & Toasts)
// -------------------------------------------------------------
function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const iconMap = {
        'success': 'fa-circle-check',
        'warning': 'fa-triangle-exclamation',
        'danger': 'fa-ban',
        'info': 'fa-info-circle'
    };

    toast.innerHTML = `
        <i class="fa-solid ${iconMap[type] || 'fa-info-circle'}" style="font-size: 1.2rem;"></i>
        <div style="font-size: 0.88rem; font-weight: 500;">${message}</div>
    `;

    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}
