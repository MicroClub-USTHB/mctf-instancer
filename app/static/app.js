// CTF Instancer Frontend Application

const API_BASE = '';

// State
let currentUser = null;
let challenges = [];
let instances = [];
let timerIntervals = {};
let authToken = null;
let authMode = 'none';
let maxInstances = 0;
let lastAuthError = '';

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    init();
});

async function init() {
    // Check for saved token
    // Note: Using sessionStorage instead of localStorage for better security
    // sessionStorage clears when browser/tab is closed, reducing token exposure
    authToken = sessionStorage.getItem('ctfd_token');
    
    await checkHealth();
    await checkAuthMode();
    
    if (authMode === 'none') {
        // No auth mode - show main content directly
        showMainContent();
        const success = await loadUserInfo();
        if (success) {
            await loadChallenges();
            await loadInstances();
        } else {
            showToast(lastAuthError || 'Authentication refused by server', 'error');
        }
    } else if (authToken) {
        // CTFd mode with saved token - try to authenticate
        const success = await loadUserInfo();
        if (success) {
            showMainContent();
            await loadChallenges();
            await loadInstances();
        } else {
            // Token invalid, show auth form
            showAuthForm();
            if (lastAuthError) {
                showToast(lastAuthError, 'error');
            }
        }
    } else {
        // CTFd mode without token - show auth form
        showAuthForm();
    }
    
    // Refresh instances every 10 seconds
    setInterval(() => {
        if (currentUser) {
            loadInstances();
        }
    }, 10000);
}

function showAuthForm() {
    document.getElementById('auth-section').classList.remove('hidden');
    document.getElementById('main-content').classList.add('hidden');
}

function showMainContent() {
    document.getElementById('auth-section').classList.add('hidden');
    document.getElementById('main-content').classList.remove('hidden');
}

async function checkAuthMode() {
    try {
        const data = await fetch(`${API_BASE}/api`).then(r => r.json());
        authMode = data.auth_mode || 'none';
        
        // Update auth section link based on CTFd URL
        if (authMode === 'ctfd') {
            // The link is already set in HTML, but we could update it dynamically if needed
        }
    } catch (error) {
        console.error('Failed to check auth mode:', error);
    }
}

async function authenticate() {
    const tokenInput = document.getElementById('ctfd-token');
    const token = tokenInput.value.trim();
    
    if (!token) {
        showToast('Please enter your CTFd access token', 'error');
        return;
    }
    
    // Save token temporarily
    authToken = token;
    
    // Try to authenticate
    const success = await loadUserInfo();
    
    if (success) {
        // Save token to sessionStorage (more secure than localStorage)
        // Token will be cleared when browser/tab is closed
        sessionStorage.setItem('ctfd_token', token);
        showToast(`Session opened for ${currentUser.username}`, 'success');
        showMainContent();
        await loadChallenges();
        await loadInstances();
    } else {
        authToken = null;
        showToast(lastAuthError || 'Invalid token. Please check and try again.', 'error');
    }
}

function logout() {
    authToken = null;
    currentUser = null;
    sessionStorage.removeItem('ctfd_token');
    
    // Clear instances
    instances = [];
    Object.keys(timerIntervals).forEach(id => {
        clearInterval(timerIntervals[id]);
        delete timerIntervals[id];
    });
    
    // Clear token input
    document.getElementById('ctfd-token').value = '';
    
    showToast('Session closed', 'info');
    showAuthForm();
}

// API Functions
async function api(endpoint, options = {}) {
    try {
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };
        
        // Add auth token if available
        if (authToken) {
            headers['Authorization'] = `Bearer ${authToken}`;
        }
        
        const response = await fetch(`${API_BASE}${endpoint}`, {
            headers,
            ...options
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.detail || 'API Error');
        }
        
        return data;
    } catch (error) {
        console.error(`API Error (${endpoint}):`, error);
        throw error;
    }
}

// Health Check
async function checkHealth() {
    const statusEl = document.getElementById('status-health');
    try {
        const data = await api('/health');
        statusEl.innerHTML = `
            <span class="status-dot online"></span>
            <span>${data.active_instances} live</span>
        `;
    } catch (error) {
        statusEl.innerHTML = `
            <span class="status-dot offline"></span>
            <span>Unavailable</span>
        `;
    }
}

// User Info
async function loadUserInfo() {
    try {
        const data = await api('/me');
        currentUser = data.user;
        maxInstances = data.max_instances || 0;
        lastAuthError = '';
        
        document.getElementById('user-name').textContent = currentUser.username;
        const userIdEl = document.getElementById('user-id');
        if (userIdEl) {
            userIdEl.textContent = '-';
        }
        document.getElementById('user-instances').textContent = 
            `${data.instances} / ${data.max_instances}`;
        
        // Display team info if in team mode
        const teamNameItem = document.getElementById('team-name-item');
        const teamNameEl = document.getElementById('team-name');
        const instancesLabel = document.getElementById('instances-label');
        
        if (data.team_mode) {
            // Show team name inline
            if (teamNameItem && teamNameEl) {
                teamNameEl.textContent = 'Team';
                teamNameItem.classList.remove('hidden');
            }
            
            // Update label for instances
            if (instancesLabel) {
                instancesLabel.textContent = 'Team Instances';
            }
            
            // Load team members
            await loadTeamMembers();
        } else {
            // Hide team info
            if (teamNameItem) {
                teamNameItem.classList.add('hidden');
            }
            if (instancesLabel) {
                instancesLabel.textContent = 'Instances';
            }
            // Hide team members section
            const teamMembersEl = document.getElementById('team-members');
            if (teamMembersEl) {
                teamMembersEl.classList.add('hidden');
            }
        }
        
        return true;
    } catch (error) {
        console.error('Failed to load user info:', error);
        lastAuthError = error.message || 'Failed to load user info';
        return false;
    }
}

// Load Team Members
async function loadTeamMembers() {
    const container = document.getElementById('team-members');
    if (!container) return;
    
    try {
        const data = await api('/me/team');
        
        if (!data.team_mode || !data.members || data.members.length === 0) {
            container.classList.add('hidden');
            return;
        }
        
        container.classList.remove('hidden');

        const teamNameEl = document.getElementById('team-name');
        if (teamNameEl) {
            teamNameEl.textContent = data.team_name || 'Team';
        }
        
        const membersList = data.members.map(member => {
            const isCurrentUser = Boolean(member.is_current) || String(member.name).toLowerCase() === String(currentUser?.username || '').toLowerCase();
            return `<span class="team-member ${isCurrentUser ? 'current-user' : ''}">${escapeHtml(member.name)}${isCurrentUser ? ' (you)' : ''}</span>`;
        }).join('');
        
        container.innerHTML = `
            <div class="info-item team-members-list">
                <span class="label">Team Members</span>
                <span class="value">${membersList}</span>
            </div>
        `;
    } catch (error) {
        console.error('Failed to load team members:', error);
        container.classList.add('hidden');
    }
}

// Challenges
async function loadChallenges() {
    const container = document.getElementById('challenges-list');
    container.innerHTML = '<div class="loading">Loading challenge deck...</div>';
    
    try {
        const data = await api('/challenges');
        challenges = data.challenges;
        
        if (challenges.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <span class="empty-icon">□</span>
                    <p>No challenges available</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = challenges.map(challenge => `
            <div class="challenge-card" data-id="${challenge.id}">
                <div class="challenge-header">
                    <span class="challenge-name">${escapeHtml(challenge.name)}</span>
                    <span class="challenge-category category-${challenge.category}">${challenge.category}</span>
                </div>
                <p class="challenge-description">${escapeHtml(challenge.description || 'No description')}</p>
                <div class="challenge-meta">
                    <span>${escapeHtml(challenge.routing_type || 'unknown')} routing</span>
                </div>
                <div class="challenge-actions">
                    <button class="btn btn-primary" data-challenge-id="${challenge.id}" onclick="spawnInstance('${challenge.id}', this)">
                        Deploy
                    </button>
                </div>
            </div>
        `).join('');
        
    } catch (error) {
        container.innerHTML = `
            <div class="empty-state">
                <span class="empty-icon">×</span>
                <p>Failed to load challenges</p>
                <button class="btn btn-secondary" onclick="loadChallenges()">Retry</button>
            </div>
        `;
    }
}

// Instances
async function loadInstances() {
    const container = document.getElementById('instances-list');
    
    try {
        const data = await api('/instances');
        instances = data.instances;
        
        // Update user instance count
        document.getElementById('user-instances').textContent = 
            `${instances.length} / ${maxInstances || '-'}`;
        
        if (instances.length === 0) {
            // Clear any existing timers
            Object.keys(timerIntervals).forEach(id => {
                clearInterval(timerIntervals[id]);
                delete timerIntervals[id];
            });
            
            container.innerHTML = `
                <div class="empty-state">
                    <span class="empty-icon">□</span>
                    <p>No active instances</p>
                    <p class="empty-hint">Deploy a challenge to begin.</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = instances.map(instance => {
            // Generate URLs for all ports
            const publicUrls = Array.isArray(instance.public_urls) ? instance.public_urls : [];
            let portsHtml;
            const routingType = (instance.routing_type || '').toLowerCase();
            
            if (publicUrls.length > 0) {
                portsHtml = publicUrls
                    .map((url) => `
                        <span class="instance-url" onclick="copyToClipboard('${url}')" title="Click to copy">
                            ${url}
                        </span>
                    `).join('');
            } else {
                // Fallback to single URL
                const url = instance.public_url || 'N/A';
                portsHtml = `
                    <span class="instance-url" onclick="copyToClipboard('${url}')" title="Click to copy">
                        ${url}
                    </span>
                `;
            }
            
            const encodedConnectionHint = instance.connection_hint
                ? encodeURIComponent(instance.connection_hint)
                : '';

            const connectionHintHtml = instance.connection_hint ? `
                <div class="instance-detail">
                    <span class="label">Command:</span>
                    <span class="instance-url" onclick="copyToClipboard(decodeURIComponent('${encodedConnectionHint}'))" title="Click to copy command">
                        ${escapeHtml(instance.connection_hint)}
                    </span>
                </div>
            ` : '';
            
            // Show spawned by info in team mode (if spawned by different user)
            const spawnedByHtml = (instance.team_name && instance.username && instance.username !== currentUser?.username) ? 
                `<span class="spawned-by">(spawned by ${escapeHtml(instance.username)})</span>` : '';
            
            return `
                <div class="instance-card" data-id="${instance.instance_id}">
                    <div class="instance-info">
                        <div class="instance-header">
                            <span class="instance-name">${escapeHtml(instance.challenge_id)}</span>
                            <span class="instance-status status-${instance.status}">${instance.status}</span>
                            ${routingType ? `<span class="challenge-category category-${routingType === 'http' ? 'web' : 'pwn'}">${routingType}</span>` : ''}
                            ${spawnedByHtml}
                        </div>
                        <div class="instance-details">
                            <div class="instance-detail">
                                <span class="label">Connect:</span>
                                <div class="instance-urls">
                                    ${portsHtml}
                                </div>
                            </div>
                            <div class="instance-detail">
                                <span class="label">Expires:</span>
                                <span class="instance-timer" id="timer-${instance.instance_id}">
                                    ${formatTimeRemaining(instance.expires_at)}
                                </span>
                            </div>
                            ${connectionHintHtml}
                        </div>
                    </div>
                    <div class="instance-actions">
                        <button class="btn btn-warning btn-sm" onclick="extendInstance('${instance.instance_id}')" title="Request extension">
                            Extend
                        </button>
                        <button class="btn btn-danger btn-sm" onclick="stopInstance('${instance.instance_id}')">
                            Stop
                        </button>
                    </div>
                </div>
            `;
        }).join('');
        
        // Setup timers
        instances.forEach(instance => {
            setupTimer(instance.instance_id, instance.expires_at);
        });
        
    } catch (error) {
        console.error('Failed to load instances:', error);
        container.innerHTML = `
            <div class="empty-state">
                <span class="empty-icon">×</span>
                <p>Failed to load instances</p>
                <button class="btn btn-secondary" onclick="loadInstances()">Retry</button>
            </div>
        `;
    }
}

// Spawn Instance
async function spawnInstance(challengeId, triggerButton = null) {
    const btn = triggerButton || null;
    const originalText = btn ? btn.innerHTML : '';

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = 'Deploying...';
    }
    
    try {
        const data = await api('/instances/spawn', {
            method: 'POST',
            body: JSON.stringify({ challenge_id: challengeId })
        });
        
        if (data.success) {
            // Build URLs message for multi-port challenges
            let urlsMsg = '';
            if (data.instance.connection_hint) {
                urlsMsg = data.instance.connection_hint;
            } else {
                const publicUrls = Array.isArray(data.instance.public_urls) ? data.instance.public_urls : [];
                if (publicUrls.length > 1) {
                    urlsMsg = publicUrls.join(', ');
                } else {
                    urlsMsg = publicUrls[0] || data.instance.public_url;
                }
            }
            showToast(`Instance deployed: ${urlsMsg}`, 'success');
            await loadInstances();
            await loadUserInfo();
        } else {
            showToast(data.message, 'error');
        }
    } catch (error) {
        showToast(error.message || 'Failed to spawn instance', 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalText || 'Deploy';
        }
    }
}

// Stop Instance
async function stopInstance(instanceId) {
    if (!confirm('Are you sure you want to stop this instance?')) {
        return;
    }
    
    try {
        await api(`/instances/${instanceId}`, {
            method: 'DELETE'
        });
        
        showToast('Instance stopped', 'success');
        await loadInstances();
        await loadUserInfo();
    } catch (error) {
        showToast(error.message || 'Failed to stop instance', 'error');
    }
}

// Extend Instance
async function extendInstance(instanceId) {
    try {
        const data = await api(`/instances/${instanceId}/extend`, {
            method: 'POST'
        });
        
        showToast(data.message || 'Instance extended', 'success');
        await loadInstances();
    } catch (error) {
        showToast(error.message || 'Failed to extend instance', 'error');
    }
}

// Timer Functions
function setupTimer(instanceId, expiresAt) {
    // Clear existing timer
    if (timerIntervals[instanceId]) {
        clearInterval(timerIntervals[instanceId]);
    }
    
    const updateTimer = () => {
        const timerEl = document.getElementById(`timer-${instanceId}`);
        if (timerEl) {
            timerEl.textContent = formatTimeRemaining(expiresAt);
        }
    };
    
    updateTimer();
    timerIntervals[instanceId] = setInterval(updateTimer, 1000);
}

function formatTimeRemaining(expiresAt) {
    const now = new Date();
    
    // Parse expires_at - handle both ISO format and add 'Z' if missing (for UTC)
    let expiresStr = expiresAt;
    if (expiresStr && !expiresStr.endsWith('Z') && !expiresStr.includes('+')) {
        expiresStr = expiresStr + 'Z';  // Assume UTC if no timezone specified
    }
    const expires = new Date(expiresStr);
    
    // Check if date is valid
    if (isNaN(expires.getTime())) {
        return 'Invalid date';
    }
    
    const diff = expires - now;
    
    if (diff <= 0) {
        return 'Expired';
    }
    
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((diff % (1000 * 60)) / 1000);
    
    if (hours > 0) {
        return `${hours}h ${minutes}m ${seconds}s`;
    } else if (minutes > 0) {
        return `${minutes}m ${seconds}s`;
    } else {
        return `${seconds}s`;
    }
}

// Toast Notifications
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: 'OK',
        error: 'ERR',
        info: 'INFO'
    };
    
    toast.innerHTML = `
        <span>${icons[type] || icons.info}</span>
        <span>${escapeHtml(message)}</span>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// Modal Functions
function openModal(title, content) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-body').innerHTML = content;
    document.getElementById('modal').classList.remove('hidden');
}

function closeModal() {
    document.getElementById('modal').classList.add('hidden');
}

// Utility Functions
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function copyToClipboard(text) {
    if (!text || text === 'N/A') {
        return;
    }

    navigator.clipboard.writeText(text).then(() => {
        showToast(`Copied: ${text}`, 'success');
    }).catch(() => {
        // Fallback
        const input = document.createElement('input');
        input.value = text;
        document.body.appendChild(input);
        input.select();
        document.execCommand('copy');
        document.body.removeChild(input);
        showToast(`Copied: ${text}`, 'success');
    });
}
