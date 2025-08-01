// API Configuration
const API_BASE_URL = 'http://localhost:5000/api';

// API helper functions
async function apiRequest(endpoint, options = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    console.log(`🌐 API Request: ${options.method || 'GET'} ${url}`);

    try {
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });

        console.log(`📡 API Response: ${response.status} ${response.statusText}`);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        console.log(`✅ API Data received:`, data);
        return data;
    } catch (error) {
        console.error('❌ API Error:', error);
        showErrorNotification(`API Error: ${error.message}`);
        throw error;
    }
}

// Application data - will be loaded from API
const appData = {
  "scans": [],
  "vulnerabilities": [],
  "agents": [],
  "reports": [],
  "stats": {
    "totalScans": 0,
    "activeAgents": 0,
    "vulnerabilitiesFound": 0,
    "criticalIssues": 0,
    "averageScanTime": "0 minutes",
    "successRate": 0
  }
};

// Global variables
let vulnerabilityChart = null;
let currentFilter = '';

// API Data Loading Functions
async function loadStats() {
    try {
        const stats = await apiRequest('/stats');
        appData.stats = stats;
        updateStatsDisplay();
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

async function loadScans() {
    try {
        const scans = await apiRequest('/scans');
        appData.scans = scans;
        renderActiveScans();
    } catch (error) {
        console.error('Failed to load scans:', error);
    }
}

async function loadAgents() {
    try {
        const agents = await apiRequest('/agents');
        appData.agents = agents;
        renderAgents();
    } catch (error) {
        console.error('Failed to load agents:', error);
    }
}

async function loadVulnerabilities() {
    try {
        const vulnerabilities = await apiRequest('/vulnerabilities');
        appData.vulnerabilities = vulnerabilities;
        renderVulnerabilities();
    } catch (error) {
        console.error('Failed to load vulnerabilities:', error);
    }
}

async function loadReports() {
    try {
        const reports = await apiRequest('/reports');
        appData.reports = reports;
        renderReports();
    } catch (error) {
        console.error('Failed to load reports:', error);
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', async function() {
    console.log('🚀 Initializing AI Bug Bounty Scanner...');

    initializeNavigation();
    initializeCharts();
    initializeForms();
    initializeModal();

    console.log('📡 Loading data from API...');

    // Load data from API
    try {
        await loadStats();
        console.log('✅ Stats loaded');

        await loadScans();
        console.log('✅ Scans loaded');

        await loadAgents();
        console.log('✅ Agents loaded');

        await loadVulnerabilities();
        console.log('✅ Vulnerabilities loaded');

        await loadReports();
        console.log('✅ Reports loaded');

        console.log('🎉 All data loaded successfully!');

    } catch (error) {
        console.error('❌ Failed to load initial data:', error);
    }

    renderActivityFeed();
    startRealTimeUpdates();

    console.log('🔄 Real-time updates started');
});

// Update stats display
function updateStatsDisplay() {
    const stats = appData.stats;

    // Update stat cards
    const statCards = document.querySelectorAll('.stat-card');
    if (statCards.length >= 4) {
        statCards[0].querySelector('.stat-number').textContent = stats.totalScans;
        statCards[1].querySelector('.stat-number').textContent = stats.activeAgents;
        statCards[2].querySelector('.stat-number').textContent = stats.vulnerabilitiesFound;
        statCards[3].querySelector('.stat-number').textContent = stats.criticalIssues;
    }

    // Update header status indicators
    const statusIndicators = document.querySelectorAll('.status');
    if (statusIndicators.length >= 2) {
        statusIndicators[0].textContent = `${stats.activeAgents} Agents Active`;
        statusIndicators[1].textContent = `${appData.scans.filter(s => s.status === 'running').length} Scans Running`;
    }
}

// Error notification function
function showErrorNotification(message) {
    const notification = createNotification(message, 'error');
    document.body.appendChild(notification);
}

// Navigation functionality - FIXED
function initializeNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const views = document.querySelectorAll('.view');
    const pageTitle = document.getElementById('page-title');

    navItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation(); // Prevent event bubbling
            
            // Remove active class from all nav items and views
            navItems.forEach(nav => nav.classList.remove('active'));
            views.forEach(view => view.classList.remove('active'));
            
            // Add active class to clicked nav item
            this.classList.add('active');
            
            // Show corresponding view
            const viewName = this.dataset.view;
            const targetView = document.getElementById(`${viewName}-view`);
            if (targetView) {
                targetView.classList.add('active');
                pageTitle.textContent = this.textContent;
            }
        });
    });
}

// Chart initialization
function initializeCharts() {
    const ctx = document.getElementById('vulnerabilityChart').getContext('2d');
    
    const chartData = {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
        datasets: [
            {
                label: 'Critical',
                data: [5, 8, 12, 15, 18, 20, 23],
                backgroundColor: '#FF5459',
                borderColor: '#FF5459',
                tension: 0.4
            },
            {
                label: 'High',
                data: [15, 22, 28, 35, 42, 48, 55],
                backgroundColor: '#E68161',
                borderColor: '#E68161',
                tension: 0.4
            },
            {
                label: 'Medium',
                data: [25, 35, 45, 52, 58, 65, 78],
                backgroundColor: '#32808D',
                borderColor: '#32808D',
                tension: 0.4
            }
        ]
    };

    vulnerabilityChart = new Chart(ctx, {
        type: 'line',
        data: chartData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        color: '#f5f5f5',
                        font: {
                            size: 12
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#a7a9a9'
                    }
                },
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#a7a9a9'
                    }
                }
            }
        }
    });
}

// Render activity feed
function renderActivityFeed() {
    const activityFeed = document.getElementById('activity-feed');
    
    const activities = [
        {
            title: 'Critical SQL Injection Found',
            description: 'Web App Agent discovered SQL injection in login form',
            time: '2 minutes ago',
            type: 'critical'
        },
        {
            title: 'Scan Completed',
            description: 'Full scan of example.com completed successfully',
            time: '15 minutes ago',
            type: 'success'
        },
        {
            title: 'New Agent Deployed',
            description: 'API Agent started scanning REST endpoints', 
            time: '1 hour ago',
            type: 'info'
        },
        {
            title: 'Report Generated',
            description: 'Security assessment report ready for download',
            time: '2 hours ago',
            type: 'success'
        }
    ];

    const activityHTML = activities.map(activity => `
        <div class="activity-item">
            <div class="activity-content">
                <h4 class="activity-title">${activity.title}</h4>
                <p class="activity-description">${activity.description}</p>
            </div>
            <div class="activity-time">${activity.time}</div>
        </div>
    `).join('');

    activityFeed.innerHTML = activityHTML;
}

// Render active scans - FIXED
function renderActiveScans() {
    const activeScansContainer = document.getElementById('active-scans');
    
    const scansHTML = appData.scans.map(scan => {
        const progress = scan.progress || 100;
        const statusClass = scan.status === 'running' ? 'info' : 'success';
        
        return `
            <div class="scan-item">
                <div class="scan-target">
                    <strong>${scan.target}</strong>
                    <div class="scan-type">${scan.scanType}</div>
                </div>
                <div class="scan-status">
                    <span class="status status--${statusClass}">${scan.status}</span>
                    ${scan.status === 'running' ? `
                        <div class="scan-progress">
                            <div class="scan-progress-bar" style="width: ${progress}%"></div>
                        </div>
                    ` : ''}
                </div>
                <div class="vulnerability-counts">
                    <div class="vuln-count critical">🔴 ${scan.critical}</div>
                    <div class="vuln-count high">🟠 ${scan.high}</div>
                    <div class="vuln-count medium">🟡 ${scan.medium}</div>
                </div>
                <div class="scan-agents">
                    ${scan.agents.join(', ')}
                </div>
                <div class="scan-actions">
                    <button class="btn btn--sm btn--outline" onclick="viewScanDetails('${scan.id}')">View</button>
                </div>
            </div>
        `;
    }).join('');

    activeScansContainer.innerHTML = scansHTML;
}

// Render AI agents - FIXED
function renderAgents() {
    const agentsGrid = document.getElementById('agents-grid');
    
    const agentsHTML = appData.agents.map(agent => `
        <div class="agent-card">
            <div class="agent-header">
                <h3 class="agent-name">${agent.name}</h3>
                <div class="agent-status">
                    <div class="status-dot"></div>
                    ${agent.status}
                </div>
            </div>
            <p class="agent-description">${agent.description}</p>
            <div class="agent-metrics">
                <div class="metric">
                    <p class="metric-value">${agent.successRate}%</p>
                    <p class="metric-label">Success Rate</p>
                </div>
                <div class="metric">
                    <p class="metric-value">24/7</p>
                    <p class="metric-label">Uptime</p>
                </div>
            </div>
            <div class="agent-capabilities">
                <h4>Capabilities</h4>
                <div class="capabilities-list">
                    ${agent.capabilities.map(cap => `<span class="capability-tag">${cap}</span>`).join('')}
                </div>
            </div>
            <button class="btn btn--outline btn--full-width" onclick="configureAgent('${agent.name}')">Configure Agent</button>
        </div>
    `).join('');

    agentsGrid.innerHTML = agentsHTML;
}

// Render reports - FIXED
function renderReports() {
    const reportsGrid = document.getElementById('reports-grid');
    
    const reportsHTML = appData.reports.map(report => `
        <div class="report-card" onclick="downloadReport('${report.id}')">
            <div class="report-header">
                <h4 class="report-title">${report.title}</h4>
                <span class="report-severity ${report.severity.toLowerCase()}">${report.severity}</span>
            </div>
            <div class="report-meta">
                <span>${new Date(report.generated).toLocaleDateString()}</span>
                <span>${report.format}</span>
            </div>
            <div class="report-stats">
                <div class="report-stat">
                    <div class="report-stat-value">${report.vulnerabilities}</div>
                    <div>Vulnerabilities</div>
                </div>
                <div class="report-stat">
                    <div class="report-stat-value">${report.pages}</div>
                    <div>Pages</div>
                </div>
            </div>
        </div>
    `).join('');

    reportsGrid.innerHTML = reportsHTML;
}

// Render vulnerabilities - FIXED
function renderVulnerabilities() {
    const vulnerabilitiesList = document.getElementById('vulnerabilities-list');
    
    let filteredVulns = appData.vulnerabilities;
    if (currentFilter) {
        filteredVulns = appData.vulnerabilities.filter(vuln => vuln.severity === currentFilter);
    }
    
    const vulnerabilitiesHTML = filteredVulns.map(vuln => `
        <div class="vulnerability-item" onclick="showVulnerabilityDetails('${vuln.id}')">
            <div class="vulnerability-header">
                <h4 class="vulnerability-title">${vuln.title}</h4>
                <span class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
            </div>
            <div class="vulnerability-meta">
                <span>CVSS: ${vuln.cvss}</span>
                <span>URL: ${vuln.url}</span>
                <span>Parameter: ${vuln.parameter}</span>
            </div>
            <p class="vulnerability-description">${vuln.description}</p>
            <div class="vulnerability-footer">
                <div class="discovered-by">
                    <span>🤖</span>
                    <span>Discovered by ${vuln.discoveredBy}</span>
                </div>
                <span>${new Date(vuln.timestamp).toLocaleString()}</span>
            </div>
        </div>
    `).join('');

    vulnerabilitiesList.innerHTML = vulnerabilitiesHTML;
}

// Initialize forms - FIXED
function initializeForms() {
    // Quick scan form - FIXED
    const quickScanForm = document.getElementById('quick-scan-form');
    if (quickScanForm) {
        quickScanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            const targetUrl = this.querySelector('input[type="url"]').value;
            if (targetUrl) {
                startQuickScan(targetUrl);
                this.querySelector('input[type="url"]').value = ''; // Clear form
            }
        });
    }

    // New scan form - FIXED
    const newScanForm = document.getElementById('new-scan-form');
    if (newScanForm) {
        newScanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            const targetUrl = this.querySelector('input[type="url"]').value;
            const scanType = this.querySelector('select').value;
            const selectedAgents = Array.from(this.querySelectorAll('input[type="checkbox"]:checked'))
                .map(cb => cb.nextSibling.textContent.trim());
            
            if (targetUrl) {
                startNewScan(targetUrl, scanType, selectedAgents);
                this.reset(); // Clear form
            }
        });
    }

    // Severity filter - FIXED
    const severityFilter = document.getElementById('severity-filter');
    if (severityFilter) {
        severityFilter.addEventListener('change', function(e) {
            e.stopPropagation();
            currentFilter = this.value;
            renderVulnerabilities();
        });
    }
}

// Initialize modal - FIXED
function initializeModal() {
    const modal = document.getElementById('vulnerability-modal');
    const closeBtn = modal.querySelector('.modal-close');
    
    closeBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        modal.classList.add('hidden');
    });
    
    modal.addEventListener('click', function(e) {
        if (e.target === modal) {
            modal.classList.add('hidden');
        }
    });
}

// Show vulnerability details in modal - FIXED
function showVulnerabilityDetails(vulnId) {
    const vulnerability = appData.vulnerabilities.find(v => v.id === vulnId);
    if (!vulnerability) return;

    const modal = document.getElementById('vulnerability-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalBody = document.getElementById('modal-body');

    modalTitle.textContent = vulnerability.title;
    
    modalBody.innerHTML = `
        <div class="detail-section">
            <h4>Severity & Score</h4>
            <p><strong>Severity:</strong> <span class="severity-badge ${vulnerability.severity.toLowerCase()}">${vulnerability.severity}</span></p>
            <p><strong>CVSS Score:</strong> ${vulnerability.cvss}</p>
        </div>
        
        <div class="detail-section">
            <h4>Vulnerability Details</h4>
            <p><strong>URL:</strong> ${vulnerability.url}</p>
            <p><strong>Parameter:</strong> ${vulnerability.parameter}</p>
            <p><strong>Description:</strong> ${vulnerability.description}</p>
        </div>
        
        <div class="detail-section">
            <h4>Proof of Concept</h4>
            <div class="code-block">${vulnerability.payload}</div>
        </div>
        
        <div class="detail-section">
            <h4>Remediation</h4>
            <p>${vulnerability.remediation}</p>
        </div>
        
        <div class="detail-section">
            <h4>Discovery Information</h4>
            <p><strong>Discovered by:</strong> ${vulnerability.discoveredBy}</p>
            <p><strong>Timestamp:</strong> ${new Date(vulnerability.timestamp).toLocaleString()}</p>
        </div>
    `;

    modal.classList.remove('hidden');
}

// Start quick scan - API INTEGRATED
async function startQuickScan(targetUrl) {
    try {
        const notification = createNotification('Creating quick scan for ' + targetUrl, 'info');
        document.body.appendChild(notification);

        // Create scan via API
        const scanData = {
            target: targetUrl,
            scanType: 'Quick Scan',
            agents: ['Web App Agent', 'Recon Agent']
        };

        const newScan = await apiRequest('/scans', {
            method: 'POST',
            body: JSON.stringify(scanData)
        });

        // Add to local data and update UI
        appData.scans.unshift(newScan);
        renderActiveScans();

        const successNotification = createNotification(`Quick scan created successfully for ${targetUrl}`, 'success');
        document.body.appendChild(successNotification);

        // Start real scanning
        await startRealScan(newScan.id);

    } catch (error) {
        console.error('Failed to start quick scan:', error);
        showErrorNotification('Failed to start scan. Please try again.');
    }
}

// Start new scan - API INTEGRATED
async function startNewScan(targetUrl, scanType, selectedAgents) {
    try {
        const notification = createNotification(`Creating ${scanType} for ${targetUrl}`, 'info');
        document.body.appendChild(notification);

        // Create scan via API
        const scanData = {
            target: targetUrl,
            scanType: scanType,
            agents: selectedAgents.length > 0 ? selectedAgents : ['Web App Agent']
        };

        const newScan = await apiRequest('/scans', {
            method: 'POST',
            body: JSON.stringify(scanData)
        });

        // Add to local data and update UI
        appData.scans.unshift(newScan);
        renderActiveScans();

        const successNotification = createNotification(`${scanType} created successfully for ${targetUrl}`, 'success');
        document.body.appendChild(successNotification);

        // Start real scanning
        await startRealScan(newScan.id);

    } catch (error) {
        console.error('Failed to start new scan:', error);
        showErrorNotification('Failed to start scan. Please try again.');
    }
}

// View scan details - NEW
function viewScanDetails(scanId) {
    const scan = appData.scans.find(s => s.id === scanId);
    if (scan) {
        const notification = createNotification('Viewing details for ' + scan.target, 'info');
        document.body.appendChild(notification);
    }
}

// Configure agent - NEW
function configureAgent(agentName) {
    const notification = createNotification(`Configuring ${agentName} settings`, 'info');
    document.body.appendChild(notification);
}

// Start real scan via API - REAL SCANNING
async function startRealScan(scanId) {
    try {
        console.log(`🔍 Starting REAL security scan for scan ID: ${scanId}`);

        // Trigger real scanning endpoint
        const result = await apiRequest(`/scan/${scanId}`, {
            method: 'POST'
        });

        console.log('✅ Real scan started:', result);

        // Start polling for scan progress
        pollScanProgress(scanId);

    } catch (error) {
        console.error('❌ Failed to start real scan:', error);

        // Check if it's a validation error
        if (error.message.includes('Cannot scan')) {
            showErrorNotification(`Security Error: ${error.message}`);
        } else {
            showErrorNotification('Failed to start real scan. Please try again.');
        }
    }
}

// Poll scan progress for real-time updates
async function pollScanProgress(scanId) {
    const pollInterval = setInterval(async () => {
        try {
            // Get updated scan data
            const scan = await apiRequest(`/scans/${scanId}`);

            // Update local data
            const scanIndex = appData.scans.findIndex(s => s.id === scanId);
            if (scanIndex !== -1) {
                appData.scans[scanIndex] = scan;
                renderActiveScans();
            }

            // Check if scan is complete
            if (scan.status === 'completed' || scan.status === 'failed') {
                clearInterval(pollInterval);

                // Reload all data to get vulnerabilities
                await loadScans();
                await loadVulnerabilities();
                await loadStats();

                const statusMessage = scan.status === 'completed'
                    ? `✅ Real scan completed for ${scan.target}`
                    : `❌ Scan failed for ${scan.target}`;

                const notification = createNotification(statusMessage,
                    scan.status === 'completed' ? 'success' : 'error');
                document.body.appendChild(notification);
            }

        } catch (error) {
            console.error('Failed to poll scan progress:', error);
            clearInterval(pollInterval);
        }
    }, 3000); // Poll every 3 seconds
}

// Keep simulation function for demo/testing
async function simulateApiScan(scanId) {
    try {
        console.log(`🎭 Starting DEMO scan simulation for scan ID: ${scanId}`);

        // Trigger simulation endpoint
        await apiRequest(`/simulate/scan/${scanId}`, {
            method: 'POST'
        });

        // Reload data to get updated scan with vulnerabilities
        await loadScans();
        await loadVulnerabilities();
        await loadStats();

        const scan = appData.scans.find(s => s.id === scanId);
        if (scan) {
            const notification = createNotification(`Demo scan completed for ${scan.target}`, 'success');
            document.body.appendChild(notification);
        }

    } catch (error) {
        console.error('Failed to simulate scan:', error);
        showErrorNotification('Scan simulation failed');
    }
}

// Legacy simulate scan progress - KEPT FOR COMPATIBILITY
function simulateScanProgress(scanId) {
    const scan = appData.scans.find(s => s.id === scanId);
    if (!scan) return;

    const progressInterval = setInterval(async () => {
        scan.progress += Math.random() * 15;

        if (scan.progress >= 100) {
            scan.progress = 100;
            scan.status = 'completed';
            scan.completed = new Date().toISOString();
            clearInterval(progressInterval);

            // Update via API
            try {
                await apiRequest(`/scans/${scanId}`, {
                    method: 'PUT',
                    body: JSON.stringify({ status: 'completed', progress: 100 })
                });
            } catch (error) {
                console.error('Failed to update scan status:', error);
            }

            const notification = createNotification(`Scan completed for ${scan.target}`, 'success');
            document.body.appendChild(notification);
        }

        renderActiveScans();
    }, 2000);
}

// Create notification - ENHANCED
function createNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification--${type}`;

    // Set colors based on type
    let backgroundColor = 'var(--color-surface)';
    let borderColor = 'var(--color-border)';
    let textColor = 'var(--color-text)';

    if (type === 'error') {
        backgroundColor = '#2d1b1b';
        borderColor = '#ff5459';
        textColor = '#ff9999';
    } else if (type === 'success') {
        backgroundColor = '#1b2d1b';
        borderColor = '#4caf50';
        textColor = '#99ff99';
    } else if (type === 'info') {
        backgroundColor = '#1b1b2d';
        borderColor = '#2196f3';
        textColor = '#99ccff';
    }

    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${backgroundColor};
        border: 1px solid ${borderColor};
        border-radius: var(--radius-base);
        padding: var(--space-16);
        box-shadow: var(--shadow-lg);
        z-index: 1001;
        max-width: 300px;
        color: ${textColor};
        font-size: var(--font-size-sm);
        animation: slideIn 0.3s ease-out;
    `;
    notification.textContent = message;

    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);

    return notification;
}

// Download report - FIXED
function downloadReport(reportId) {
    const report = appData.reports.find(r => r.id === reportId);
    if (report) {
        const notification = createNotification('Downloading ' + report.title, 'success');
        document.body.appendChild(notification);
    }
}

// Real-time updates with API polling
function startRealTimeUpdates() {
    setInterval(async () => {
        try {
            // Poll for updates from the API
            await loadStats();
            await loadScans();

            // Only reload vulnerabilities if there are running scans
            const runningScans = appData.scans.filter(scan => scan.status === 'running');
            if (runningScans.length > 0) {
                await loadVulnerabilities();
            }

        } catch (error) {
            console.error('Failed to update real-time data:', error);
        }
    }, 10000); // Update every 10 seconds
}

// Utility functions
function formatDate(dateString) {
    return new Date(dateString).toLocaleDateString();
}

function formatTime(dateString) {
    return new Date(dateString).toLocaleTimeString();
}

function getSeverityColor(severity) {
    switch (severity.toLowerCase()) {
        case 'critical': return '#FF5459';
        case 'high': return '#E68161';
        case 'medium': return '#32808D';
        case 'low': return '#626C71';
        default: return '#626C71';
    }
}