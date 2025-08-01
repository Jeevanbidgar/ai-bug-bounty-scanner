// API Configuration
const API_BASE_URL = 'http://localhost:5000/api';

// Socket.IO client initialization
let socket = null;
let connectionStatus = 'disconnected';

// Global app state
const appData = {
    scans: [],
    vulnerabilities: [],
    reports: [],
    agents: [],
    stats: {}
};

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

// Socket.IO Real-time Communication
function initializeSocket() {
    socket = io('http://localhost:5000');

    // Connection events
    socket.on('connect', () => {
        console.log('✅ Connected to server via Socket.IO');
        connectionStatus = 'connected';
        updateConnectionStatus('connected', 'Connected');

        // Send a test message
        socket.emit('ping', { message: 'Hello from frontend!', timestamp: new Date().toISOString() });
    });

    socket.on('disconnect', () => {
        console.log('❌ Disconnected from server');
        connectionStatus = 'disconnected';
        updateConnectionStatus('disconnected', 'Disconnected');
    });

    socket.on('connect_error', (error) => {
        console.error('❌ Connection error:', error);
        connectionStatus = 'error';
        updateConnectionStatus('error', 'Connection Error');
    });

    // Server response events
    socket.on('connection_status', (data) => {
        console.log('📡 Server connection status:', data);
    });

    socket.on('pong', (data) => {
        console.log('🏓 Received pong from server:', data);
    });

    // Real-time scan progress updates
    socket.on('scan_progress_update', (data) => {
        console.log('📊 Scan progress update:', data);
        handleRealTimeScanProgress(data);
    });

    return socket;
}

// Update connection status in UI
function updateConnectionStatus(status, text) {
    const statusElement = document.getElementById('connection-status');
    const textElement = document.getElementById('connection-text');

    if (statusElement && textElement) {
        statusElement.className = `w-3 h-3 rounded-full ${
            status === 'connected' ? 'bg-green-500' :
            status === 'error' ? 'bg-red-500' : 'bg-gray-500'
        }`;
        textElement.textContent = text;
        textElement.className = `text-sm ${
            status === 'connected' ? 'text-green-400' :
            status === 'error' ? 'text-red-400' : 'text-gray-400'
        }`;
    }
}

// Handle real-time scan progress updates
function handleRealTimeScanProgress(data) {
    const { scan_id, progress, current_test, status } = data;

    // Update local scan data
    const scanIndex = appData.scans.findIndex(s => s.id === scan_id);
    if (scanIndex !== -1) {
        appData.scans[scanIndex].progress = progress;
        appData.scans[scanIndex].current_test = current_test;
        appData.scans[scanIndex].status = status;

        // Show notification for scan completion
        if (status === 'completed' && progress === 100) {
            const notification = createNotification(
                `✅ Real-time scan completed for ${appData.scans[scanIndex].target}`,
                'success'
            );
            document.body.appendChild(notification);
        } else if (status === 'failed') {
            const notification = createNotification(
                `❌ Real-time scan failed for ${appData.scans[scanIndex].target}`,
                'error'
            );
            document.body.appendChild(notification);
        }
    }

    // Update progress modal if it's open
    const modal = document.getElementById('scan-progress-modal');
    if (modal && !modal.classList.contains('hidden')) {
        updateScanProgressModal({
            id: scan_id,
            progress: progress,
            current_test: current_test,
            status: status
        });

        // Auto-hide modal when scan completes
        if (status === 'completed' || status === 'failed') {
            setTimeout(() => {
                hideScanProgressModal();
            }, 2000);
        }
    }

    // Update active scans display
    renderActiveScans();
}

// Initialize Socket.IO test functionality
function initializeSocketTest() {
    const testButton = document.getElementById('test-socket');
    if (testButton) {
        testButton.addEventListener('click', () => {
            if (socket && socket.connected) {
                // Send test message
                const testData = {
                    message: 'Test message from frontend',
                    timestamp: new Date().toISOString(),
                    random: Math.random()
                };

                socket.emit('ping', testData);

                // Show notification
                const notification = createNotification('🔄 Socket.IO test message sent!', 'info');
                document.body.appendChild(notification);

                console.log('📤 Sent test message:', testData);
            } else {
                const notification = createNotification('❌ Socket.IO not connected', 'error');
                document.body.appendChild(notification);
            }
        });
    }
}

// Application data will be loaded from API and stored in the global appData object

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

    // Initialize Socket.IO for real-time communication
    initializeSocket();

    // Initialize Socket.IO test button
    initializeSocketTest();

    initializeNavigation();
    await initializeCharts();
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

    await renderActivityFeed();
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

// Chart initialization - REAL DATA
async function initializeCharts() {
    const ctx = document.getElementById('vulnerabilityChart').getContext('2d');

    try {
        // Get real vulnerability data
        const vulnerabilities = await apiRequest('/vulnerabilities');
        const chartData = generateVulnerabilityTrendsData(vulnerabilities);

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

    } catch (error) {
        console.error('Failed to load vulnerability chart data:', error);
        // Fallback to empty chart
        const emptyChartData = {
            labels: ['No Data'],
            datasets: [
                {
                    label: 'Critical',
                    data: [0],
                    backgroundColor: '#FF5459',
                    borderColor: '#FF5459',
                    tension: 0.4
                },
                {
                    label: 'High',
                    data: [0],
                    backgroundColor: '#E68161',
                    borderColor: '#E68161',
                    tension: 0.4
                },
                {
                    label: 'Medium',
                    data: [0],
                    backgroundColor: '#32808D',
                    borderColor: '#32808D',
                    tension: 0.4
                }
            ]
        };

        vulnerabilityChart = new Chart(ctx, {
            type: 'line',
            data: emptyChartData,
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
}

// Generate real vulnerability trends data from actual vulnerabilities
function generateVulnerabilityTrendsData(vulnerabilities) {
    // Get last 6 months
    const months = [];
    const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const now = new Date();

    for (let i = 5; i >= 0; i--) {
        const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
        months.push({
            label: monthNames[date.getMonth()],
            year: date.getFullYear(),
            month: date.getMonth()
        });
    }

    // Initialize data arrays
    const criticalData = new Array(6).fill(0);
    const highData = new Array(6).fill(0);
    const mediumData = new Array(6).fill(0);

    // Process vulnerabilities
    vulnerabilities.forEach(vuln => {
        if (!vuln.timestamp) return;

        const vulnDate = new Date(vuln.timestamp);
        const vulnMonth = vulnDate.getMonth();
        const vulnYear = vulnDate.getFullYear();

        // Find matching month index
        const monthIndex = months.findIndex(m =>
            m.month === vulnMonth && m.year === vulnYear
        );

        if (monthIndex !== -1) {
            switch (vuln.severity.toLowerCase()) {
                case 'critical':
                    criticalData[monthIndex]++;
                    break;
                case 'high':
                    highData[monthIndex]++;
                    break;
                case 'medium':
                    mediumData[monthIndex]++;
                    break;
            }
        }
    });

    // If no data, show a message in the chart
    const hasData = criticalData.some(v => v > 0) || highData.some(v => v > 0) || mediumData.some(v => v > 0);

    if (!hasData) {
        return {
            labels: ['No vulnerability data available'],
            datasets: [
                {
                    label: 'Critical',
                    data: [0],
                    backgroundColor: '#FF5459',
                    borderColor: '#FF5459',
                    tension: 0.4
                },
                {
                    label: 'High',
                    data: [0],
                    backgroundColor: '#E68161',
                    borderColor: '#E68161',
                    tension: 0.4
                },
                {
                    label: 'Medium',
                    data: [0],
                    backgroundColor: '#32808D',
                    borderColor: '#32808D',
                    tension: 0.4
                }
            ]
        };
    }

    return {
        labels: months.map(m => m.label),
        datasets: [
            {
                label: 'Critical',
                data: criticalData,
                backgroundColor: '#FF5459',
                borderColor: '#FF5459',
                tension: 0.4
            },
            {
                label: 'High',
                data: highData,
                backgroundColor: '#E68161',
                borderColor: '#E68161',
                tension: 0.4
            },
            {
                label: 'Medium',
                data: mediumData,
                backgroundColor: '#32808D',
                borderColor: '#32808D',
                tension: 0.4
            }
        ]
    };
}

// Update vulnerability chart with new data
async function updateVulnerabilityChart() {
    if (!vulnerabilityChart) return;

    try {
        const vulnerabilities = await apiRequest('/vulnerabilities');
        const newChartData = generateVulnerabilityTrendsData(vulnerabilities);

        // Update chart data
        vulnerabilityChart.data = newChartData;
        vulnerabilityChart.update('none'); // Update without animation for real-time

    } catch (error) {
        console.error('Failed to update vulnerability chart:', error);
    }
}

// Render activity feed - REAL DATA
async function renderActivityFeed() {
    const activityFeed = document.getElementById('activity-feed');

    try {
        // Get real data from API
        const [scans, vulnerabilities, reports] = await Promise.all([
            apiRequest('/scans'),
            apiRequest('/vulnerabilities'),
            apiRequest('/reports')
        ]);

        // Generate real activity items
        const activities = [];

        // Add recent vulnerabilities
        vulnerabilities.slice(0, 3).forEach(vuln => {
            activities.push({
                title: `${vuln.severity.toUpperCase()} ${vuln.type} Found`,
                description: `${vuln.agent} discovered ${vuln.type.toLowerCase()} in ${vuln.location || 'target'}`,
                time: getRelativeTime(vuln.timestamp),
                type: getSeverityType(vuln.severity),
                timestamp: new Date(vuln.timestamp)
            });
        });

        // Add recent scan completions
        scans.filter(scan => scan.status === 'completed').slice(0, 2).forEach(scan => {
            activities.push({
                title: 'Scan Completed',
                description: `${scan.scanType} of ${scan.target} completed successfully`,
                time: getRelativeTime(scan.completed),
                type: 'success',
                timestamp: new Date(scan.completed)
            });
        });

        // Add recent scan starts
        scans.filter(scan => scan.status === 'running').slice(0, 2).forEach(scan => {
            activities.push({
                title: 'Scan Started',
                description: `${scan.scanType} initiated for ${scan.target}`,
                time: getRelativeTime(scan.started),
                type: 'info',
                timestamp: new Date(scan.started)
            });
        });

        // Add recent reports
        reports.slice(0, 1).forEach(report => {
            activities.push({
                title: 'Report Generated',
                description: `Security assessment report created: ${report.title}`,
                time: getRelativeTime(report.created_at),
                type: 'success',
                timestamp: new Date(report.created_at)
            });
        });

        // Sort by timestamp (most recent first)
        activities.sort((a, b) => b.timestamp - a.timestamp);

        // Take only the 5 most recent activities
        const recentActivities = activities.slice(0, 5);

        // If no real activities, show a message
        if (recentActivities.length === 0) {
            activityFeed.innerHTML = `
                <div class="activity-item">
                    <div class="activity-content">
                        <h4 class="activity-title">No Recent Activity</h4>
                        <p class="activity-description">Start a scan to see real-time activity updates</p>
                    </div>
                    <div class="activity-time">Now</div>
                </div>
            `;
            return;
        }

        const activityHTML = recentActivities.map(activity => `
            <div class="activity-item">
                <div class="activity-content">
                    <h4 class="activity-title">${activity.title}</h4>
                    <p class="activity-description">${activity.description}</p>
                </div>
                <div class="activity-time">${activity.time}</div>
            </div>
        `).join('');

        activityFeed.innerHTML = activityHTML;

    } catch (error) {
        console.error('Failed to load activity feed:', error);
        activityFeed.innerHTML = `
            <div class="activity-item">
                <div class="activity-content">
                    <h4 class="activity-title">Unable to Load Activity</h4>
                    <p class="activity-description">Failed to fetch recent activity data</p>
                </div>
                <div class="activity-time">Error</div>
            </div>
        `;
    }
}

// Helper function to get relative time
function getRelativeTime(timestamp) {
    if (!timestamp) return 'Unknown';

    const now = new Date();
    const time = new Date(timestamp);
    const diffMs = now - time;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    return time.toLocaleDateString();
}

// Helper function to map severity to activity type
function getSeverityType(severity) {
    switch (severity.toLowerCase()) {
        case 'critical': return 'critical';
        case 'high': return 'warning';
        case 'medium': return 'info';
        case 'low': return 'success';
        default: return 'info';
    }
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

// Initialize forms - ENHANCED WITH SCAN TYPE LOGIC
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

    // New scan form - ENHANCED WITH SCAN TYPE LOGIC
    const newScanForm = document.getElementById('new-scan-form');
    if (newScanForm) {
        // Add scan type change listener
        const scanTypeSelect = newScanForm.querySelector('select');
        if (scanTypeSelect) {
            scanTypeSelect.addEventListener('change', function() {
                updateAgentSelection(this.value);
            });
            // Initialize with default selection
            updateAgentSelection(scanTypeSelect.value);
        }

        newScanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            e.stopPropagation();

            const targetUrl = this.querySelector('input[type="url"]').value;
            const scanType = this.querySelector('select').value;
            const selectedAgents = getSelectedAgentsForScanType(scanType);

            if (targetUrl) {
                startNewScan(targetUrl, scanType, selectedAgents);
                this.reset(); // Clear form
                // Re-initialize agent selection after reset
                updateAgentSelection(scanType);
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

// Scan type configuration
const SCAN_TYPE_CONFIG = {
    'Quick Scan': {
        agents: ['Web App Agent', 'Report Agent'],
        description: 'Fast vulnerability assessment focusing on web application security',
        duration: '5-10 minutes',
        readonly: true,
        agentInfo: 'Uses Web App Agent and Report Agent automatically'
    },
    'Full Scan': {
        agents: ['Recon Agent', 'Web App Agent', 'Network Agent', 'API Agent', 'Report Agent'],
        description: 'Comprehensive security assessment using all available agents',
        duration: '30-60 minutes',
        readonly: true,
        agentInfo: 'Uses all 5 security agents automatically'
    },
    'Custom Scan': {
        agents: [], // User selectable
        description: 'Choose specific agents for targeted testing',
        duration: 'Varies based on selected agents',
        readonly: false,
        agentInfo: 'Select which agents to use below'
    }
};

// Update agent selection based on scan type
function updateAgentSelection(scanType) {
    const agentSelectionGroup = document.getElementById('ai-agents-group');
    const agentSelection = document.querySelector('.agent-selection');

    if (!agentSelection || !agentSelectionGroup) return;

    const config = SCAN_TYPE_CONFIG[scanType];
    if (!config) return;

    // Show/hide the entire AI Agents section based on scan type
    if (config.readonly) {
        // For Quick and Full scans, hide the AI Agents section
        agentSelectionGroup.style.display = 'none';
        console.log(`🔧 ${scanType}: AI Agents section hidden (using predefined agents: ${config.agents.join(', ')})`);
    } else {
        // For Custom scan, show the AI Agents section
        agentSelectionGroup.style.display = 'block';
        console.log(`🔧 ${scanType}: AI Agents section shown (user can select agents)`);

        // Enable all checkboxes for custom selection
        const checkboxes = agentSelection.querySelectorAll('input[type="checkbox"]');
        checkboxes.forEach(checkbox => {
            checkbox.disabled = false;
            checkbox.parentElement.style.opacity = '1';
        });
    }

    // Update scan type description
    updateScanTypeDescription(scanType, config);
}

// Update scan type description
function updateScanTypeDescription(scanType, config) {
    let descElement = document.querySelector('.scan-type-description');

    if (!descElement) {
        // Create description element if it doesn't exist
        const scanTypeGroup = document.querySelector('select').parentElement;
        descElement = document.createElement('div');
        descElement.className = 'scan-type-description';
        scanTypeGroup.appendChild(descElement);
    }

    descElement.innerHTML = `
        <div class="scan-description">
            <p><strong>${scanType}:</strong> ${config.description}</p>
            <p><small>Estimated duration: ${config.duration}</small></p>
            <p><small><strong>Agents:</strong> ${config.agentInfo}</small></p>
        </div>
    `;
}

// Get selected agents for scan type
function getSelectedAgentsForScanType(scanType) {
    const config = SCAN_TYPE_CONFIG[scanType];

    if (config.readonly) {
        // For Quick and Full scans, return predefined agents
        return config.agents;
    } else {
        // For Custom scan, return user-selected agents
        const selectedAgents = Array.from(document.querySelectorAll('.agent-selection input[type="checkbox"]:checked'))
            .map(cb => cb.nextSibling.textContent.trim());

        // Ensure at least one agent is selected
        return selectedAgents.length > 0 ? selectedAgents : ['Web App Agent'];
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

// Show modal with custom content
function showModal(content) {
    // Create modal if it doesn't exist
    let modal = document.getElementById('custom-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'custom-modal';
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal-container">
                <div id="custom-modal-content"></div>
            </div>
        `;
        document.body.appendChild(modal);

        // Add click outside to close
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                closeModal();
            }
        });
    }

    // Set content and show
    document.getElementById('custom-modal-content').innerHTML = content;
    modal.classList.remove('hidden');
    modal.style.display = 'flex';
}

// Close modal
function closeModal() {
    const modal = document.getElementById('custom-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.style.display = 'none';
    }
}

// Start quick scan - API INTEGRATED WITH SCAN TYPE CONFIG
async function startQuickScan(targetUrl) {
    try {
        const notification = createNotification('Creating quick scan for ' + targetUrl, 'info');
        document.body.appendChild(notification);

        // Get Quick Scan configuration
        const quickScanConfig = SCAN_TYPE_CONFIG['Quick Scan'];

        // Create scan via API
        const scanData = {
            target: targetUrl,
            scanType: 'Quick Scan',
            agents: quickScanConfig.agents
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

// View scan details - ENHANCED
async function viewScanDetails(scanId) {
    try {
        // Get fresh scan data from API
        const scan = await apiRequest(`/scans/${scanId}`);

        // Get vulnerabilities for this scan
        const allVulns = await apiRequest('/vulnerabilities');
        const scanVulns = allVulns.filter(v => v.scanId === scanId);

        // Create modal content
        const modalContent = `
            <div class="scan-details-modal">
                <div class="scan-details-header">
                    <h2>Scan Details: ${scan.target}</h2>
                    <button class="modal-close" onclick="closeModal()">&times;</button>
                </div>
                <div class="scan-details-content">
                    <div class="scan-info-grid">
                        <div class="scan-info-item">
                            <label>Target:</label>
                            <span>${scan.target}</span>
                        </div>
                        <div class="scan-info-item">
                            <label>Status:</label>
                            <span class="status status--${scan.status}">${scan.status}</span>
                        </div>
                        <div class="scan-info-item">
                            <label>Progress:</label>
                            <span>${scan.progress}%</span>
                        </div>
                        <div class="scan-info-item">
                            <label>Started:</label>
                            <span>${new Date(scan.started).toLocaleString()}</span>
                        </div>
                        <div class="scan-info-item">
                            <label>Scan Type:</label>
                            <span>${scan.scanType}</span>
                        </div>
                        <div class="scan-info-item">
                            <label>Agents:</label>
                            <span>${scan.agents.join(', ')}</span>
                        </div>
                    </div>

                    <div class="vulnerabilities-section">
                        <h3>Vulnerabilities Found (${scanVulns.length})</h3>
                        <div class="vulnerabilities-list">
                            ${scanVulns.length > 0 ? scanVulns.map(vuln => `
                                <div class="vulnerability-item">
                                    <div class="vuln-header">
                                        <span class="vuln-title">${vuln.title}</span>
                                        <span class="vuln-severity ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                                    </div>
                                    <div class="vuln-details">
                                        <p><strong>Description:</strong> ${vuln.description}</p>
                                        <p><strong>URL:</strong> ${vuln.url}</p>
                                        <p><strong>Discovered by:</strong> ${vuln.discoveredBy}</p>
                                        ${vuln.cvss ? `<p><strong>CVSS Score:</strong> ${vuln.cvss}</p>` : ''}
                                    </div>
                                </div>
                            `).join('') : '<p>No vulnerabilities found yet.</p>'}
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Show modal
        showModal(modalContent);

    } catch (error) {
        console.error('Failed to load scan details:', error);
        showErrorNotification('Failed to load scan details');
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

        // Get scan details for progress modal
        const scan = await apiRequest(`/scans/${scanId}`);

        // Show progress modal
        showScanProgressModal(scan);

        // Trigger real scanning endpoint
        const result = await apiRequest(`/scan/${scanId}`, {
            method: 'POST'
        });

        console.log('✅ Real scan started:', result);

        // Request real-time progress updates via Socket.IO
        if (socket && socket.connected) {
            socket.emit('scan_progress_request', { scan_id: scanId });
        } else {
            // Fallback to polling if Socket.IO is not available
            pollScanProgress(scanId);
        }

    } catch (error) {
        console.error('❌ Failed to start real scan:', error);

        // Hide progress modal on error
        hideScanProgressModal();

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

            // Update progress modal
            updateScanProgressModal(scan);

            // Update local data
            const scanIndex = appData.scans.findIndex(s => s.id === scanId);
            if (scanIndex !== -1) {
                appData.scans[scanIndex] = scan;
                renderActiveScans();
            }

            // Check if scan is complete
            if (scan.status === 'completed' || scan.status === 'failed') {
                clearInterval(pollInterval);

                // Hide progress modal after a short delay
                setTimeout(() => {
                    hideScanProgressModal();
                }, 2000);

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
            hideScanProgressModal();
        }
    }, 2000); // Poll every 2 seconds for more responsive updates
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

            // Update activity feed with real data
            await renderActivityFeed();

            // Update vulnerability trends chart
            await updateVulnerabilityChart();

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

// Scan Progress Modal Functions
function showScanProgressModal(scan) {
    const modal = document.getElementById('scan-progress-modal');
    const targetDisplay = document.getElementById('scan-target-display');
    const scanTypeDisplay = document.getElementById('scan-type-display');
    const scanAgentsDisplay = document.getElementById('scan-agents-display');

    // Set initial values
    targetDisplay.textContent = scan.target;
    scanTypeDisplay.textContent = scan.scanType;
    scanAgentsDisplay.textContent = scan.agents.join(', ');

    // Show modal
    modal.classList.remove('hidden');

    // Update with current scan data
    updateScanProgressModal(scan);
}

function updateScanProgressModal(scan) {
    const progressFill = document.getElementById('progress-fill');
    const progressPercentage = document.getElementById('progress-percentage');
    const currentTest = document.getElementById('current-test');

    // Update progress bar
    const progress = scan.progress || 0;
    progressFill.style.width = `${progress}%`;
    progressPercentage.textContent = `${progress}%`;

    // Update current test
    if (scan.current_test) {
        currentTest.textContent = scan.current_test;
    } else {
        // Default messages based on status
        switch (scan.status) {
            case 'pending':
                currentTest.textContent = '⏳ Preparing scan environment...';
                break;
            case 'running':
                currentTest.textContent = '🔍 Security scan in progress...';
                break;
            case 'completed':
                currentTest.textContent = '✅ Scan completed successfully!';
                break;
            case 'failed':
                currentTest.textContent = '❌ Scan failed. Please try again.';
                break;
            default:
                currentTest.textContent = 'Initializing scan...';
        }
    }
}

function hideScanProgressModal() {
    const modal = document.getElementById('scan-progress-modal');
    modal.classList.add('hidden');
}