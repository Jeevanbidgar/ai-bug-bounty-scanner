// Tauri API integration for AI Bug Bounty Scanner
// This replaces the Socket.IO and HTTP API calls with Tauri commands and events

// Global app state (same as before)
const appData = {
  scans: [],
  vulnerabilities: [],
  reports: [],
  agents: [],
  stats: {},
};

// Tauri invoke wrapper for API calls
async function tauriInvoke(command, payload = {}) {
  console.log(`🔗 Tauri invoke: ${command}`, payload);

  try {
    const result = await window.__TAURI__.invoke(command, payload);
    console.log(`✅ Tauri response for ${command}:`, result);
    return result;
  } catch (error) {
    console.error(`❌ Tauri error for ${command}:`, error);
    showErrorNotification(`Tauri Error: ${error}`);
    throw error;
  }
}

// Tauri event listener setup
function initializeTauriEvents() {
  console.log("🎧 Setting up Tauri event listeners...");

  // Workflow events
  window.__TAURI__.event.listen('workflow://started', (event) => {
    console.log('🚀 Workflow started:', event.payload);
    handleWorkflowStarted(event.payload);
  });

  window.__TAURI__.event.listen('workflow://status_changed', (event) => {
    console.log('📊 Workflow status changed:', event.payload);
    handleWorkflowStatusChanged(event.payload);
  });

  window.__TAURI__.event.listen('workflow://step_changed', (event) => {
    console.log('🔄 Workflow step changed:', event.payload);
    handleWorkflowStepChanged(event.payload);
  });

  window.__TAURI__.event.listen('workflow://progress_updated', (event) => {
    console.log('📈 Workflow progress updated:', event.payload);
    handleWorkflowProgressUpdated(event.payload);
  });

  window.__TAURI__.event.listen('workflow://step_completed', (event) => {
    console.log('✅ Workflow step completed:', event.payload);
    handleWorkflowStepCompleted(event.payload);
  });

  window.__TAURI__.event.listen('workflow://step_output', (event) => {
    console.log('📝 Workflow step output:', event.payload);
    handleWorkflowStepOutput(event.payload);
  });

  window.__TAURI__.event.listen('workflow://completed', (event) => {
    console.log('🎉 Workflow completed:', event.payload);
    handleWorkflowCompleted(event.payload);
  });

  window.__TAURI__.event.listen('workflow://failed', (event) => {
    console.log('💥 Workflow failed:', event.payload);
    handleWorkflowFailed(event.payload);
  });

  // Scan events
  window.__TAURI__.event.listen('scan://started', (event) => {
    console.log('🔍 Scan started:', event.payload);
    handleScanStarted(event.payload);
  });

  window.__TAURI__.event.listen('scan://status_changed', (event) => {
    console.log('📊 Scan status changed:', event.payload);
    handleScanStatusChanged(event.payload);
  });

  window.__TAURI__.event.listen('scan://progress_updated', (event) => {
    console.log('📈 Scan progress updated:', event.payload);
    handleScanProgressUpdated(event.payload);
  });

  window.__TAURI__.event.listen('scan://completed', (event) => {
    console.log('🎉 Scan completed:', event.payload);
    handleScanCompleted(event.payload);
  });

  // System events
  window.__TAURI__.event.listen('system://health_changed', (event) => {
    console.log('🏥 System health changed:', event.payload);
    handleSystemHealthChanged(event.payload);
  });

  window.__TAURI__.event.listen('tool://availability_changed', (event) => {
    console.log('🔧 Tool availability changed:', event.payload);
    handleToolAvailabilityChanged(event.payload);
  });

  console.log("✅ Tauri event listeners configured");
}

// API replacement functions using Tauri commands

// Tool management
async function getTools() {
  return await tauriInvoke('get_tools');
}

async function getAvailableTools() {
  return await tauriInvoke('get_available_tools');
}

async function discoverTools() {
  return await tauriInvoke('discover_tools');
}

async function checkToolAvailability(toolName) {
  return await tauriInvoke('check_tool_availability', { toolName });
}

// Workflow management
async function getWorkflowTemplates(includeCompatibility = true) {
  return await tauriInvoke('get_workflow_templates', { includeCompatibility });
}

async function executeWorkflow(workflowId, inputs, workingDirectory) {
  return await tauriInvoke('execute_workflow', {
    workflowId,
    inputs,
    workingDirectory
  });
}

async function getWorkflowStatus(executionId) {
  return await tauriInvoke('get_workflow_status', { executionId });
}

async function cancelWorkflow(executionId) {
  return await tauriInvoke('cancel_workflow', { executionId });
}

// Scan management
async function getScans() {
  return await tauriInvoke('get_scans');
}

async function createScan(name, target, scanType, workflowId, tags) {
  return await tauriInvoke('create_scan', {
    name,
    target,
    scanType,
    workflowId,
    tags
  });
}

async function startScan(scanId) {
  return await tauriInvoke('start_scan', { scanId });
}

async function stopScan(scanId) {
  return await tauriInvoke('stop_scan', { scanId });
}

async function deleteScan(scanId) {
  return await tauriInvoke('delete_scan', { scanId });
}

async function getScanDetails(scanId) {
  return await tauriInvoke('get_scan_details', { scanId });
}

// Health and metrics
async function getHealth() {
  return await tauriInvoke('get_health');
}

async function getMetrics() {
  return await tauriInvoke('get_metrics');
}

async function getSystemInfo() {
  return await tauriInvoke('get_system_info');
}

// Report management
async function getReports() {
  return await tauriInvoke('get_reports');
}

async function generateReport(scanId, format, title) {
  return await tauriInvoke('generate_report', { scanId, format, title });
}

// Event handlers (these replace Socket.IO event handlers)

// Workflow event handlers
function handleWorkflowStarted(payload) {
  showSuccessNotification(`Workflow started: ${payload.workflow_name}`);
  // Update UI to show running workflow
  updateDashboardStats();
}

function handleWorkflowStatusChanged(payload) {
  const status = payload.new_status;
  showInfoNotification(`Workflow status: ${status}`);

  if (status === 'completed') {
    showSuccessNotification('Workflow completed successfully!');
  } else if (status === 'failed') {
    showErrorNotification(`Workflow failed: ${payload.error_message || 'Unknown error'}`);
  }
}

function handleWorkflowStepChanged(payload) {
  // Update current step display
  updateCurrentStepDisplay(payload.step_name);
}

function handleWorkflowProgressUpdated(payload) {
  // Update progress bars
  updateProgressDisplay(payload.progress, payload.current_step);
}

function handleWorkflowStepCompleted(payload) {
  showSuccessNotification(`Step completed: ${payload.step_name}`);
  // Update step completion status
}

function handleWorkflowStepOutput(payload) {
  // Add to logs display
  appendToLogs(payload.line, payload.stream_type);
}

function handleWorkflowCompleted(payload) {
  showSuccessNotification(`Workflow completed! Found ${payload.vulnerabilities_found} vulnerabilities`);
  // Refresh scan results and dashboard
  updateDashboardStats();
  loadScanResults();
}

function handleWorkflowFailed(payload) {
  showErrorNotification(`Workflow failed: ${payload.error_message}`);
  // Update UI to show failed state
}

// Scan event handlers
function handleScanStarted(payload) {
  showSuccessNotification(`Scan started: ${payload.scan_name}`);
  updateScanStatus(payload.scan_id, 'running');
}

function handleScanStatusChanged(payload) {
  updateScanStatus(payload.scan_id, payload.new_status);
}

function handleScanProgressUpdated(payload) {
  updateScanProgress(payload.scan_id, payload.progress, payload.current_test);
}

function handleScanCompleted(payload) {
  showSuccessNotification('Scan completed!');
  updateScanStatus(payload.scan_id, 'completed');
  loadScanResults();
}

// System event handlers
function handleSystemHealthChanged(payload) {
  updateConnectionStatus('connected', 'Connected to Tauri backend');

  if (payload.status === 'degraded') {
    showWarningNotification('System health degraded');
  } else if (payload.status === 'unhealthy') {
    showErrorNotification('System health unhealthy');
  }
}

function handleToolAvailabilityChanged(payload) {
  const status = payload.available ? 'available' : 'unavailable';
  showInfoNotification(`Tool ${payload.tool_name} is now ${status}`);
}

// UI update functions (these replace the old Socket.IO-based updates)
function updateConnectionStatus(status, text) {
  const statusElement = document.getElementById("connection-status");
  const textElement = document.getElementById("connection-text");

  if (statusElement && textElement) {
    statusElement.className = `w-3 h-3 rounded-full ${
      status === "connected" ? "bg-green-500" :
      status === "disconnected" ? "bg-red-500" :
      status === "error" ? "bg-yellow-500" : "bg-gray-500"
    }`;
    textElement.textContent = text;
  }
}

function updateDashboardStats() {
  // Use Tauri commands instead of API calls
  Promise.all([
    getHealth(),
    getMetrics(),
    getScans()
  ]).then(([health, metrics, scans]) => {
    // Update dashboard with new data
    updateStatsDisplay(health, metrics, scans);
  }).catch(error => {
    console.error("Error updating dashboard:", error);
  });
}

function updateCurrentStepDisplay(stepName) {
  const currentStepElement = document.getElementById("current-step");
  if (currentStepElement) {
    currentStepElement.textContent = stepName || "No active step";
  }
}

function updateProgressDisplay(progress, currentStep) {
  const progressBar = document.getElementById("progress-bar");
  const progressText = document.getElementById("progress-text");

  if (progressBar) {
    progressBar.style.width = `${progress}%`;
  }

  if (progressText) {
    progressText.textContent = `${progress.toFixed(1)}%`;
  }

  if (currentStep) {
    const currentStepElement = document.getElementById("current-step");
    if (currentStepElement) {
      currentStepElement.textContent = currentStep;
    }
  }
}

function appendToLogs(line, streamType) {
  const logsContainer = document.getElementById("scan-logs");
  if (logsContainer) {
    const logLine = document.createElement("div");
    logLine.className = `font-mono text-sm ${
      streamType === 'stderr' ? 'text-red-400' : 'text-gray-300'
    }`;
    logLine.textContent = line;
    logsContainer.appendChild(logLine);

    // Auto-scroll to bottom
    logsContainer.scrollTop = logsContainer.scrollHeight;
  }
}

function updateScanStatus(scanId, status) {
  // Update scan status in the UI
  const scanElements = document.querySelectorAll(`[data-scan-id="${scanId}"]`);
  scanElements.forEach(element => {
    const statusBadge = element.querySelector('.status-badge');
    if (statusBadge) {
      statusBadge.textContent = status;
      statusBadge.className = `status-badge px-2 py-1 text-xs rounded-full ${
        status === 'running' ? 'bg-blue-600' :
        status === 'completed' ? 'bg-green-600' :
        status === 'failed' ? 'bg-red-600' :
        status === 'pending' ? 'bg-yellow-600' : 'bg-gray-600'
      }`;
    }
  });
}

function updateScanProgress(scanId, progress, currentTest) {
  const scanElements = document.querySelectorAll(`[data-scan-id="${scanId}"]`);
  scanElements.forEach(element => {
    const progressBar = element.querySelector('.progress-bar');
    const progressText = element.querySelector('.progress-text');

    if (progressBar) {
      progressBar.style.width = `${progress}%`;
    }

    if (progressText) {
      progressText.textContent = `${progress.toFixed(1)}%`;
    }

    if (currentTest) {
      const currentTestElement = element.querySelector('.current-test');
      if (currentTestElement) {
        currentTestElement.textContent = currentTest;
      }
    }
  });
}

// Notification functions (same as before)
function showSuccessNotification(message) {
  showNotification(message, 'success');
}

function showErrorNotification(message) {
  showNotification(message, 'error');
}

function showWarningNotification(message) {
  showNotification(message, 'warning');
}

function showInfoNotification(message) {
  showNotification(message, 'info');
}

function showNotification(message, type = 'info') {
  const notification = document.createElement('div');
  notification.className = `fixed top-4 right-4 px-6 py-3 rounded-lg shadow-lg z-50 ${
    type === 'success' ? 'bg-green-600' :
    type === 'error' ? 'bg-red-600' :
    type === 'warning' ? 'bg-yellow-600' :
    'bg-blue-600'
  } text-white`;

  notification.innerHTML = `
    <div class="flex items-center gap-2">
      <span>${message}</span>
      <button onclick="this.parentElement.parentElement.remove()" class="ml-2 text-white hover:text-gray-200">×</button>
    </div>
  `;

  document.body.appendChild(notification);

  // Auto-remove after 5 seconds
  setTimeout(() => {
    if (notification.parentElement) {
      notification.remove();
    }
  }, 5000);
}

// Initialize Tauri integration when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  console.log('🚀 Initializing Tauri integration...');

  // Initialize event listeners
  initializeTauriEvents();

  // Update connection status to show Tauri is available
  updateConnectionStatus('connected', 'Connected to Tauri backend');

  // Load initial data
  loadInitialData();

  console.log('✅ Tauri integration initialized');
});

// Load initial data using Tauri commands
async function loadInitialData() {
  try {
    console.log('📊 Loading initial data...');

    // Load dashboard data in parallel
    const [health, metrics, scans, tools, workflows] = await Promise.all([
      getHealth(),
      getMetrics(),
      getScans(),
      getAvailableTools(),
      getWorkflowTemplates()
    ]);

    // Update app state
    appData.stats = { health, metrics };
    appData.scans = scans;
    appData.tools = tools;
    appData.workflows = workflows;

    // Update UI
    updateDashboardDisplay();
    renderScansTable();
    populateToolSelector();
    populateWorkflowSelector();

    console.log('✅ Initial data loaded');
  } catch (error) {
    console.error('❌ Error loading initial data:', error);
    showErrorNotification('Failed to load initial data');
  }
}

// Dashboard update function
function updateDashboardDisplay() {
  if (appData.stats.health) {
    const health = appData.stats.health;

    // Update system status
    const statusElement = document.getElementById('system-status');
    if (statusElement) {
      statusElement.textContent = health.status;
      statusElement.className = `px-2 py-1 text-xs rounded-full ${
        health.status === 'healthy' ? 'bg-green-600' :
        health.status === 'degraded' ? 'bg-yellow-600' : 'bg-red-600'
      }`;
    }

    // Update uptime
    const uptimeElement = document.getElementById('system-uptime');
    if (uptimeElement) {
      const hours = Math.floor(health.uptime_seconds / 3600);
      const minutes = Math.floor((health.uptime_seconds % 3600) / 60);
      uptimeElement.textContent = `${hours}h ${minutes}m`;
    }

    // Update memory usage
    const memoryElement = document.getElementById('memory-usage');
    if (memoryElement) {
      memoryElement.textContent = `${health.memory_usage_mb} MB`;
    }

    // Update tool counts
    const toolsAvailableElement = document.getElementById('tools-available');
    const toolsMissingElement = document.getElementById('tools-missing');

    if (toolsAvailableElement) {
      toolsAvailableElement.textContent = health.tools_available.toString();
    }

    if (toolsMissingElement) {
      toolsMissingElement.textContent = health.tools_missing.toString();
    }
  }

  if (appData.stats.metrics) {
    const metrics = appData.stats.metrics;

    // Update scan counts
    const scansTodayElement = document.getElementById('scans-today');
    const scansWeekElement = document.getElementById('scans-week');
    const scansMonthElement = document.getElementById('scans-month');

    if (scansTodayElement) scansTodayElement.textContent = metrics.scans_today.toString();
    if (scansWeekElement) scansWeekElement.textContent = metrics.scans_this_week.toString();
    if (scansMonthElement) scansMonthElement.textContent = metrics.scans_this_month.toString();

    // Update vulnerability counts
    const vulnsTodayElement = document.getElementById('vulnerabilities-today');
    if (vulnsTodayElement) {
      vulnsTodayElement.textContent = metrics.vulnerabilities_found_today.toString();
    }
  }
}

// Render scans table
function renderScansTable() {
  const scansTableBody = document.getElementById('scans-table-body');
  if (!scansTableBody) return;

  scansTableBody.innerHTML = '';

  if (appData.scans.length === 0) {
    scansTableBody.innerHTML = `
      <tr>
        <td colspan="6" class="px-6 py-8 text-center text-gray-500">
          No scans found. Create your first scan to get started.
        </td>
      </tr>
    `;
    return;
  }

  appData.scans.forEach(scan => {
    const row = document.createElement('tr');
    row.className = 'border-b border-gray-700 hover:bg-gray-800';
    row.innerHTML = `
      <td class="px-6 py-4">
        <div class="flex items-center">
          <div class="w-3 h-3 rounded-full mr-3 ${
            scan.status === 'running' ? 'bg-blue-500 animate-pulse' :
            scan.status === 'completed' ? 'bg-green-500' :
            scan.status === 'failed' ? 'bg-red-500' :
            scan.status === 'pending' ? 'bg-yellow-500' : 'bg-gray-500'
          }"></div>
          <div>
            <div class="text-sm font-medium text-white">${scan.name || scan.target}</div>
            <div class="text-sm text-gray-400">${scan.target}</div>
          </div>
        </div>
      </td>
      <td class="px-6 py-4">
        <span class="px-2 py-1 text-xs rounded-full ${
          scan.status === 'running' ? 'bg-blue-600' :
          scan.status === 'completed' ? 'bg-green-600' :
          scan.status === 'failed' ? 'bg-red-600' :
          scan.status === 'pending' ? 'bg-yellow-600' : 'bg-gray-600'
        }">
          ${scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
        </span>
      </td>
      <td class="px-6 py-4 text-sm text-gray-400">
        ${scan.scan_type || 'Custom'}
      </td>
      <td class="px-6 py-4 text-sm text-gray-400">
        ${scan.started ? new Date(scan.started).toLocaleDateString() : 'Not started'}
      </td>
      <td class="px-6 py-4 text-sm text-gray-400">
        ${scan.duration || 'N/A'}
      </td>
      <td class="px-6 py-4 text-right">
        <div class="flex items-center justify-end space-x-2">
          ${scan.status === 'running' ? `
            <button onclick="stopScan('${scan.id}')" class="text-red-400 hover:text-red-300">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m-7 1V4a2 2 0 012-2h6a2 2 0 012 2v14a2 2 0 01-2 2H7a2 2 0 01-2-2v-2a2 2 0 012-2z"></path>
              </svg>
            </button>
          ` : ''}
          <button onclick="deleteScan('${scan.id}')" class="text-red-400 hover:text-red-300">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
            </svg>
          </button>
        </div>
      </td>
    `;

    scansTableBody.appendChild(row);
  });
}

// Populate tool selector (for workflow creation)
function populateToolSelector() {
  // This would populate dropdowns with available tools
  // Implementation depends on specific UI structure
}

// Populate workflow selector (for workflow creation)
function populateWorkflowSelector() {
  // This would populate dropdowns with available workflows
  // Implementation depends on specific UI structure
}

// Enhanced scan creation using Tauri
async function createNewScan() {
  const target = document.getElementById('scan-target')?.value;
  const name = document.getElementById('scan-name')?.value;
  const workflowId = document.getElementById('workflow-selector')?.value;
  const tags = document.getElementById('scan-tags')?.value?.split(',').map(t => t.trim()) || [];

  if (!target) {
    showErrorNotification('Target is required');
    return;
  }

  try {
    const scanId = await createScan(
      name || `Scan of ${target}`,
      target,
      'Custom',
      workflowId || null,
      tags
    );

    showSuccessNotification(`Scan created: ${scanId}`);

    // Refresh scans list
    const scans = await getScans();
    appData.scans = scans;
    renderScansTable();

    // Clear form
    if (document.getElementById('scan-target')) {
      document.getElementById('scan-target').value = '';
    }
    if (document.getElementById('scan-name')) {
      document.getElementById('scan-name').value = '';
    }

  } catch (error) {
    showErrorNotification(`Failed to create scan: ${error}`);
  }
}

// Enhanced scan execution using Tauri
async function executeScanWorkflow(scanId) {
  try {
    await startScan(scanId);
    showSuccessNotification('Scan started successfully');
  } catch (error) {
    showErrorNotification(`Failed to start scan: ${error}`);
  }
}

// Tool discovery using Tauri
async function runToolDiscovery() {
  try {
    showInfoNotification('Discovering tools...');
    const discoveredCount = await discoverTools();
    showSuccessNotification(`Discovered ${discoveredCount} new tools`);

    // Refresh tools list
    const tools = await getAvailableTools();
    appData.tools = tools;
    populateToolSelector();

  } catch (error) {
    showErrorNotification(`Tool discovery failed: ${error}`);
  }
}

// Export existing functions for backward compatibility
// These maintain the same interface as the original Socket.IO version

// Real-time scan progress (now handled by Tauri events)
function handleRealTimeScanProgress(data) {
  // This function is now handled by Tauri events
  // Keeping for backward compatibility
  console.log('Real-time scan progress (legacy):', data);
}

// Quick scan function (now uses Tauri)
async function quickScan(target) {
  try {
    const scanId = await createScan(
      `Quick scan of ${target}`,
      target,
      'Quick Scan',
      null, // No specific workflow
      ['quick']
    );

    await startScan(scanId);
    showSuccessNotification('Quick scan started');
    return scanId;

  } catch (error) {
    showErrorNotification(`Quick scan failed: ${error}`);
    throw error;
  }
}

// Load scan results (now uses Tauri)
async function loadScanResults() {
  try {
    const scans = await getScans();
    appData.scans = scans;

    // Update UI with latest results
    renderScansTable();
    updateDashboardStats();

  } catch (error) {
    console.error('Error loading scan results:', error);
  }
}

// Test Socket.IO functionality (now shows Tauri status)
function testSocketConnection() {
  showInfoNotification('Connected to Tauri backend - real-time events active');
  return true;
}

// Legacy Socket.IO functions (kept for backward compatibility)
function handleSocketConnect() {
  // Now handled by Tauri events
}

function handleSocketDisconnect() {
  showWarningNotification('Disconnected from Tauri backend');
}

function handleSocketError(error) {
  showErrorNotification(`Connection error: ${error}`);
}

// Initialize the application
console.log('🎯 AI Bug Bounty Scanner - Tauri Edition');
console.log('🔗 Using Tauri for desktop-native performance');

// Make functions globally available
window.getTools = getTools;
window.getAvailableTools = getAvailableTools;
window.discoverTools = discoverTools;
window.getWorkflowTemplates = getWorkflowTemplates;
window.executeWorkflow = executeWorkflow;
window.getScans = getScans;
window.createScan = createScan;
window.startScan = startScan;
window.stopScan = stopScan;
window.getHealth = getHealth;
window.getMetrics = getMetrics;
window.quickScan = quickScan;
window.loadScanResults = loadScanResults;
window.testSocketConnection = testSocketConnection;
window.createNewScan = createNewScan;
window.executeScanWorkflow = executeScanWorkflow;
window.runToolDiscovery = runToolDiscovery;