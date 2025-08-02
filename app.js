// API Configuration
const API_BASE_URL = "http://localhost:5000/api";

// Socket.IO client initialization
let socket = null;
let connectionStatus = "disconnected";

// Global app state
const appData = {
  scans: [],
  vulnerabilities: [],
  reports: [],
  agents: [],
  stats: {},
};

// API helper functions
async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  console.log(`🌐 API Request: ${options.method || "GET"} ${url}`);

  try {
    const response = await fetch(url, {
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
      ...options,
    });

    console.log(`📡 API Response: ${response.status} ${response.statusText}`);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    console.log(`✅ API Data received:`, data);
    return data;
  } catch (error) {
    console.error("❌ API Error:", error);
    showErrorNotification(`API Error: ${error.message}`);
    throw error;
  }
}

// Socket.IO Real-time Communication
function initializeSocket() {
  socket = io("http://localhost:5000");

  // Connection events
  socket.on("connect", () => {
    console.log("✅ Connected to server via Socket.IO");
    connectionStatus = "connected";
    updateConnectionStatus("connected", "Connected");

    // Send a test message
    socket.emit("ping", {
      message: "Hello from frontend!",
      timestamp: new Date().toISOString(),
    });
  });

  socket.on("disconnect", () => {
    console.log("❌ Disconnected from server");
    connectionStatus = "disconnected";
    updateConnectionStatus("disconnected", "Disconnected");
  });

  socket.on("connect_error", (error) => {
    console.error("❌ Connection error:", error);
    connectionStatus = "error";
    updateConnectionStatus("error", "Connection Error");
  });

  // Server response events
  socket.on("connection_status", (data) => {
    console.log("📡 Server connection status:", data);
  });

  socket.on("pong", (data) => {
    console.log("🏓 Received pong from server:", data);
  });

  // Real-time scan progress updates
  socket.on("scan_progress_update", (data) => {
    console.log("📊 Scan progress update:", data);
    handleRealTimeScanProgress(data);
  });

  return socket;
}

// Update connection status in UI
function updateConnectionStatus(status, text) {
  const statusElement = document.getElementById("connection-status");
  const textElement = document.getElementById("connection-text");

  if (statusElement && textElement) {
    statusElement.className = `w-3 h-3 rounded-full ${
      status === "connected"
        ? "bg-green-500"
        : status === "error"
        ? "bg-red-500"
        : "bg-gray-500"
    }`;
    textElement.textContent = text;
    textElement.className = `text-sm ${
      status === "connected"
        ? "text-green-400"
        : status === "error"
        ? "text-red-400"
        : "text-gray-400"
    }`;
  }
}

// Handle real-time scan progress updates
function handleRealTimeScanProgress(data) {
  const { scan_id, progress, current_test, status } = data;

  // Update local scan data
  const scanIndex = appData.scans.findIndex((s) => s.id === scan_id);
  if (scanIndex !== -1) {
    appData.scans[scanIndex].progress = progress;
    appData.scans[scanIndex].current_test = current_test;
    appData.scans[scanIndex].status = status;

    // Show notification for scan completion
    if (status === "completed" && progress === 100) {
      const notification = createNotification(
        `✅ Real-time scan completed for ${appData.scans[scanIndex].target}`,
        "success"
      );
      document.body.appendChild(notification);
    } else if (status === "failed") {
      const notification = createNotification(
        `❌ Real-time scan failed for ${appData.scans[scanIndex].target}`,
        "error"
      );
      document.body.appendChild(notification);
    }
  }

  // Update progress modal if it's open
  const modal = document.getElementById("scan-progress-modal");
  if (
    modal &&
    !modal.classList.contains("hidden") &&
    currentScanId === scan_id
  ) {
    updateScanProgressModal({
      id: scan_id,
      progress: progress,
      current_test: current_test,
      status: status,
    });

    // Auto-hide modal when scan completes - give more time to see completion
    if (status === "completed" || status === "failed") {
      // Check if this was a user-cancelled scan
      const wasCancelled =
        current_test && current_test.includes("cancelled by user");
      const delay = wasCancelled ? 2000 : 5000; // Shorter delay for cancelled scans

      setTimeout(() => {
        if (!isModalMinimized) {
          hideScanProgressModal();
        }
      }, delay);
    }
  }

  // Also update minimized indicator if visible
  const minimizedIndicator = document.getElementById(
    "minimized-scan-indicator"
  );
  if (
    minimizedIndicator &&
    !minimizedIndicator.classList.contains("hidden") &&
    currentScanId === scan_id
  ) {
    const minimizedProgress = document.getElementById("minimized-progress");
    if (minimizedProgress) {
      minimizedProgress.textContent = `${progress}%`;
    }

    // Auto-hide minimized indicator when scan completes
    if (status === "completed" || status === "failed") {
      setTimeout(() => {
        minimizedIndicator.classList.add("hidden");
        currentScanId = null;
      }, 5000);
    }
  }

  // Update active scans display
  renderActiveScans();

  // Update activity feed with enhanced information
  if (data.agent_name) {
    const agentEmoji = getAgentEmoji(data.agent_name);
    let message = `${agentEmoji} ${data.agent_name}: ${
      current_test || "Processing..."
    }`;

    // Add external tool integration status based on current test
    if (current_test) {
      if (
        current_test.includes("SQLMap") ||
        current_test.includes("sqlmap") ||
        current_test.includes("deeper analysis")
      ) {
        message += " 💉"; // SQLMap integration
      }
      if (
        current_test.includes("ZAP") ||
        current_test.includes("zap") ||
        current_test.includes("OWASP")
      ) {
        message += " 🛡️"; // ZAP integration
      }
      if (
        current_test.includes("Subfinder") ||
        current_test.includes("subfinder") ||
        current_test.includes("external tool integrations")
      ) {
        message += " 🌐"; // Subfinder integration
      }
    }

    updateActivityFeed(message);
  }
}

// Helper function to get agent emojis
function getAgentEmoji(agentName) {
  const emojiMap = {
    "Recon Agent": "🔍",
    "Web App Agent": "🌐",
    "Network Agent": "🔒",
    "API Agent": "⚡",
    "Report Agent": "📋",
    "Enhanced Security Agent": "🔬",
    "Threat Intelligence Agent": "🛡️",
  };
  return emojiMap[agentName] || "🤖";
}

// Function to update activity feed
function updateActivityFeed(message) {
  const activityFeed = document.getElementById("activity-feed");
  if (!activityFeed) return;

  const timestamp = new Date().toLocaleTimeString();
  const activityItem = document.createElement("div");
  activityItem.className = "flex items-center gap-2 text-sm text-gray-300 mb-2";
  activityItem.innerHTML = `
        <span class="text-gray-500">${timestamp}</span>
        <span>${message}</span>
    `;

  // Add to beginning of feed
  if (activityFeed.firstChild && activityFeed.firstChild.tagName !== "P") {
    activityFeed.insertBefore(activityItem, activityFeed.firstChild);
  } else {
    // Replace "No Recent Activity" message
    activityFeed.innerHTML = "";
    activityFeed.appendChild(activityItem);
  }

  // Keep only last 10 items
  while (activityFeed.children.length > 10) {
    activityFeed.removeChild(activityFeed.lastChild);
  }
}

// Initialize Socket.IO test functionality
function initializeSocketTest() {
  const testButton = document.getElementById("test-socket");
  if (testButton) {
    testButton.addEventListener("click", () => {
      if (socket && socket.connected) {
        // Send test message
        const testData = {
          message: "Test message from frontend",
          timestamp: new Date().toISOString(),
          random: Math.random(),
        };

        socket.emit("ping", testData);

        // Show notification
        const notification = createNotification(
          "🔄 Socket.IO test message sent!",
          "info"
        );
        document.body.appendChild(notification);

        console.log("📤 Sent test message:", testData);
      } else {
        const notification = createNotification(
          "❌ Socket.IO not connected",
          "error"
        );
        document.body.appendChild(notification);
      }
    });
  }
}

// Application data will be loaded from API and stored in the global appData object

// Global variables
let vulnerabilityChart = null;
let currentFilter = "";

// API Data Loading Functions
async function loadStats() {
  try {
    const stats = await apiRequest("/stats");
    appData.stats = stats;
    updateStatsDisplay();
  } catch (error) {
    console.error("Failed to load stats:", error);
  }
}

async function loadScans() {
  try {
    const scans = await apiRequest("/scans");
    appData.scans = scans;
    renderActiveScans();
  } catch (error) {
    console.error("Failed to load scans:", error);
  }
}

async function loadAgents() {
  try {
    const agents = await apiRequest("/agents");

    // If no agents from API, use enhanced default agents
    if (!agents || agents.length === 0) {
      appData.agents = getDefaultEnhancedAgents();
    } else {
      appData.agents = agents;
    }

    renderAgents();
  } catch (error) {
    console.error("Failed to load agents:", error);
    // Fallback to default enhanced agents
    appData.agents = getDefaultEnhancedAgents();
    renderAgents();
  }
}

// Default enhanced agents configuration
function getDefaultEnhancedAgents() {
  return [
    {
      name: "Recon Agent",
      status: "Active",
      description:
        "Network reconnaissance and subdomain discovery with professional external tool integration",
      successRate: 94,
      capabilities: [
        "Port Scanning (Nmap)",
        "DNS Resolution & Enumeration",
        "SSL/TLS Certificate Analysis",
        "Service Enumeration & Banner Grabbing",
        "Subfinder Integration (Advanced Subdomain Discovery)",
        "OWASP ZAP Integration (Web Application Scanning)",
        "Network Topology Mapping",
        "Passive Vulnerability Scanning",
      ],
    },
    {
      name: "Web App Agent",
      status: "Active",
      description:
        "Web application security testing with Scrapy crawler and advanced SQLMap integration",
      successRate: 87,
      capabilities: [
        "Advanced Web Crawling (Scrapy)",
        "Form & Parameter Discovery",
        "XSS Detection (Multiple Payloads)",
        "SQL Injection Testing (Built-in)",
        "Enhanced SQLMap Integration (Multi-URL)",
        "Security Header Analysis (CSP, HSTS, X-Frame-Options)",
        "Directory Traversal Testing",
        "Information Disclosure Detection",
        "API Endpoint Discovery",
        "Database Exploitation (via SQLMap)",
      ],
    },
    {
      name: "Network Agent",
      status: "Active",
      description:
        "Network-level security assessment and infrastructure analysis",
      successRate: 91,
      capabilities: [
        "Network Service Enumeration",
        "Protocol-Specific Testing",
        "Firewall & Filtering Detection",
        "Network Configuration Analysis",
        "Service Version Detection",
        "Network Topology Mapping",
        "Protocol Vulnerability Assessment",
      ],
    },
    {
      name: "API Agent",
      status: "Active",
      description:
        "REST API security testing and endpoint vulnerability assessment",
      successRate: 89,
      capabilities: [
        "API Endpoint Discovery",
        "Authentication Bypass Testing",
        "Input Validation Testing",
        "Rate Limiting Assessment",
        "API Documentation Analysis",
        "Authentication Mechanism Testing",
        "DoS Protection Assessment",
      ],
    },
    {
      name: "Report Agent",
      status: "Active",
      description:
        "Comprehensive vulnerability reporting with CVSS scoring and remediation guidance",
      successRate: 99,
      capabilities: [
        "Vulnerability Aggregation & Analysis",
        "Risk Assessment & CVSS Scoring",
        "Executive Summary Generation",
        "Technical Detail Compilation",
        "Remediation Recommendations",
        "Multi-format Export (PDF, JSON)",
        "Compliance Reporting",
      ],
    },
    {
      name: "Enhanced Security Agent",
      status: "Enhanced",
      description:
        "Advanced security testing with machine learning capabilities and WAF evasion techniques",
      successRate: 96,
      capabilities: [
        "Advanced XSS Detection",
        "Time-based SQL Injection",
        "WAF Evasion Techniques",
        "SSL/TLS Security Analysis",
        "ML-Powered Vulnerability Detection",
        "Advanced Payload Generation",
        "Behavioral Analysis",
        "Zero-day Detection Patterns",
      ],
      enhanced: true,
    },
    {
      name: "Threat Intelligence Agent",
      status: "Enhanced",
      description:
        "Real-time threat intelligence integration with multiple security APIs",
      successRate: 93,
      capabilities: [
        "IP Reputation Analysis (AbuseIPDB)",
        "Domain & URL Analysis (VirusTotal)",
        "Internet Device Intelligence (Shodan)",
        "Malware Detection & Analysis",
        "CVE Database Integration",
        "Threat Actor Intelligence",
        "IoC (Indicators of Compromise) Analysis",
        "Real-time Threat Feeds",
      ],
      enhanced: true,
    },
  ];
}

async function loadVulnerabilities() {
  try {
    const vulnerabilities = await apiRequest("/vulnerabilities");
    appData.vulnerabilities = vulnerabilities;
    renderVulnerabilities();
  } catch (error) {
    console.error("Failed to load vulnerabilities:", error);
  }
}

async function loadReports() {
  try {
    const reports = await apiRequest("/reports");
    appData.reports = reports;
    renderReports();
  } catch (error) {
    console.error("Failed to load reports:", error);
  }
}

// Initialize the application
document.addEventListener("DOMContentLoaded", async function () {
  console.log("🚀 Initializing AI Bug Bounty Scanner...");

  // Initialize Socket.IO for real-time communication
  initializeSocket();

  // Initialize Socket.IO test button
  initializeSocketTest();

  initializeNavigation();
  await initializeCharts();
  initializeForms();
  initializeModal();

  console.log("📡 Loading data from API...");

  // Load data from API
  try {
    await loadStats();
    console.log("✅ Stats loaded");

    await loadScans();
    console.log("✅ Scans loaded");

    await loadAgents();
    console.log("✅ Agents loaded");

    await loadVulnerabilities();
    console.log("✅ Vulnerabilities loaded");

    await loadReports();
    console.log("✅ Reports loaded");

    console.log("🎉 All data loaded successfully!");
  } catch (error) {
    console.error("❌ Failed to load initial data:", error);
  }

  await renderActivityFeed();
  startRealTimeUpdates();

  console.log("🔄 Real-time updates started");
});

// Update stats display - FIXED FOR TAILWIND CSS
function updateStatsDisplay() {
  const stats = appData.stats;

  if (!stats) {
    console.warn("No stats data available");
    return;
  }

  // Update stat cards using specific IDs
  const totalScansEl = document.getElementById("total-scans");
  const activeAgentsEl = document.getElementById("active-agents");
  const totalVulnerabilitiesEl = document.getElementById(
    "total-vulnerabilities"
  );
  const criticalIssuesEl = document.getElementById("critical-issues");

  if (totalScansEl) totalScansEl.textContent = stats.totalScans || 0;
  if (activeAgentsEl) activeAgentsEl.textContent = stats.activeAgents || 0;
  if (totalVulnerabilitiesEl)
    totalVulnerabilitiesEl.textContent = stats.vulnerabilitiesFound || 0;
  if (criticalIssuesEl)
    criticalIssuesEl.textContent = stats.criticalIssues || 0;

  // Update header status indicators
  const statusIndicators = document.querySelectorAll(".status");
  if (statusIndicators.length >= 2) {
    statusIndicators[0].textContent = `${
      stats.activeAgents || 0
    } Agents Active`;
    statusIndicators[1].textContent = `${
      appData.scans
        ? appData.scans.filter((s) => s.status === "running").length
        : 0
    } Scans Running`;
  }

  console.log("📊 Stats updated:", stats);
}

// Error notification function
function showErrorNotification(message) {
  const notification = createNotification(message, "error");
  document.body.appendChild(notification);
}

// Navigation functionality - FIXED
function initializeNavigation() {
  const navItems = document.querySelectorAll(".nav-item");
  const views = document.querySelectorAll(".view");
  const pageTitle = document.getElementById("page-title");

  navItems.forEach((item) => {
    item.addEventListener("click", function (e) {
      e.preventDefault();
      e.stopPropagation(); // Prevent event bubbling

      // Remove active class from all nav items and views
      navItems.forEach((nav) => nav.classList.remove("active"));
      views.forEach((view) => view.classList.remove("active"));

      // Add active class to clicked nav item
      this.classList.add("active");

      // Show corresponding view
      const viewName = this.dataset.view;
      const targetView = document.getElementById(`${viewName}-view`);
      if (targetView) {
        targetView.classList.add("active");
        pageTitle.textContent = this.textContent;
      }
    });
  });
}

// Chart initialization - REAL DATA
async function initializeCharts() {
  const chartElement = document.getElementById("vulnerabilityChart");

  if (!chartElement) {
    console.warn(
      "vulnerabilityChart element not found, skipping chart initialization"
    );
    return;
  }

  const ctx = chartElement.getContext("2d");

  try {
    // Get real vulnerability data
    const vulnerabilities = await apiRequest("/vulnerabilities");
    const chartData = generateVulnerabilityTrendsData(vulnerabilities);

    vulnerabilityChart = new Chart(ctx, {
      type: "line",
      data: chartData,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "top",
            labels: {
              color: "#f5f5f5",
              font: {
                size: 12,
              },
            },
          },
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: {
              color: "rgba(255, 255, 255, 0.1)",
            },
            ticks: {
              color: "#a7a9a9",
            },
          },
          x: {
            grid: {
              color: "rgba(255, 255, 255, 0.1)",
            },
            ticks: {
              color: "#a7a9a9",
            },
          },
        },
      },
    });
  } catch (error) {
    console.error("Failed to load vulnerability chart data:", error);
    // Fallback to empty chart
    const emptyChartData = {
      labels: ["No Data"],
      datasets: [
        {
          label: "Critical",
          data: [0],
          backgroundColor: "#FF5459",
          borderColor: "#FF5459",
          tension: 0.4,
        },
        {
          label: "High",
          data: [0],
          backgroundColor: "#E68161",
          borderColor: "#E68161",
          tension: 0.4,
        },
        {
          label: "Medium",
          data: [0],
          backgroundColor: "#32808D",
          borderColor: "#32808D",
          tension: 0.4,
        },
      ],
    };

    vulnerabilityChart = new Chart(ctx, {
      type: "line",
      data: emptyChartData,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "top",
            labels: {
              color: "#f5f5f5",
              font: {
                size: 12,
              },
            },
          },
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: {
              color: "rgba(255, 255, 255, 0.1)",
            },
            ticks: {
              color: "#a7a9a9",
            },
          },
          x: {
            grid: {
              color: "rgba(255, 255, 255, 0.1)",
            },
            ticks: {
              color: "#a7a9a9",
            },
          },
        },
      },
    });
  }
}

// Generate real vulnerability trends data from actual vulnerabilities
function generateVulnerabilityTrendsData(vulnerabilities) {
  // Get last 6 months
  const months = [];
  const monthNames = [
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
  ];
  const now = new Date();

  for (let i = 5; i >= 0; i--) {
    const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
    months.push({
      label: monthNames[date.getMonth()],
      year: date.getFullYear(),
      month: date.getMonth(),
    });
  }

  // Initialize data arrays
  const criticalData = new Array(6).fill(0);
  const highData = new Array(6).fill(0);
  const mediumData = new Array(6).fill(0);

  // Process vulnerabilities
  vulnerabilities.forEach((vuln) => {
    if (!vuln.timestamp) return;

    const vulnDate = new Date(vuln.timestamp);
    const vulnMonth = vulnDate.getMonth();
    const vulnYear = vulnDate.getFullYear();

    // Find matching month index
    const monthIndex = months.findIndex(
      (m) => m.month === vulnMonth && m.year === vulnYear
    );

    if (monthIndex !== -1) {
      switch (vuln.severity.toLowerCase()) {
        case "critical":
          criticalData[monthIndex]++;
          break;
        case "high":
          highData[monthIndex]++;
          break;
        case "medium":
          mediumData[monthIndex]++;
          break;
      }
    }
  });

  // If no data, show a message in the chart
  const hasData =
    criticalData.some((v) => v > 0) ||
    highData.some((v) => v > 0) ||
    mediumData.some((v) => v > 0);

  if (!hasData) {
    return {
      labels: ["No vulnerability data available"],
      datasets: [
        {
          label: "Critical",
          data: [0],
          backgroundColor: "#FF5459",
          borderColor: "#FF5459",
          tension: 0.4,
        },
        {
          label: "High",
          data: [0],
          backgroundColor: "#E68161",
          borderColor: "#E68161",
          tension: 0.4,
        },
        {
          label: "Medium",
          data: [0],
          backgroundColor: "#32808D",
          borderColor: "#32808D",
          tension: 0.4,
        },
      ],
    };
  }

  return {
    labels: months.map((m) => m.label),
    datasets: [
      {
        label: "Critical",
        data: criticalData,
        backgroundColor: "#FF5459",
        borderColor: "#FF5459",
        tension: 0.4,
      },
      {
        label: "High",
        data: highData,
        backgroundColor: "#E68161",
        borderColor: "#E68161",
        tension: 0.4,
      },
      {
        label: "Medium",
        data: mediumData,
        backgroundColor: "#32808D",
        borderColor: "#32808D",
        tension: 0.4,
      },
    ],
  };
}

// Update vulnerability chart with new data
async function updateVulnerabilityChart() {
  if (!vulnerabilityChart) return;

  try {
    const vulnerabilities = await apiRequest("/vulnerabilities");
    const newChartData = generateVulnerabilityTrendsData(vulnerabilities);

    // Update chart data
    vulnerabilityChart.data = newChartData;
    vulnerabilityChart.update("none"); // Update without animation for real-time
  } catch (error) {
    console.error("Failed to update vulnerability chart:", error);
  }
}

// Render activity feed - REAL DATA
async function renderActivityFeed() {
  const activityFeed = document.getElementById("activity-feed");

  try {
    // Get real data from API
    const [scans, vulnerabilities, reports] = await Promise.all([
      apiRequest("/scans"),
      apiRequest("/vulnerabilities"),
      apiRequest("/reports"),
    ]);

    // Generate real activity items
    const activities = [];

    // Add recent vulnerabilities
    vulnerabilities.slice(0, 3).forEach((vuln) => {
      activities.push({
        title: `${vuln.severity.toUpperCase()} Vulnerability Found`,
        description: `${vuln.discoveredBy || "Scanner"} discovered ${
          vuln.title
        } in ${vuln.url || "target"}`,
        time: getRelativeTime(vuln.timestamp),
        type: getSeverityType(vuln.severity),
        timestamp: new Date(vuln.timestamp),
      });
    });

    // Add recent scan completions
    scans
      .filter((scan) => scan.status === "completed")
      .slice(0, 2)
      .forEach((scan) => {
        activities.push({
          title: "Scan Completed",
          description: `${scan.scanType} of ${scan.target} completed successfully`,
          time: getRelativeTime(scan.completed),
          type: "success",
          timestamp: new Date(scan.completed),
        });
      });

    // Add recent scan starts
    scans
      .filter((scan) => scan.status === "running")
      .slice(0, 2)
      .forEach((scan) => {
        activities.push({
          title: "Scan Started",
          description: `${scan.scanType} initiated for ${scan.target}`,
          time: getRelativeTime(scan.started),
          type: "info",
          timestamp: new Date(scan.started),
        });
      });

    // Add recent reports
    reports.slice(0, 1).forEach((report) => {
      activities.push({
        title: "Report Generated",
        description: `Security assessment report created: ${report.title}`,
        time: getRelativeTime(report.created_at),
        type: "success",
        timestamp: new Date(report.created_at),
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

    const activityHTML = recentActivities
      .map(
        (activity) => `
            <div class="flex justify-between items-start p-3 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex-1">
                    <h4 class="font-medium text-white text-sm">${activity.title}</h4>
                    <p class="text-gray-400 text-xs mt-1">${activity.description}</p>
                </div>
                <div class="text-xs text-gray-500 ml-3">${activity.time}</div>
            </div>
        `
      )
      .join("");

    activityFeed.innerHTML = activityHTML;
  } catch (error) {
    console.error("Failed to load activity feed:", error);
    activityFeed.innerHTML = `
            <div class="flex justify-between items-start p-3 bg-gray-800 rounded-lg border border-gray-700">
                <div class="flex-1">
                    <h4 class="font-medium text-white text-sm">Unable to Load Activity</h4>
                    <p class="text-gray-400 text-xs mt-1">Failed to fetch recent activity data</p>
                </div>
                <div class="text-xs text-gray-500 ml-3">Error</div>
            </div>
        `;
  }
}

// Helper function to get relative time
function getRelativeTime(timestamp) {
  if (!timestamp) return "Unknown";

  const now = new Date();
  const time = new Date(timestamp);
  const diffMs = now - time;
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? "s" : ""} ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? "s" : ""} ago`;
  if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? "s" : ""} ago`;
  return time.toLocaleDateString();
}

// Helper function to map severity to activity type
function getSeverityType(severity) {
  switch (severity.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "warning";
    case "medium":
      return "info";
    case "low":
      return "success";
    default:
      return "info";
  }
}

// Render active scans - TAILWIND CSS
function renderActiveScans() {
  const activeScansContainer = document.getElementById("active-scans");

  if (!activeScansContainer) {
    console.warn("active-scans element not found");
    return;
  }

  if (!appData.scans || appData.scans.length === 0) {
    activeScansContainer.innerHTML =
      '<p class="text-gray-400">No active scans</p>';
    return;
  }

  const scansHTML = appData.scans
    .map((scan) => {
      const progress = scan.progress || 100;
      const statusClass =
        scan.status === "running" ? "text-blue-400" : "text-green-400";

      return `
            <div class="bg-gray-800 border border-gray-600 rounded-lg p-4 space-y-3">
                <div class="flex justify-between items-start">
                    <div>
                        <div class="font-semibold text-white">${
                          scan.target
                        }</div>
                        <div class="text-sm text-gray-400">${
                          scan.scanType
                        }</div>
                    </div>
                    <span class="px-2 py-1 rounded text-xs font-medium ${statusClass} bg-gray-700">${
        scan.status
      }</span>
                </div>

                ${
                  scan.status === "running"
                    ? `
                    <div class="w-full bg-gray-700 rounded-full h-2">
                        <div class="bg-primary h-2 rounded-full transition-all duration-300" style="width: ${progress}%"></div>
                    </div>
                `
                    : ""
                }

                <div class="flex gap-4 text-sm">
                    <span class="text-red-400">🔴 ${scan.critical || 0}</span>
                    <span class="text-orange-400">🟠 ${scan.high || 0}</span>
                    <span class="text-yellow-400">🟡 ${scan.medium || 0}</span>
                </div>

                <div class="text-sm text-gray-400">
                    Agents: ${scan.agents.join(", ")}
                </div>

                <button class="w-full px-3 py-2 border border-primary text-primary rounded hover:bg-primary hover:text-white transition-colors text-sm" onclick="viewScanDetails('${
                  scan.id
                }')">
                    View Details
                </button>
            </div>
        `;
    })
    .join("");

  activeScansContainer.innerHTML = scansHTML;
}

// Render AI agents - TAILWIND CSS
function renderAgents() {
  const agentsGrid = document.getElementById("agents-grid");

  if (!agentsGrid) {
    console.warn("agents-grid element not found");
    return;
  }

  const agentsHTML = appData.agents
    .map((agent) => {
      const isEnhanced =
        agent.enhanced ||
        agent.name.includes("Enhanced") ||
        agent.name.includes("Threat Intelligence");
      const statusColor =
        agent.status === "Enhanced" ? "text-primary" : "text-green-400";
      const statusDot =
        agent.status === "Enhanced" ? "bg-primary" : "bg-green-500";
      const borderClass = isEnhanced
        ? "border-primary border-opacity-50 bg-gradient-to-br from-primary/5 to-secondary/5"
        : "border-gray-700";

      return `
        <div class="bg-dark-lighter border ${borderClass} rounded-xl p-6 hover:border-primary transition-colors">
            <div class="flex justify-between items-start mb-4">
                <div class="flex items-center gap-2">
                    <h3 class="text-lg font-semibold text-white">${
                      agent.name
                    }</h3>
                    ${
                      isEnhanced
                        ? '<span class="px-2 py-1 bg-primary bg-opacity-20 text-primary text-xs rounded-full">ENHANCED</span>'
                        : ""
                    }
                </div>
                <div class="flex items-center gap-2">
                    <div class="w-2 h-2 ${statusDot} rounded-full animate-pulse"></div>
                    <span class="text-sm ${statusColor}">${agent.status}</span>
                </div>
            </div>
            <p class="text-gray-300 text-sm mb-4">${agent.description}</p>
            <div class="grid grid-cols-2 gap-4 mb-4">
                <div class="text-center">
                    <p class="text-2xl font-bold ${
                      isEnhanced ? "text-primary" : "text-accent"
                    }">${agent.successRate}%</p>
                    <p class="text-xs text-gray-400">Success Rate</p>
                </div>
                <div class="text-center">
                    <p class="text-2xl font-bold ${
                      isEnhanced ? "text-secondary" : "text-accent"
                    }">24/7</p>
                    <p class="text-xs text-gray-400">Uptime</p>
                </div>
            </div>
            <div class="mb-4">
                <h4 class="text-sm font-medium text-gray-300 mb-2">Capabilities</h4>
                <div class="flex flex-wrap gap-1">
                    ${agent.capabilities
                      .map(
                        (cap) => `
                        <span class="px-2 py-1 ${
                          isEnhanced
                            ? "bg-primary bg-opacity-20 text-primary"
                            : "bg-gray-800 text-gray-300"
                        } text-xs rounded-md">${cap}</span>
                    `
                      )
                      .join("")}
                </div>
            </div>
            ${
              isEnhanced
                ? `
            <div class="mb-4 p-3 bg-primary bg-opacity-10 border border-primary border-opacity-30 rounded-lg">
                <div class="flex items-center gap-2 text-primary text-xs font-medium">
                    <div class="w-2 h-2 bg-primary rounded-full"></div>
                    <span>Enhanced features active</span>
                </div>
            </div>
            `
                : ""
            }
            ${
              isConfigurableAgent(agent.name)
                ? `
            <button class="w-full px-4 py-2 border ${
              isEnhanced
                ? "border-primary text-primary hover:bg-primary"
                : "border-gray-600 text-gray-300 hover:bg-gray-600"
            } rounded-lg hover:text-white transition-colors"
                    onclick="configureAgent('${agent.name}')">
                ${
                  isEnhanced ? "⚡ Configure Enhanced Agent" : "Configure Agent"
                }
            </button>
            `
                : `
            <div class="w-full px-4 py-2 border border-gray-800 text-gray-500 rounded-lg text-center">
                No Configuration Available
            </div>
            `
            }
        </div>
    `;
    })
    .join("");

  agentsGrid.innerHTML = agentsHTML;
}

// Render reports - TAILWIND CSS
function renderReports() {
  const reportsGrid = document.getElementById("reports-grid");

  if (!reportsGrid) {
    console.warn("reports-grid element not found");
    return;
  }

  if (!appData.reports || appData.reports.length === 0) {
    reportsGrid.innerHTML =
      '<p class="text-gray-400 col-span-full">No reports generated yet</p>';
    return;
  }

  const reportsHTML = appData.reports
    .map(
      (report) => `
        <div class="bg-dark-lighter border border-gray-700 rounded-xl p-6 hover:border-primary transition-colors cursor-pointer" onclick="downloadReport('${
          report.id
        }')">
            <div class="flex justify-between items-start mb-4">
                <h4 class="text-lg font-semibold text-white">${
                  report.title
                }</h4>
                <span class="px-2 py-1 rounded-md text-xs font-medium ${getSeverityClasses(
                  report.severity
                )}">${report.severity}</span>
            </div>
            <div class="flex justify-between text-sm text-gray-400 mb-4">
                <span>📅 ${new Date(
                  report.generated
                ).toLocaleDateString()}</span>
                <span>📄 ${report.format}</span>
            </div>
            <div class="grid grid-cols-2 gap-4">
                <div class="text-center">
                    <div class="text-2xl font-bold text-primary">${
                      report.vulnerabilities
                    }</div>
                    <div class="text-xs text-gray-400">Vulnerabilities</div>
                </div>
                <div class="text-center">
                    <div class="text-2xl font-bold text-accent">${
                      report.pages
                    }</div>
                    <div class="text-xs text-gray-400">Pages</div>
                </div>
            </div>
        </div>
    `
    )
    .join("");

  reportsGrid.innerHTML = reportsHTML;
}

// Render vulnerabilities - TAILWIND CSS
function renderVulnerabilities() {
  const vulnerabilitiesList = document.getElementById("vulnerabilities-list");

  if (!vulnerabilitiesList) {
    console.warn("vulnerabilities-list element not found");
    return;
  }

  let filteredVulns = appData.vulnerabilities || [];
  if (currentFilter) {
    filteredVulns = appData.vulnerabilities.filter(
      (vuln) => vuln.severity === currentFilter
    );
  }

  if (filteredVulns.length === 0) {
    vulnerabilitiesList.innerHTML =
      '<p class="text-gray-400">No vulnerabilities found yet</p>';
    return;
  }

  const vulnerabilitiesHTML = filteredVulns
    .map((vuln) => {
      // Check if vulnerability has threat intelligence data
      const hasThreatIntel = vuln.threat_intel || vuln.threatIntel;
      const threatScore = hasThreatIntel
        ? vuln.threat_intel?.risk_score || vuln.threatIntel?.risk_score || 0
        : 0;

      return `
        <div class="bg-dark-lighter border border-gray-700 rounded-xl p-6 hover:border-primary transition-colors cursor-pointer" onclick="showVulnerabilityDetails('${
          vuln.id
        }')">
            <div class="flex justify-between items-start mb-4">
                <h4 class="text-lg font-semibold text-white">${vuln.title}</h4>
                <div class="flex items-center gap-2">
                    <span class="px-2 py-1 rounded-md text-xs font-medium ${getSeverityClasses(
                      vuln.severity
                    )}">${vuln.severity}</span>
                    ${
                      hasThreatIntel
                        ? `<span class="px-2 py-1 bg-purple-900 text-purple-300 border border-purple-700 rounded-md text-xs font-medium">🛡️ Enhanced</span>`
                        : ""
                    }
                </div>
            </div>
            
            ${
              hasThreatIntel && threatScore > 0
                ? `
            <div class="mb-3 p-3 bg-purple-900 bg-opacity-30 border border-purple-700 border-opacity-50 rounded-lg">
                <div class="flex items-center gap-2 mb-2">
                    <span class="text-purple-400 text-sm font-medium">🛡️ Threat Intelligence</span>
                    <span class="px-2 py-1 bg-purple-700 text-purple-200 text-xs rounded-full">Risk Score: ${threatScore}/100</span>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs">
                    ${
                      vuln.threat_intel?.intelligence_sources?.includes(
                        "AbuseIPDB"
                      )
                        ? '<span class="text-blue-300">🛡️ IP Reputation</span>'
                        : ""
                    }
                    ${
                      vuln.threat_intel?.intelligence_sources?.includes(
                        "Shodan"
                      )
                        ? '<span class="text-cyan-300">🌐 Device Intel</span>'
                        : ""
                    }
                    ${
                      vuln.threat_intel?.intelligence_sources?.includes(
                        "VirusTotal"
                      )
                        ? '<span class="text-purple-300">🦠 Malware Check</span>'
                        : ""
                    }
                </div>
            </div>
            `
                : ""
            }
            
            <div class="grid grid-cols-1 md:grid-cols-3 gap-2 text-sm text-gray-400 mb-3">
                <span>🎯 CVSS: ${vuln.cvss}</span>
                <span>🔗 ${vuln.url}</span>
                <span>📝 ${vuln.parameter}</span>
            </div>
            <p class="text-gray-300 mb-4 line-clamp-2">${vuln.description}</p>
            <div class="flex justify-between items-center text-sm text-gray-400">
                <div class="flex items-center gap-2">
                    <span>🤖</span>
                    <span>Discovered by ${vuln.discoveredBy}</span>
                    ${
                      hasThreatIntel
                        ? '<span class="text-purple-400">+ Threat Intel</span>'
                        : ""
                    }
                </div>
                <span>${new Date(vuln.timestamp).toLocaleString()}</span>
            </div>
        </div>
    `;
    })
    .join("");

  vulnerabilitiesList.innerHTML = vulnerabilitiesHTML;
}

// Helper function to get severity badge classes
function getSeverityClasses(severity) {
  const severityLower = severity.toLowerCase();
  switch (severityLower) {
    case "critical":
      return "bg-red-900 text-red-300 border border-red-700";
    case "high":
      return "bg-orange-900 text-orange-300 border border-orange-700";
    case "medium":
      return "bg-yellow-900 text-yellow-300 border border-yellow-700";
    case "low":
      return "bg-blue-900 text-blue-300 border border-blue-700";
    default:
      return "bg-gray-800 text-gray-300 border border-gray-600";
  }
}

// Initialize forms - ENHANCED WITH SCAN TYPE LOGIC
function initializeForms() {
  // Quick scan form - FIXED
  const quickScanForm = document.getElementById("quick-scan-form");
  if (quickScanForm) {
    quickScanForm.addEventListener("submit", function (e) {
      e.preventDefault();
      e.stopPropagation();

      const targetUrl = this.querySelector('input[type="url"]').value;
      if (targetUrl) {
        startQuickScan(targetUrl);
        this.querySelector('input[type="url"]').value = ""; // Clear form
      }
    });
  }

  // New scan form - Enhanced with scan mode logic
  const newScanForm = document.getElementById("new-scan-form");
  if (newScanForm) {
    // Add scan mode change listener
    const scanModeSelect = newScanForm.querySelector("#scan-mode");
    if (scanModeSelect) {
      scanModeSelect.addEventListener("change", function () {
        updateAgentSelection(this.value);
      });
      // Initialize with default selection
      updateAgentSelection(scanModeSelect.value);
    }

    newScanForm.addEventListener("submit", function (e) {
      e.preventDefault();
      e.stopPropagation();

      const targetUrl = this.querySelector('input[type="url"]').value;
      const scanMode = this.querySelector("#scan-mode").value;
      const selectedAgents = getSelectedAgentsForScanMode(scanMode);

      if (targetUrl) {
        startNewScan(targetUrl, scanMode, selectedAgents);
        this.reset(); // Clear form
        // Re-initialize agent selection after reset
        updateAgentSelection(scanMode);
      }
    });
  } else {
    console.warn("🔧 New scan form not found");
  }

  // Add quick scan mode change listener
  const quickScanModeSelect = document.getElementById("quick-scan-mode");
  if (quickScanModeSelect) {
    quickScanModeSelect.addEventListener("change", function () {
      // Update any UI elements that depend on the quick scan mode
      console.log(`Quick scan mode changed to: ${this.value}`);
    });
  }

  // Add main scan mode description updates
  const mainScanModeSelect = document.getElementById("scan-mode");
  if (mainScanModeSelect) {
    mainScanModeSelect.addEventListener("change", function () {
      const config = SCAN_MODE_CONFIG[this.value];
      if (config) {
        updateScanModeDescription(this.value, config);
      }
    });

    // Initialize with default
    const defaultMode = mainScanModeSelect.value || "Quick Scan";
    const defaultConfig = SCAN_MODE_CONFIG[defaultMode];
    if (defaultConfig) {
      updateScanModeDescription(defaultMode, defaultConfig);
    }
  }

  // Severity filter - FIXED
  const severityFilter = document.getElementById("severity-filter");
  if (severityFilter) {
    severityFilter.addEventListener("change", function (e) {
      e.stopPropagation();
      currentFilter = this.value;
      renderVulnerabilities();
    });
  }
}

// Scan mode configuration - Updated to match backend types
const SCAN_MODE_CONFIG = {
  "Quick Scan": {
    name: "⚡ Quick Scan",
    agents: ["Web App Agent", "Report Agent"],
    description:
      "Fast vulnerability assessment focusing on web application security",
    duration: "30 minutes",
    priorities: ["XSS Detection", "SQL Injection", "CSRF Testing"],
    cvss_threshold: 4.0,
    estimated_findings: "5-15 web vulnerabilities",
    readonly: true,
    agentInfo:
      "Focuses on common web application vulnerabilities with quick scanning",
  },
  "Full Scan": {
    name: "🔍 Full Scan",
    agents: [
      "Recon Agent",
      "Web App Agent",
      "Network Agent",
      "API Agent",
      "Report Agent",
    ],
    description: "Comprehensive security assessment using all core agents",
    duration: "1-2 hours",
    priorities: [
      "Web Application Security",
      "Network Security",
      "API Security",
      "Asset Discovery",
    ],
    cvss_threshold: 3.0,
    estimated_findings: "15-40 vulnerabilities across all categories",
    readonly: true,
    agentInfo: "Complete security assessment with all core security agents",
  },
  "Enhanced Scan": {
    name: "� Enhanced Scan",
    agents: [
      "Recon Agent",
      "Web App Agent",
      "Network Agent",
      "API Agent",
      "Enhanced Security Agent",
      "Threat Intelligence Agent",
      "Report Agent",
    ],
    description:
      "Advanced security assessment with ML-powered vulnerability detection and threat intelligence",
    duration: "2-3 hours",
    priorities: [
      "Advanced Vulnerability Detection",
      "Threat Intelligence Analysis",
      "ML-Powered Security Testing",
      "Comprehensive Coverage",
    ],
    cvss_threshold: 2.0,
    estimated_findings: "25-60 vulnerabilities with advanced analysis",
    readonly: true,
    agentInfo:
      "Advanced testing with AI agents, threat intelligence, and enhanced detection",
  },
  "Custom Scan": {
    name: "🎯 Custom Scan",
    agents: [], // User selectable
    description:
      "Choose specific agents for targeted testing based on your requirements",
    duration: "Variable",
    priorities: ["User Defined"],
    cvss_threshold: 0.0,
    estimated_findings: "Depends on selected agents",
    readonly: false, // Allow agent selection
    agentInfo:
      "Select the specific security agents you want to use for this scan",
  },
};

// Update agent selection based on scan mode
function updateAgentSelection(scanMode) {
  const agentSelectionGroup = document.getElementById("ai-agents-group");
  const scanDuration = document.getElementById("scan-duration");
  const scanAgentsCount = document.getElementById("scan-agents-count");
  const scanFindings = document.getElementById("scan-findings");
  const scanFocusInfo = document.getElementById("scan-focus-info");

  if (!agentSelectionGroup) {
    console.warn("🔧 ai-agents-group element not found");
    return;
  }

  const config = SCAN_MODE_CONFIG[scanMode];
  if (!config) {
    console.warn(`🔧 No config found for scan mode: ${scanMode}`);
    return;
  }

  console.log(`🔧 Updating agent selection for ${scanMode}`);

  // Update scan information display
  if (scanDuration) scanDuration.textContent = config.duration;
  if (scanAgentsCount)
    scanAgentsCount.textContent = `${config.agents.length} agents`;
  if (scanFindings) scanFindings.textContent = config.estimated_findings;
  if (scanFocusInfo) scanFocusInfo.textContent = config.priorities.join(", ");

  if (config.readonly) {
    // For predefined scans, show the agents but make them readonly
    agentSelectionGroup.style.display = "block";

    // Update the agents display to show selected agents
    const checkboxes = agentSelectionGroup.querySelectorAll(
      'input[type="checkbox"]'
    );
    checkboxes.forEach((checkbox) => {
      const label = checkbox.nextElementSibling;
      const agentName = label ? label.textContent.trim() : "";

      // Map HTML agent names to config agent names
      let isIncluded = false;

      if (agentName.includes("Recon Agent")) {
        isIncluded = config.agents.includes("Recon Agent");
      } else if (agentName.includes("Web App Agent")) {
        isIncluded = config.agents.includes("Web App Agent");
      } else if (agentName.includes("Network Agent")) {
        isIncluded = config.agents.includes("Network Agent");
      } else if (agentName.includes("API Agent")) {
        isIncluded = config.agents.includes("API Agent");
      } else if (agentName.includes("Report Agent")) {
        isIncluded = config.agents.includes("Report Agent");
      } else if (agentName.includes("Enhanced Security Agent")) {
        isIncluded = config.agents.includes("Enhanced Security Agent");
      } else if (agentName.includes("Threat Intelligence Agent")) {
        isIncluded = config.agents.includes("Threat Intelligence Agent");
      }

      checkbox.checked = isIncluded;
      checkbox.disabled = true; // Make readonly

      // Visual styling for selected/unselected
      const labelElement = checkbox.parentElement;
      if (isIncluded) {
        labelElement.style.opacity = "1";
        labelElement.classList.add(
          "bg-primary",
          "bg-opacity-20",
          "border",
          "border-primary",
          "border-opacity-50",
          "rounded",
          "px-2",
          "py-1"
        );
      } else {
        labelElement.style.opacity = "0.4";
        labelElement.classList.remove(
          "bg-primary",
          "bg-opacity-20",
          "border",
          "border-primary",
          "border-opacity-50",
          "rounded",
          "px-2",
          "py-1"
        );
      }
    });

    // Add info message
    updateAgentInfo(config.agentInfo);
    console.log(
      `🔧 ${scanMode}: Using predefined agents: ${config.agents.join(", ")}`
    );
  } else {
    // For custom scan modes, show the AI Agents section and enable selection
    agentSelectionGroup.style.display = "block";

    // Enable all checkboxes and reset styling
    const checkboxes = agentSelectionGroup.querySelectorAll(
      'input[type="checkbox"]'
    );
    checkboxes.forEach((checkbox) => {
      checkbox.disabled = false;
      checkbox.checked = false; // Reset selection
      const labelElement = checkbox.parentElement;
      labelElement.style.opacity = "1";
      labelElement.classList.remove(
        "bg-primary",
        "bg-opacity-20",
        "border",
        "border-primary",
        "border-opacity-50",
        "rounded",
        "px-2",
        "py-1"
      );
    });

    updateAgentInfo(config.agentInfo);
    console.log(`🔧 ${scanMode}: User can select agents`);
  }

  // Update scan mode description in any status displays
  updateScanModeDescription(scanMode, config);
}

// Update agent info message
function updateAgentInfo(message) {
  let infoElement = document.getElementById("agent-info-message");

  if (!infoElement) {
    // Create info element if it doesn't exist
    const agentGroup = document.getElementById("ai-agents-group");
    if (agentGroup) {
      infoElement = document.createElement("div");
      infoElement.id = "agent-info-message";
      infoElement.className =
        "mt-3 p-3 bg-blue-900 bg-opacity-30 border border-blue-700 border-opacity-50 rounded-lg text-sm text-blue-300";
      agentGroup.appendChild(infoElement);
    }
  }

  if (infoElement) {
    infoElement.innerHTML = `<span class="font-medium">ℹ️ ${message}</span>`;
  }
}

// Update scan mode description
function updateScanModeDescription(scanMode, config) {
  const descElement = document.getElementById("scan-mode-description");

  if (descElement) {
    descElement.textContent = `${config.description} • ${config.duration} • ${config.estimated_findings}`;
  }
}

// Get selected agents for scan mode
function getSelectedAgentsForScanMode(scanMode) {
  const config = SCAN_MODE_CONFIG[scanMode];

  if (config && config.readonly) {
    // For predefined scan modes, return predefined agents
    console.log(`🔧 ${scanMode}: Using predefined agents:`, config.agents);
    return config.agents;
  } else {
    // For Custom scan, return user-selected agents (map HTML names to backend names)
    const selectedAgents = Array.from(
      document.querySelectorAll(
        '#ai-agents-group input[type="checkbox"]:checked'
      )
    )
      .map((cb) => {
        const spanElement = cb.nextElementSibling;
        if (!spanElement) {
          console.warn("🔧 No span element found for checkbox");
          return null;
        }

        const agentText = spanElement.textContent.trim();
        console.log(`🔧 Processing agent text: "${agentText}"`);

        // Map HTML agent names to backend names
        if (agentText.includes("Recon Agent")) return "Recon Agent";
        if (agentText.includes("Web App Agent")) return "Web App Agent";
        if (agentText.includes("Network Agent")) return "Network Agent";
        if (agentText.includes("API Agent")) return "API Agent";
        if (agentText.includes("Report Agent")) return "Report Agent";
        if (agentText.includes("Enhanced Security Agent"))
          return "Enhanced Security Agent";
        if (agentText.includes("Threat Intelligence Agent"))
          return "Threat Intelligence Agent";

        // Fallback: remove emoji and return cleaned name
        const cleanName = agentText.replace(/^[🔍🌐🔒⚡📋🔬🛡️]\s*/, "");
        console.warn(
          `🔧 Fallback agent mapping for: "${agentText}" -> "${cleanName}"`
        );
        return cleanName;
      })
      .filter((agent) => agent); // Remove null values

    console.log(`🔧 ${scanMode}: Selected agents:`, selectedAgents);

    // Return selected agents (no fallback to Web App Agent since backend now requires at least one)
    return selectedAgents;
  }
}

// Initialize modal - FIXED
function initializeModal() {
  const modal = document.getElementById("vulnerability-modal");

  if (!modal) {
    console.warn("vulnerability-modal element not found");
    return;
  }

  // Modal click outside to close
  modal.addEventListener("click", function (e) {
    if (e.target === modal) {
      modal.classList.add("hidden");
    }
  });
}

// Show vulnerability details in modal - FIXED
function showVulnerabilityDetails(vulnId) {
  const vulnerability = appData.vulnerabilities.find((v) => v.id === vulnId);
  if (!vulnerability) return;

  const modal = document.getElementById("vulnerability-modal");
  const modalTitle = document.getElementById("modal-title");
  const modalBody = document.getElementById("modal-body");

  modalTitle.textContent = vulnerability.title;

  modalBody.innerHTML = `
        <div class="space-y-6">
            <div class="bg-gray-800 p-4 rounded-lg">
                <h4 class="text-lg font-semibold text-white mb-3">Severity & Score</h4>
                <div class="space-y-2">
                    <p class="text-gray-300"><span class="font-medium text-gray-400">Severity:</span> <span class="px-2 py-1 rounded text-xs font-medium ${getSeverityClasses(
                      vulnerability.severity
                    )}">${vulnerability.severity}</span></p>
                    <p class="text-gray-300"><span class="font-medium text-gray-400">CVSS Score:</span> ${
                      vulnerability.cvss
                    }</p>
                </div>
            </div>

            <div class="bg-gray-800 p-4 rounded-lg">
                <h4 class="text-lg font-semibold text-white mb-3">Vulnerability Details</h4>
                <div class="space-y-2">
                    <p class="text-gray-300"><span class="font-medium text-gray-400">URL:</span> ${
                      vulnerability.url
                    }</p>
                    <p class="text-gray-300"><span class="font-medium text-gray-400">Parameter:</span> ${
                      vulnerability.parameter
                    }</p>
                    <p class="text-gray-300"><span class="font-medium text-gray-400">Description:</span> ${
                      vulnerability.description
                    }</p>
                </div>
            </div>

            <div class="bg-gray-800 p-4 rounded-lg">
                <h4 class="text-lg font-semibold text-white mb-3">Proof of Concept</h4>
                <div class="bg-gray-900 p-3 rounded border border-gray-600 font-mono text-sm text-green-400 overflow-x-auto">${
                  vulnerability.payload
                }</div>
            </div>

            <div class="bg-gray-800 p-4 rounded-lg">
                <h4 class="text-lg font-semibold text-white mb-3">Remediation</h4>
                <p class="text-gray-300">${vulnerability.remediation}</p>
            </div>

            <div class="bg-gray-800 p-4 rounded-lg">
                <h4 class="text-lg font-semibold text-white mb-3">Discovery Information</h4>
                <div class="space-y-2">
                    <p class="text-gray-300"><span class="font-medium text-gray-400">Discovered by:</span> ${
                      vulnerability.discoveredBy
                    }</p>
                    <p class="text-gray-300"><span class="font-medium text-gray-400">Timestamp:</span> ${new Date(
                      vulnerability.timestamp
                    ).toLocaleString()}</p>
                </div>
            </div>
        </div>
    `;

  modal.classList.remove("hidden");
}

// Show modal with custom content - TAILWIND CSS
function showModal(content) {
  // Create modal if it doesn't exist
  let modal = document.getElementById("custom-modal");
  if (!modal) {
    modal = document.createElement("div");
    modal.id = "custom-modal";
    modal.className =
      "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4";
    modal.innerHTML = `
            <div id="custom-modal-content" class="relative"></div>
        `;
    document.body.appendChild(modal);

    // Add click outside to close
    modal.addEventListener("click", function (e) {
      if (e.target === modal) {
        closeModal();
      }
    });
  }

  // Set content and show
  document.getElementById("custom-modal-content").innerHTML = content;
  modal.classList.remove("hidden");
  modal.style.display = "flex";
}

// Close modal
function closeModal() {
  const modal = document.getElementById("custom-modal");
  if (modal) {
    modal.classList.add("hidden");
    modal.style.display = "none";
  }
}

// Start quick scan - Updated for focused scanning modes
async function startQuickScan(targetUrl) {
  try {
    const notification = createNotification(
      "Creating focused scan for " + targetUrl,
      "info"
    );
    document.body.appendChild(notification);

    // Get scan mode from the quick scan form
    const quickScanModeSelect = document.getElementById("quick-scan-mode");
    const scanMode = quickScanModeSelect
      ? quickScanModeSelect.value
      : "focused";

    // Get scan mode configuration
    const scanConfig = SCAN_MODE_CONFIG[scanMode];

    // Create scan via API
    const scanData = {
      target: targetUrl,
      scanMode: scanMode,
      agents: scanConfig.agents,
    };

    const newScan = await apiRequest("/scans", {
      method: "POST",
      body: JSON.stringify(scanData),
    });

    // Add to local data and update UI
    appData.scans.unshift(newScan);
    renderActiveScans();

    const successNotification = createNotification(
      `${scanConfig.name} created successfully for ${targetUrl}`,
      "success"
    );
    document.body.appendChild(successNotification);

    // Start real scanning
    await startRealScan(newScan.id);
  } catch (error) {
    console.error("Failed to start quick scan:", error);
    showErrorNotification("Failed to start scan. Please try again.");
  }
}

// Start new scan - Updated for scan modes
async function startNewScan(targetUrl, scanMode, selectedAgents) {
  try {
    const config = SCAN_MODE_CONFIG[scanMode];
    console.log(`🚀 Starting new scan:`, {
      targetUrl,
      scanMode,
      selectedAgents,
      agentCount: selectedAgents.length,
    });

    const notification = createNotification(
      `Creating ${config.name} for ${targetUrl}`,
      "info"
    );
    document.body.appendChild(notification);

    // Create scan via API
    const scanData = {
      target: targetUrl,
      scanMode: scanMode,
      agents: selectedAgents, // Send exactly what was selected, backend will validate
    };

    console.log(`📡 Sending scan data to backend:`, scanData);

    const newScan = await apiRequest("/scans", {
      method: "POST",
      body: JSON.stringify(scanData),
    });

    console.log(`✅ Scan created successfully:`, newScan);

    // Add to local data and update UI
    appData.scans.unshift(newScan);
    renderActiveScans();

    const successNotification = createNotification(
      `${scanType} created successfully for ${targetUrl}`,
      "success"
    );
    document.body.appendChild(successNotification);

    // Start real scanning
    await startRealScan(newScan.id);
  } catch (error) {
    console.error("❌ Failed to start new scan:", error);
    showErrorNotification(`Failed to start scan: ${error.message}`);
  }
}

// View scan details - ENHANCED
async function viewScanDetails(scanId) {
  try {
    // Get fresh scan data from API
    const scan = await apiRequest(`/scans/${scanId}`);

    // Get vulnerabilities for this scan
    const allVulns = await apiRequest("/vulnerabilities");
    const scanVulns = allVulns.filter((v) => v.scanId === scanId);

    // Create modal content with Tailwind CSS
    const modalContent = `
            <div class="bg-dark-lighter rounded-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
                <div class="flex justify-between items-center p-6 border-b border-gray-700">
                    <h2 class="text-xl font-bold text-white">Scan Details: ${
                      scan.target
                    }</h2>
                    <button class="text-gray-400 hover:text-white text-2xl" onclick="closeModal()">&times;</button>
                </div>
                <div class="p-6 space-y-6">
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        <div class="bg-gray-800 p-4 rounded-lg">
                            <label class="block text-sm font-medium text-gray-400 mb-1">Target</label>
                            <span class="text-white">${scan.target}</span>
                        </div>
                        <div class="bg-gray-800 p-4 rounded-lg">
                            <label class="block text-sm font-medium text-gray-400 mb-1">Status</label>
                            <span class="px-2 py-1 rounded text-xs font-medium ${
                              scan.status === "completed"
                                ? "bg-green-900 text-green-300"
                                : "bg-blue-900 text-blue-300"
                            }">${scan.status}</span>
                        </div>
                        <div class="bg-gray-800 p-4 rounded-lg">
                            <label class="block text-sm font-medium text-gray-400 mb-1">Progress</label>
                            <span class="text-white">${scan.progress}%</span>
                        </div>
                        <div class="bg-gray-800 p-4 rounded-lg">
                            <label class="block text-sm font-medium text-gray-400 mb-1">Started</label>
                            <span class="text-white">${new Date(
                              scan.started
                            ).toLocaleString()}</span>
                        </div>
                        <div class="bg-gray-800 p-4 rounded-lg">
                            <label class="block text-sm font-medium text-gray-400 mb-1">Scan Type</label>
                            <span class="text-white">${scan.scanType}</span>
                        </div>
                        <div class="bg-gray-800 p-4 rounded-lg">
                            <label class="block text-sm font-medium text-gray-400 mb-1">Agents</label>
                            <span class="text-white">${scan.agents.join(
                              ", "
                            )}</span>
                        </div>
                    </div>

                    <div class="border-t border-gray-700 pt-6">
                        <h3 class="text-lg font-semibold text-white mb-4">Vulnerabilities Found (${
                          scanVulns.length
                        })</h3>
                        <div class="space-y-4">
                            ${
                              scanVulns.length > 0
                                ? scanVulns
                                    .map(
                                      (vuln) => `
                                <div class="bg-gray-800 border border-gray-600 rounded-lg p-4">
                                    <div class="flex justify-between items-start mb-3">
                                        <h4 class="font-medium text-white">${
                                          vuln.title
                                        }</h4>
                                        <span class="px-2 py-1 rounded text-xs font-medium ${getSeverityClasses(
                                          vuln.severity
                                        )}">${vuln.severity}</span>
                                    </div>
                                    <div class="space-y-2 text-sm">
                                        <p class="text-gray-300"><span class="font-medium text-gray-400">Description:</span> ${
                                          vuln.description
                                        }</p>
                                        <p class="text-gray-300"><span class="font-medium text-gray-400">URL:</span> ${
                                          vuln.url
                                        }</p>
                                        <p class="text-gray-300"><span class="font-medium text-gray-400">Discovered by:</span> ${
                                          vuln.discoveredBy
                                        }</p>
                                        ${
                                          vuln.cvss
                                            ? `<p class="text-gray-300"><span class="font-medium text-gray-400">CVSS Score:</span> ${vuln.cvss}</p>`
                                            : ""
                                        }
                                    </div>
                                </div>
                            `
                                    )
                                    .join("")
                                : '<p class="text-gray-400 text-center py-8">No vulnerabilities found yet.</p>'
                            }
                        </div>
                    </div>
                </div>
            </div>
        `;

    // Show modal
    showModal(modalContent);
  } catch (error) {
    console.error("Failed to load scan details:", error);
    showErrorNotification("Failed to load scan details");
  }
}

// Agent configuration management
let currentConfigAgent = null;
let agentTestConfigs = {};

// Map display names to backend agent names
function getBackendAgentName(displayName) {
  const agentNameMap = {
    "Web App Agent": "webapp",
    "API Agent": "api",
    "Network Agent": "network",
    "Recon Agent": "recon",
    webapp: "webapp",
    api: "api",
    network: "network",
    recon: "recon",
  };

  return agentNameMap[displayName] || null; // Return null for unsupported agents
}

// Check if agent has configurable settings
function isConfigurableAgent(displayName) {
  const configurableAgents = [
    "Web App Agent",
    "API Agent",
    "Network Agent",
    "Recon Agent",
    "webapp",
    "api",
    "network",
    "recon",
  ];
  return configurableAgents.includes(displayName);
}

async function configureAgent(agentName) {
  const backendAgentName = getBackendAgentName(agentName);

  if (!backendAgentName) {
    showNotification(
      `${agentName} does not have configurable settings`,
      "warning"
    );
    return;
  }

  currentConfigAgent = backendAgentName;
  showAgentConfigModal();
  await loadAgentConfiguration(backendAgentName);
}

function showAgentConfigModal() {
  const modal = document.getElementById("agent-config-modal");
  const title = document.getElementById("config-modal-title");

  if (currentConfigAgent) {
    // Convert backend name to display name
    const displayNameMap = {
      webapp: "Web App Agent",
      api: "API Agent",
      network: "Network Agent",
      recon: "Recon Agent",
    };
    const displayName =
      displayNameMap[currentConfigAgent] ||
      currentConfigAgent.toUpperCase() + " Agent";
    title.textContent = `Configure ${displayName}`;
  }

  // Reset modal state
  document.getElementById("config-loading").classList.remove("hidden");
  document.getElementById("config-content").classList.add("hidden");
  document.getElementById("config-error").classList.add("hidden");

  modal.classList.remove("hidden");
}

function closeAgentConfigModal() {
  const modal = document.getElementById("agent-config-modal");
  modal.classList.add("hidden");
  currentConfigAgent = null;
}

async function loadAgentConfiguration(agentName) {
  try {
    const response = await fetch(`/api/agents/${agentName}/config`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const config = await response.json();
    agentTestConfigs[agentName] = config;

    renderAgentConfigTests(config);

    document.getElementById("config-loading").classList.add("hidden");
    document.getElementById("config-content").classList.remove("hidden");
  } catch (error) {
    console.error("Failed to load agent configuration:", error);
    document.getElementById("config-loading").classList.add("hidden");
    document.getElementById("config-error").classList.remove("hidden");
  }
}

function renderAgentConfigTests(config) {
  const container = document.getElementById("config-tests-container");
  container.innerHTML = "";

  if (!config.available_tests || config.available_tests.length === 0) {
    container.innerHTML =
      '<p class="text-gray-400 text-center py-4">No configurable tests available for this agent.</p>';
    updateEnabledCount();
    return;
  }

  config.available_tests.forEach((test) => {
    const isEnabled = config.enabled_tests.includes(test.id);

    const testElement = document.createElement("div");
    testElement.className =
      "flex items-start gap-3 p-3 bg-gray-800 rounded-lg border border-gray-700";
    testElement.innerHTML = `
            <div class="flex items-center mt-1">
                <input type="checkbox" 
                       id="test-${test.id}" 
                       ${isEnabled ? "checked" : ""} 
                       onchange="toggleTest('${test.id}')"
                       class="w-4 h-4 text-primary bg-gray-700 border-gray-600 rounded focus:ring-primary focus:ring-2">
            </div>
            <div class="flex-1">
                <label for="test-${
                  test.id
                }" class="block text-white font-medium cursor-pointer">
                    ${test.name}
                </label>
                <p class="text-gray-400 text-sm mt-1">${test.description}</p>
                <div class="flex items-center gap-4 mt-2 text-xs">
                    <span class="px-2 py-1 bg-${getSeverityColor(
                      test.severity
                    )}-900 text-${getSeverityColor(test.severity)}-300 rounded">
                        ${test.severity.toUpperCase()}
                    </span>
                    <span class="text-gray-500">
                        ${test.category}
                    </span>
                </div>
            </div>
        `;

    container.appendChild(testElement);
  });

  updateEnabledCount();
}

function getSeverityColor(severity) {
  const colors = {
    critical: "red",
    high: "orange",
    medium: "yellow",
    low: "green",
    info: "blue",
  };
  return colors[severity.toLowerCase()] || "gray";
}

function toggleTest(testId) {
  if (!currentConfigAgent || !agentTestConfigs[currentConfigAgent]) return;

  const config = agentTestConfigs[currentConfigAgent];
  const checkbox = document.getElementById(`test-${testId}`);

  if (checkbox.checked) {
    if (!config.enabled_tests.includes(testId)) {
      config.enabled_tests.push(testId);
    }
  } else {
    const index = config.enabled_tests.indexOf(testId);
    if (index > -1) {
      config.enabled_tests.splice(index, 1);
    }
  }

  updateEnabledCount();
}

function updateEnabledCount() {
  if (!currentConfigAgent || !agentTestConfigs[currentConfigAgent]) return;

  const config = agentTestConfigs[currentConfigAgent];
  const enabledCount = config.enabled_tests ? config.enabled_tests.length : 0;

  const countElement = document.getElementById("enabled-count");
  if (countElement) {
    countElement.textContent = enabledCount;
  }
}

async function saveAgentConfiguration() {
  if (!currentConfigAgent || !agentTestConfigs[currentConfigAgent]) return;

  try {
    const config = agentTestConfigs[currentConfigAgent];

    const response = await fetch(`/api/agents/${currentConfigAgent}/config`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        enabled_tests: config.enabled_tests,
      }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const result = await response.json();

    if (result.success) {
      // Show success message
      showNotification("Configuration saved successfully!", "success");
      closeAgentConfigModal();
    } else {
      throw new Error(result.message || "Failed to save configuration");
    }
  } catch (error) {
    console.error("Failed to save agent configuration:", error);
    showNotification("Failed to save configuration: " + error.message, "error");
  }
}

function showNotification(message, type = "info") {
  // Create notification element
  const notification = document.createElement("div");
  notification.className = `fixed top-4 right-4 z-50 px-4 py-3 rounded-lg shadow-lg transition-all duration-300 transform translate-x-full`;

  // Set colors based on type
  const colors = {
    success: "bg-green-600 text-white",
    error: "bg-red-600 text-white",
    warning: "bg-yellow-600 text-black",
    info: "bg-blue-600 text-white",
  };

  notification.className += ` ${colors[type] || colors.info}`;
  notification.textContent = message;

  document.body.appendChild(notification);

  // Animate in
  setTimeout(() => {
    notification.classList.remove("translate-x-full");
  }, 100);

  // Auto remove after 3 seconds
  setTimeout(() => {
    notification.classList.add("translate-x-full");
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, 300);
  }, 3000);
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
      method: "POST",
    });

    console.log("✅ Real scan started:", result);

    // Request real-time progress updates via Socket.IO
    if (socket && socket.connected) {
      socket.emit("scan_progress_request", { scan_id: scanId });
    } else {
      // Fallback to polling if Socket.IO is not available
      pollScanProgress(scanId);
    }
  } catch (error) {
    console.error("❌ Failed to start real scan:", error);

    // Hide progress modal on error
    hideScanProgressModal();

    // Check if it's a validation error
    if (error.message.includes("Cannot scan")) {
      showErrorNotification(`Security Error: ${error.message}`);
    } else {
      showErrorNotification("Failed to start real scan. Please try again.");
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
      const scanIndex = appData.scans.findIndex((s) => s.id === scanId);
      if (scanIndex !== -1) {
        appData.scans[scanIndex] = scan;
        renderActiveScans();
      }

      // Check if scan is complete
      if (scan.status === "completed" || scan.status === "failed") {
        clearInterval(pollInterval);

        // Hide progress modal after a short delay
        setTimeout(() => {
          hideScanProgressModal();
        }, 2000);

        // Reload all data to get vulnerabilities
        await loadScans();
        await loadVulnerabilities();
        await loadStats();

        const statusMessage =
          scan.status === "completed"
            ? `✅ Real scan completed for ${scan.target}`
            : `❌ Scan failed for ${scan.target}`;

        const notification = createNotification(
          statusMessage,
          scan.status === "completed" ? "success" : "error"
        );
        document.body.appendChild(notification);
      }
    } catch (error) {
      console.error("Failed to poll scan progress:", error);
      clearInterval(pollInterval);
      hideScanProgressModal();
    }
  }, 2000); // Poll every 2 seconds for more responsive updates
}

// Create notification - ENHANCED
function createNotification(message, type = "info") {
  const notification = document.createElement("div");
  notification.className = `notification notification--${type}`;

  // Set colors based on type
  let backgroundColor = "var(--color-surface)";
  let borderColor = "var(--color-border)";
  let textColor = "var(--color-text)";

  if (type === "error") {
    backgroundColor = "#2d1b1b";
    borderColor = "#ff5459";
    textColor = "#ff9999";
  } else if (type === "success") {
    backgroundColor = "#1b2d1b";
    borderColor = "#4caf50";
    textColor = "#99ff99";
  } else if (type === "info") {
    backgroundColor = "#1b1b2d";
    borderColor = "#2196f3";
    textColor = "#99ccff";
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

// Download/View report - ENHANCED
async function downloadReport(reportId) {
  try {
    console.log(`📄 Opening report: ${reportId}`);

    // Fetch the full report data from API
    const reportData = await apiRequest(`/reports/${reportId}`);

    if (reportData.format === "HTML" && reportData.content) {
      // Display HTML report in a modal
      showReportModal(reportData);
    } else if (reportData.format === "PDF") {
      // For PDF, create download link
      downloadReportFile(reportData);
    } else if (reportData.format === "JSON") {
      // For JSON, display formatted data
      showJsonReport(reportData);
    } else {
      // Fallback: show report summary
      showReportSummary(reportData);
    }

    const notification = createNotification(
      `Opened ${reportData.title}`,
      "success"
    );
    document.body.appendChild(notification);
  } catch (error) {
    console.error("Failed to open report:", error);
    const notification = createNotification("Failed to open report", "error");
    document.body.appendChild(notification);
  }
}

// Show HTML report in modal
function showReportModal(reportData) {
  const modalContent = `
        <div class="bg-dark-lighter rounded-xl max-w-6xl w-full max-h-[90vh] overflow-y-auto">
            <div class="flex justify-between items-center p-6 border-b border-gray-700">
                <h2 class="text-xl font-bold text-white">${
                  reportData.title
                }</h2>
                <div class="flex gap-2">
                    <button class="px-3 py-1 bg-primary text-white rounded text-sm hover:bg-primary-dark" onclick="downloadTextReport('${
                      reportData.id
                    }')">
                        📄 Download TXT
                    </button>
                    <button class="text-gray-400 hover:text-white text-2xl" onclick="closeModal()">&times;</button>
                </div>
            </div>
            <div class="p-6">
                ${generateReportContent(reportData)}
            </div>
        </div>
    `;
  showModal(modalContent);
}

// Generate report content if not available
function generateReportContent(reportData) {
  const vulnerabilities = reportData.vulnerabilities || [];
  const scan = reportData.scan || {};

  // Calculate severity counts
  const criticalCount = vulnerabilities.filter(
    (v) => v.severity === "Critical"
  ).length;
  const highCount = vulnerabilities.filter((v) => v.severity === "High").length;
  const mediumCount = vulnerabilities.filter(
    (v) => v.severity === "Medium"
  ).length;
  const lowCount = vulnerabilities.filter((v) => v.severity === "Low").length;

  // Get unique agents used
  const agentsUsed = [
    ...new Set(vulnerabilities.map((v) => v.discoveredBy)),
  ].filter(Boolean);
  const primaryAgent = agentsUsed[0] || "AI Bug Bounty Scanner";

  // Format scan date
  const scanDate = scan.started
    ? new Date(scan.started).toLocaleDateString()
    : new Date().toLocaleDateString();
  const reportDate = new Date().toLocaleDateString();

  return `
        <div class="space-y-8 text-white">
            <!-- Report Header -->
            <div class="bg-gradient-to-r from-primary to-blue-600 p-6 rounded-xl text-white">
                <div class="flex items-center gap-3 mb-4">
                    <div class="w-12 h-12 bg-white bg-opacity-20 rounded-lg flex items-center justify-center">
                        <span class="text-2xl">🛡️</span>
                    </div>
                    <div>
                        <h1 class="text-2xl font-bold">Vulnerability Report</h1>
                        <p class="text-blue-100">Security Assessment Results</p>
                    </div>
                </div>
            </div>

            <!-- Summary Section -->
            <div class="bg-gray-800 border border-gray-700 rounded-xl p-6">
                <div class="flex items-center gap-3 mb-6">
                    <span class="text-2xl">📊</span>
                    <h2 class="text-xl font-bold text-white">Executive Summary</h2>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div class="space-y-3">
                        <div class="flex justify-between">
                            <span class="text-gray-400">Target:</span>
                            <span class="font-medium text-primary">${
                              scan.target || "Unknown Target"
                            }</span>
                        </div>
                        <div class="flex justify-between">
                            <span class="text-gray-400">Scan Date:</span>
                            <span class="font-medium">${scanDate}</span>
                        </div>
                        <div class="flex justify-between">
                            <span class="text-gray-400">Generated By:</span>
                            <span class="font-medium">${primaryAgent}</span>
                        </div>
                    </div>
                    <div class="space-y-3">
                        <div class="flex justify-between">
                            <span class="text-gray-400">Total Vulnerabilities:</span>
                            <span class="font-bold text-2xl text-primary">${
                              vulnerabilities.length
                            }</span>
                        </div>
                        <div class="flex justify-between">
                            <span class="text-gray-400">Report Generated:</span>
                            <span class="font-medium">${reportDate}</span>
                        </div>
                    </div>
                </div>

                <!-- Severity Breakdown -->
                <div class="bg-gray-900 p-4 rounded-lg">
                    <h3 class="text-lg font-semibold mb-4 text-white">Severity Breakdown</h3>
                    <div class="grid grid-cols-4 gap-4">
                        <div class="text-center p-3 bg-red-900 bg-opacity-50 rounded-lg border border-red-700">
                            <div class="text-2xl font-bold text-red-400">${criticalCount}</div>
                            <div class="text-xs text-red-300">Critical</div>
                        </div>
                        <div class="text-center p-3 bg-orange-900 bg-opacity-50 rounded-lg border border-orange-700">
                            <div class="text-2xl font-bold text-orange-400">${highCount}</div>
                            <div class="text-xs text-orange-300">High</div>
                        </div>
                        <div class="text-center p-3 bg-yellow-900 bg-opacity-50 rounded-lg border border-yellow-700">
                            <div class="text-2xl font-bold text-yellow-400">${mediumCount}</div>
                            <div class="text-xs text-yellow-300">Medium</div>
                        </div>
                        <div class="text-center p-3 bg-blue-900 bg-opacity-50 rounded-lg border border-blue-700">
                            <div class="text-2xl font-bold text-blue-400">${lowCount}</div>
                            <div class="text-xs text-blue-300">Low</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Vulnerability Details -->
            <div class="bg-gray-800 border border-gray-700 rounded-xl p-6">
                <div class="flex items-center gap-3 mb-6">
                    <span class="text-2xl">🔍</span>
                    <h2 class="text-xl font-bold text-white">Vulnerability Details</h2>
                </div>

                ${
                  vulnerabilities.length > 0
                    ? `
                    <div class="space-y-6">
                        ${vulnerabilities
                          .map(
                            (vuln, index) => `
                            <div class="bg-gray-900 border border-gray-600 rounded-lg p-6">
                                <!-- Vulnerability Header -->
                                <div class="flex justify-between items-start mb-4">
                                    <div class="flex items-center gap-3">
                                        <span class="bg-primary text-white px-3 py-1 rounded-full text-sm font-bold">${
                                          index + 1
                                        }</span>
                                        <h3 class="text-lg font-semibold text-white">${
                                          vuln.title
                                        }</h3>
                                    </div>
                                    <span class="px-3 py-1 rounded-full text-sm font-medium ${getSeverityClasses(
                                      vuln.severity
                                    )}">${vuln.severity}</span>
                                </div>

                                <!-- Vulnerability Info Grid -->
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                                    <div class="space-y-2">
                                        <div class="flex justify-between">
                                            <span class="text-gray-400">CVSS Score:</span>
                                            <span class="font-medium">${
                                              vuln.cvss || "N/A"
                                            }</span>
                                        </div>
                                        <div class="flex justify-between">
                                            <span class="text-gray-400">Parameter:</span>
                                            <span class="font-medium text-primary">${
                                              vuln.parameter || "N/A"
                                            }</span>
                                        </div>
                                    </div>
                                    <div class="space-y-2">
                                        <div class="flex justify-between">
                                            <span class="text-gray-400">Discovered By:</span>
                                            <span class="font-medium">${
                                              vuln.discoveredBy
                                            }</span>
                                        </div>
                                        <div class="flex justify-between">
                                            <span class="text-gray-400">Discovery Time:</span>
                                            <span class="font-medium">${
                                              vuln.timestamp
                                                ? new Date(
                                                    vuln.timestamp
                                                  ).toLocaleString()
                                                : "N/A"
                                            }</span>
                                        </div>
                                    </div>
                                </div>

                                <!-- Affected URL -->
                                <div class="mb-4">
                                    <span class="text-gray-400">Affected URL:</span>
                                    <div class="bg-gray-800 p-2 rounded mt-1 font-mono text-sm text-blue-400 break-all">${
                                      vuln.url
                                    }</div>
                                </div>

                                <!-- Description -->
                                <div class="mb-4">
                                    <h4 class="font-semibold text-white mb-2">📝 Description</h4>
                                    <p class="text-gray-300 leading-relaxed">${
                                      vuln.description
                                    }</p>
                                </div>

                                <!-- Evidence -->
                                <div class="mb-4">
                                    <h4 class="font-semibold text-white mb-2">🔬 Evidence / Proof of Concept</h4>
                                    <div class="bg-gray-800 p-3 rounded border-l-4 border-yellow-500">
                                        <code class="text-yellow-300 text-sm">${
                                          vuln.evidence ||
                                          vuln.payload ||
                                          "No specific evidence provided. Manual verification recommended."
                                        }</code>
                                    </div>
                                </div>

                                <!-- Impact -->
                                <div class="mb-4">
                                    <h4 class="font-semibold text-white mb-2">⚠️ Impact</h4>
                                    <div class="bg-red-900 bg-opacity-30 border border-red-700 p-3 rounded">
                                        <p class="text-red-200 leading-relaxed">${getVulnerabilityImpact(
                                          vuln.severity,
                                          vuln.title
                                        )}</p>
                                    </div>
                                </div>

                                <!-- Remediation -->
                                <div class="mb-4">
                                    <h4 class="font-semibold text-white mb-2">🛠️ Remediation</h4>
                                    <div class="bg-green-900 bg-opacity-30 border border-green-700 p-3 rounded">
                                        <p class="text-green-200 leading-relaxed">${
                                          vuln.remediation ||
                                          getDefaultRemediation(
                                            vuln.title,
                                            vuln.severity
                                          )
                                        }</p>
                                    </div>
                                </div>

                                <!-- References -->
                                <div>
                                    <h4 class="font-semibold text-white mb-2">📚 References</h4>
                                    <div class="bg-blue-900 bg-opacity-30 border border-blue-700 p-3 rounded">
                                        <pre class="text-blue-200 text-sm whitespace-pre-wrap">${getVulnerabilityReferences(
                                          vuln.title
                                        )}</pre>
                                    </div>
                                </div>
                            </div>
                        `
                          )
                          .join("")}
                    </div>
                `
                    : `
                    <div class="text-center py-12">
                        <div class="text-6xl mb-4">✅</div>
                        <h3 class="text-xl font-semibold text-green-400 mb-2">No Vulnerabilities Found</h3>
                        <p class="text-gray-400">This scan did not identify any security vulnerabilities.</p>
                    </div>
                `
                }
            </div>

            <!-- General Recommendations -->
            <div class="bg-gray-800 border border-gray-700 rounded-xl p-6">
                <div class="flex items-center gap-3 mb-6">
                    <span class="text-2xl">💡</span>
                    <h2 class="text-xl font-bold text-white">General Recommendations</h2>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="space-y-3">
                        <div class="flex items-start gap-3">
                            <span class="text-green-400 mt-1">✓</span>
                            <span class="text-gray-300">Use secure coding best practices</span>
                        </div>
                        <div class="flex items-start gap-3">
                            <span class="text-green-400 mt-1">✓</span>
                            <span class="text-gray-300">Implement proper input validation and output encoding</span>
                        </div>
                        <div class="flex items-start gap-3">
                            <span class="text-green-400 mt-1">✓</span>
                            <span class="text-gray-300">Enforce security headers (CSP, HSTS, etc.)</span>
                        </div>
                        <div class="flex items-start gap-3">
                            <span class="text-green-400 mt-1">✓</span>
                            <span class="text-gray-300">Conduct regular security audits</span>
                        </div>
                    </div>
                    <div class="space-y-3">
                        <div class="flex items-start gap-3">
                            <span class="text-green-400 mt-1">✓</span>
                            <span class="text-gray-300">Keep systems and dependencies updated</span>
                        </div>
                        <div class="flex items-start gap-3">
                            <span class="text-green-400 mt-1">✓</span>
                            <span class="text-gray-300">Implement Web Application Firewall (WAF)</span>
                        </div>
                        <div class="flex items-start gap-3">
                            <span class="text-green-400 mt-1">✓</span>
                            <span class="text-gray-300">Use HTTPS for all communications</span>
                        </div>
                        <div class="flex items-start gap-3">
                            <span class="text-green-400 mt-1">✓</span>
                            <span class="text-gray-300">Regular security training for teams</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Appendix -->
            <div class="bg-gray-800 border border-gray-700 rounded-xl p-6">
                <div class="flex items-center gap-3 mb-6">
                    <span class="text-2xl">📋</span>
                    <h2 class="text-xl font-bold text-white">Appendix</h2>
                </div>

                <div class="space-y-3">
                    <div class="flex justify-between">
                        <span class="text-gray-400">Scan Configuration:</span>
                        <span class="font-medium">${
                          scan.scanType || "Unknown"
                        } scan performed on ${scanDate}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Tools Used:</span>
                        <span class="font-medium">${
                          agentsUsed.join(", ") || "AI Bug Bounty Scanner"
                        }</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Contact Information:</span>
                        <span class="font-medium">Security Team</span>
                    </div>
                </div>

                <div class="mt-6 pt-4 border-t border-gray-700 text-center">
                    <p class="text-gray-400 text-sm italic">
                        This report was automatically generated by the AI Bug Bounty Scanner.<br>
                        Please review all findings and perform manual verification where necessary.
                    </p>
                </div>
            </div>
        </div>
    `;
}

// Helper function to generate vulnerability impact based on severity and type
function getVulnerabilityImpact(severity, title) {
  const titleLower = title.toLowerCase();

  if (titleLower.includes("sql injection")) {
    return "SQL injection vulnerabilities can allow attackers to manipulate database queries, potentially leading to unauthorized data access, data modification, or complete database compromise. In severe cases, attackers may gain administrative access to the database server.";
  } else if (
    titleLower.includes("xss") ||
    titleLower.includes("cross-site scripting")
  ) {
    return "Cross-Site Scripting (XSS) vulnerabilities can allow attackers to inject malicious scripts into web pages viewed by other users. This can lead to session hijacking, credential theft, defacement, or redirection to malicious sites.";
  } else if (
    titleLower.includes("csrf") ||
    titleLower.includes("cross-site request forgery")
  ) {
    return "CSRF vulnerabilities can allow attackers to trick authenticated users into performing unintended actions on the web application, potentially leading to unauthorized transactions, data modification, or account compromise.";
  } else if (
    titleLower.includes("authentication") ||
    titleLower.includes("authorization")
  ) {
    return "Authentication and authorization flaws can allow attackers to bypass security controls, gain unauthorized access to restricted areas, or escalate privileges within the application.";
  } else if (
    titleLower.includes("file upload") ||
    titleLower.includes("upload")
  ) {
    return "File upload vulnerabilities can allow attackers to upload malicious files to the server, potentially leading to remote code execution, server compromise, or serving malware to other users.";
  } else if (
    titleLower.includes("directory traversal") ||
    titleLower.includes("path traversal")
  ) {
    return "Directory traversal vulnerabilities can allow attackers to access files and directories outside the intended scope, potentially exposing sensitive configuration files, source code, or system files.";
  } else {
    // Generic impact based on severity
    switch (severity) {
      case "Critical":
        return "This critical vulnerability poses an immediate and severe risk to the application and its users. Exploitation could result in complete system compromise, massive data breach, or significant business disruption.";
      case "High":
        return "This high-severity vulnerability poses a significant risk and should be addressed promptly. Exploitation could lead to unauthorized access, data theft, or substantial impact on application functionality.";
      case "Medium":
        return "This medium-severity vulnerability represents a moderate risk that should be addressed in a timely manner. While not immediately critical, it could be exploited in combination with other vulnerabilities.";
      case "Low":
        return "This low-severity vulnerability represents a minor risk but should still be addressed to maintain overall security posture. It may provide limited information to attackers or have minimal direct impact.";
      default:
        return "The impact of this vulnerability should be assessed based on the specific context of your application and environment.";
    }
  }
}

// Helper function to generate default remediation advice
function getDefaultRemediation(title, severity) {
  const titleLower = title.toLowerCase();

  if (titleLower.includes("sql injection")) {
    return "Use parameterized queries or prepared statements for all database interactions. Implement proper input validation and sanitization. Use stored procedures where appropriate. Apply the principle of least privilege for database accounts.";
  } else if (
    titleLower.includes("xss") ||
    titleLower.includes("cross-site scripting")
  ) {
    return "Implement proper output encoding/escaping for all user-controlled data. Use Content Security Policy (CSP) headers. Validate and sanitize all input data. Consider using auto-escaping template engines.";
  } else if (
    titleLower.includes("csrf") ||
    titleLower.includes("cross-site request forgery")
  ) {
    return "Implement anti-CSRF tokens for all state-changing operations. Use SameSite cookie attributes. Verify the Origin and Referer headers. Implement proper session management.";
  } else if (titleLower.includes("authentication")) {
    return "Implement strong authentication mechanisms. Use multi-factor authentication where possible. Ensure proper session management. Implement account lockout policies and rate limiting.";
  } else if (titleLower.includes("authorization")) {
    return "Implement proper access controls and authorization checks. Use role-based access control (RBAC). Apply the principle of least privilege. Regularly review and audit user permissions.";
  } else if (titleLower.includes("file upload")) {
    return "Implement strict file type validation. Use file content scanning. Store uploaded files outside the web root. Implement file size limits. Use virus scanning for uploaded files.";
  } else if (
    titleLower.includes("directory traversal") ||
    titleLower.includes("path traversal")
  ) {
    return "Implement proper input validation for file paths. Use whitelist-based validation. Avoid user-controlled file path construction. Use secure file access APIs that prevent directory traversal.";
  } else {
    return "Review the specific vulnerability details and implement appropriate security controls. Follow secure coding best practices and conduct regular security testing.";
  }
}

// Helper function to generate relevant references
function getVulnerabilityReferences(title) {
  const titleLower = title.toLowerCase();

  if (titleLower.includes("sql injection")) {
    return "- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection\n- CWE-89: https://cwe.mitre.org/data/definitions/89.html\n- OWASP SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html";
  } else if (
    titleLower.includes("xss") ||
    titleLower.includes("cross-site scripting")
  ) {
    return "- OWASP XSS: https://owasp.org/www-community/attacks/xss/\n- CWE-79: https://cwe.mitre.org/data/definitions/79.html\n- OWASP XSS Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html";
  } else if (
    titleLower.includes("csrf") ||
    titleLower.includes("cross-site request forgery")
  ) {
    return "- OWASP CSRF: https://owasp.org/www-community/attacks/csrf\n- CWE-352: https://cwe.mitre.org/data/definitions/352.html\n- OWASP CSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html";
  } else if (titleLower.includes("authentication")) {
    return "- OWASP Authentication: https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication\n- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html";
  } else if (titleLower.includes("authorization")) {
    return "- OWASP Access Control: https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control\n- OWASP Authorization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html";
  } else if (titleLower.includes("file upload")) {
    return "- OWASP File Upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload\n- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html";
  } else if (
    titleLower.includes("directory traversal") ||
    titleLower.includes("path traversal")
  ) {
    return "- OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal\n- CWE-22: https://cwe.mitre.org/data/definitions/22.html";
  } else {
    return "- OWASP Top 10: https://owasp.org/www-project-top-ten/\n- CWE/SANS Top 25: https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html\n- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/";
  }
}

// Download text report
async function downloadTextReport(reportId) {
  try {
    const reportData = await apiRequest(`/reports/${reportId}`);
    const textContent = generateTextReport(reportData);

    const blob = new Blob([textContent], { type: "text/plain" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${reportData.title
      .replace(/[^a-z0-9]/gi, "_")
      .toLowerCase()}_report.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);

    const notification = createNotification(
      "Text report downloaded",
      "success"
    );
    document.body.appendChild(notification);
  } catch (error) {
    console.error("Failed to download text report:", error);
    const notification = createNotification(
      "Failed to download report",
      "error"
    );
    document.body.appendChild(notification);
  }
}

// Generate pure markdown content (without HTML wrapper)
function generateMarkdownReport(reportData) {
  const vulnerabilities = reportData.vulnerabilities || [];
  const scan = reportData.scan || {};

  // Calculate severity counts
  const criticalCount = vulnerabilities.filter(
    (v) => v.severity === "Critical"
  ).length;
  const highCount = vulnerabilities.filter((v) => v.severity === "High").length;
  const mediumCount = vulnerabilities.filter(
    (v) => v.severity === "Medium"
  ).length;
  const lowCount = vulnerabilities.filter((v) => v.severity === "Low").length;

  // Get unique agents used
  const agentsUsed = [
    ...new Set(vulnerabilities.map((v) => v.discoveredBy)),
  ].filter(Boolean);
  const primaryAgent = agentsUsed[0] || "AI Bug Bounty Scanner";

  // Format scan date
  const scanDate = scan.started
    ? new Date(scan.started).toLocaleDateString()
    : new Date().toLocaleDateString();
  const reportDate = new Date().toLocaleDateString();

  return `# Vulnerability Report

## 1. Summary

- **Target:** ${scan.target || "Unknown Target"}
- **Scan Date:** ${scanDate}
- **Report Generated By:** ${primaryAgent}
- **Total Vulnerabilities Found:** ${vulnerabilities.length}
- **Severity Breakdown:** Critical: ${criticalCount}, High: ${highCount}, Medium: ${mediumCount}, Low: ${lowCount}

## 2. Vulnerability Details

${
  vulnerabilities.length > 0
    ? vulnerabilities
        .map(
          (vuln, index) => `
### [${index + 1}] ${vuln.title}

- **Severity:** ${vuln.severity}
- **CVSS Score:** ${vuln.cvss || "N/A"}
- **Affected URL:** ${vuln.url}
- **Parameter/Affected Element:** ${vuln.parameter || "N/A"}
- **Discovered By:** ${vuln.discoveredBy}
- **Discovery Time:** ${
            vuln.timestamp ? new Date(vuln.timestamp).toLocaleString() : "N/A"
          }

**Description:**
${vuln.description}

**Evidence / Proof of Concept:**
${
  vuln.evidence ||
  vuln.payload ||
  "No specific evidence provided. Manual verification recommended."
}

**Impact:**
${getVulnerabilityImpact(vuln.severity, vuln.title)}

**Remediation:**
${vuln.remediation || getDefaultRemediation(vuln.title, vuln.severity)}

**References:**
${getVulnerabilityReferences(vuln.title)}

---`
        )
        .join("\n")
    : "No vulnerabilities were found during this scan."
}

## 3. General Recommendations

- Use secure coding best practices
- Implement proper input validation and output encoding
- Enforce security headers like Content-Security-Policy, Strict-Transport-Security, etc.
- Conduct regular security audits and penetration tests
- Keep systems and dependencies up to date
- Implement Web Application Firewall (WAF) protection
- Use HTTPS for all communications
- Regular security training for development teams

---

## 4. Appendix

- **Scan Configuration:** ${
    scan.scanType || "Unknown"
  } scan performed on ${scanDate}
- **Tools Used:** ${agentsUsed.join(", ") || "AI Bug Bounty Scanner"}
- **Contact Information:** For further questions or clarifications, reach out to your security team
- **Report Generated:** ${reportDate}

---

*This report was automatically generated by the AI Bug Bounty Scanner. Please review all findings and perform manual verification where necessary.*`;
}

// Generate text report (plain text format)
function generateTextReport(reportData) {
  const vulnerabilities = reportData.vulnerabilities || [];
  const scan = reportData.scan || {};

  // Calculate severity counts
  const criticalCount = vulnerabilities.filter(
    (v) => v.severity === "Critical"
  ).length;
  const highCount = vulnerabilities.filter((v) => v.severity === "High").length;
  const mediumCount = vulnerabilities.filter(
    (v) => v.severity === "Medium"
  ).length;
  const lowCount = vulnerabilities.filter((v) => v.severity === "Low").length;

  // Get unique agents used
  const agentsUsed = [
    ...new Set(vulnerabilities.map((v) => v.discoveredBy)),
  ].filter(Boolean);
  const primaryAgent = agentsUsed[0] || "AI Bug Bounty Scanner";

  // Format scan date
  const scanDate = scan.started
    ? new Date(scan.started).toLocaleDateString()
    : new Date().toLocaleDateString();
  const reportDate = new Date().toLocaleDateString();

  return `VULNERABILITY REPORT
${"=".repeat(50)}

1. SUMMARY
${"=".repeat(10)}

Target: ${scan.target || "Unknown Target"}
Scan Date: ${scanDate}
Report Generated By: ${primaryAgent}
Total Vulnerabilities Found: ${vulnerabilities.length}
Severity Breakdown: Critical: ${criticalCount}, High: ${highCount}, Medium: ${mediumCount}, Low: ${lowCount}

2. VULNERABILITY DETAILS
${"=".repeat(25)}

${
  vulnerabilities.length > 0
    ? vulnerabilities
        .map(
          (vuln, index) => `
[${index + 1}] ${vuln.title}
${"-".repeat(vuln.title.length + 4)}

Severity: ${vuln.severity}
CVSS Score: ${vuln.cvss || "N/A"}
Affected URL: ${vuln.url}
Parameter/Affected Element: ${vuln.parameter || "N/A"}
Discovered By: ${vuln.discoveredBy}
Discovery Time: ${
            vuln.timestamp ? new Date(vuln.timestamp).toLocaleString() : "N/A"
          }

Description:
${vuln.description}

Evidence / Proof of Concept:
${
  vuln.evidence ||
  vuln.payload ||
  "No specific evidence provided. Manual verification recommended."
}

Impact:
${getVulnerabilityImpact(vuln.severity, vuln.title)}

Remediation:
${vuln.remediation || getDefaultRemediation(vuln.title, vuln.severity)}

References:
${getVulnerabilityReferences(vuln.title)}

${"=".repeat(80)}`
        )
        .join("\n")
    : "No vulnerabilities were found during this scan."
}

3. GENERAL RECOMMENDATIONS
${"=".repeat(27)}

- Use secure coding best practices
- Implement proper input validation and output encoding
- Enforce security headers like Content-Security-Policy, Strict-Transport-Security, etc.
- Conduct regular security audits and penetration tests
- Keep systems and dependencies up to date
- Implement Web Application Firewall (WAF) protection
- Use HTTPS for all communications
- Regular security training for development teams

${"=".repeat(80)}

4. APPENDIX
${"=".repeat(11)}

Scan Configuration: ${scan.scanType || "Unknown"} scan performed on ${scanDate}
Tools Used: ${agentsUsed.join(", ") || "AI Bug Bounty Scanner"}
Contact Information: For further questions or clarifications, reach out to your security team
Report Generated: ${reportDate}

${"=".repeat(80)}

This report was automatically generated by the AI Bug Bounty Scanner.
Please review all findings and perform manual verification where necessary.`;
}

// Show JSON report
function showJsonReport(reportData) {
  const modalContent = `
        <div class="bg-dark-lighter rounded-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <div class="flex justify-between items-center p-6 border-b border-gray-700">
                <h2 class="text-xl font-bold text-white">${
                  reportData.title
                } (JSON)</h2>
                <button class="text-gray-400 hover:text-white text-2xl" onclick="closeModal()">&times;</button>
            </div>
            <div class="p-6">
                <pre class="bg-gray-900 p-4 rounded-lg text-green-400 text-sm overflow-x-auto"><code>${JSON.stringify(
                  reportData,
                  null,
                  2
                )}</code></pre>
            </div>
        </div>
    `;
  showModal(modalContent);
}

// Download report file (for PDF)
function downloadReportFile(reportData) {
  if (reportData.content) {
    const blob = new Blob([reportData.content], { type: "application/pdf" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${reportData.title}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  } else {
    showReportSummary(reportData);
  }
}

// Show report summary (fallback)
function showReportSummary(reportData) {
  const modalContent = `
        <div class="bg-dark-lighter rounded-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div class="flex justify-between items-center p-6 border-b border-gray-700">
                <h2 class="text-xl font-bold text-white">Report Summary</h2>
                <button class="text-gray-400 hover:text-white text-2xl" onclick="closeModal()">&times;</button>
            </div>
            <div class="p-6 space-y-4 text-white">
                <div class="bg-gray-800 p-4 rounded-lg">
                    <h3 class="font-semibold mb-2">${reportData.title}</h3>
                    <div class="space-y-2 text-sm">
                        <p><span class="text-gray-400">Generated:</span> ${new Date(
                          reportData.generated
                        ).toLocaleString()}</p>
                        <p><span class="text-gray-400">Format:</span> ${
                          reportData.format
                        }</p>
                        <p><span class="text-gray-400">Target:</span> ${
                          reportData.target
                        }</p>
                        <p><span class="text-gray-400">Vulnerabilities:</span> ${
                          reportData.vulnerabilities
                        }</p>
                        <p><span class="text-gray-400">Severity:</span> <span class="px-2 py-1 rounded text-xs ${getSeverityClasses(
                          reportData.severity
                        )}">${reportData.severity}</span></p>
                    </div>
                </div>
                <div class="text-center">
                    <p class="text-gray-400">Report content not available for preview.</p>
                </div>
            </div>
        </div>
    `;
  showModal(modalContent);
}

// Real-time updates with API polling
function startRealTimeUpdates() {
  setInterval(async () => {
    try {
      // Poll for updates from the API
      await loadStats();
      await loadScans();

      // Only reload vulnerabilities if there are running scans
      const runningScans = appData.scans.filter(
        (scan) => scan.status === "running"
      );
      if (runningScans.length > 0) {
        await loadVulnerabilities();
      }

      // Update activity feed with real data
      await renderActivityFeed();

      // Update vulnerability trends chart
      await updateVulnerabilityChart();
    } catch (error) {
      console.error("Failed to update real-time data:", error);
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
    case "critical":
      return "#FF5459";
    case "high":
      return "#E68161";
    case "medium":
      return "#32808D";
    case "low":
      return "#626C71";
    default:
      return "#626C71";
  }
}

// Scan Progress Modal Functions
let currentScanId = null;
let scanStartTime = null;
let scanTimer = null;
let isModalMinimized = false;

function showScanProgressModal(scan) {
  const modal = document.getElementById("scan-progress-modal");
  const targetDisplay = document.getElementById("scan-target-display");
  const scanTypeDisplay = document.getElementById("scan-type-display");
  const scanAgentsDisplay = document.getElementById("scan-agents-display");
  const minimizedIndicator = document.getElementById(
    "minimized-scan-indicator"
  );

  // Store current scan info
  currentScanId = scan.id;
  scanStartTime = new Date();
  isModalMinimized = false;

  // Set initial values
  targetDisplay.textContent = scan.target;
  scanTypeDisplay.textContent = scan.scanType;
  scanAgentsDisplay.textContent = scan.agents.join(", ");

  // Hide minimized indicator
  minimizedIndicator.classList.add("hidden");

  // Show modal
  modal.classList.remove("hidden");

  // Start timer
  startScanTimer();

  // Initialize modal controls
  initializeScanModalControls();

  // Update with current scan data
  updateScanProgressModal(scan);
}

function updateScanProgressModal(scan) {
  const progressFill = document.getElementById("progress-fill");
  const progressPercentage = document.getElementById("progress-percentage");
  const currentTest = document.getElementById("current-test");
  const minimizedProgress = document.getElementById("minimized-progress");

  // Update progress bar with proper percentage
  // Force 100% if scan is completed, even if progress value is not exactly 100
  let progress = scan.progress || 0;
  if (scan.status === "completed") {
    progress = 100;
  } else if (scan.status === "failed") {
    progress = 0;
  }

  progress = Math.min(Math.max(progress, 0), 100);

  // Smooth progress bar animation
  progressFill.style.width = `${progress}%`;
  progressPercentage.textContent = `${progress}%`;

  // Update minimized indicator if visible
  if (minimizedProgress) {
    minimizedProgress.textContent = `${progress}%`;
  }

  // Update current test with proper formatting
  if (scan.current_test) {
    const showSpinner = scan.status === "running" && progress < 100;
    currentTest.innerHTML = `
            <div class="flex items-center gap-2">
                ${
                  showSpinner
                    ? '<div class="animate-spin w-4 h-4 border-2 border-primary border-t-transparent rounded-full"></div>'
                    : ""
                }
                <span>${scan.current_test}</span>
            </div>
        `;
  } else {
    // Default messages based on status
    let message = "";
    let showSpinner = false;

    switch (scan.status) {
      case "pending":
        message = "⏳ Preparing scan environment...";
        showSpinner = true;
        break;
      case "running":
        message = "🔍 Security scan in progress...";
        showSpinner = true;
        break;
      case "completed":
        message = "✅ Scan completed successfully!";
        showSpinner = false;
        break;
      case "failed":
        message = "❌ Scan failed. Please try again.";
        showSpinner = false;
        break;
      default:
        message = "Initializing scan...";
        showSpinner = true;
    }

    currentTest.innerHTML = `
            <div class="flex items-center gap-2">
                ${
                  showSpinner
                    ? '<div class="animate-spin w-4 h-4 border-2 border-primary border-t-transparent rounded-full"></div>'
                    : ""
                }
                <span>${message}</span>
            </div>
        `;
  }

  // Auto-hide modal when scan completes (if not minimized)
  if (
    (scan.status === "completed" || scan.status === "failed") &&
    !isModalMinimized
  ) {
    console.log(`🔔 Scan ${scan.status}! Auto-hiding modal in 5 seconds...`);
    setTimeout(() => {
      stopScanTimer();
      hideScanProgressModal();
      console.log(`🔔 Modal auto-hidden for scan ID: ${scan.id}`);
    }, 5000); // Give user time to see completion
  }
}

function minimizeScanProgressModal() {
  const modal = document.getElementById("scan-progress-modal");
  const minimizedIndicator = document.getElementById(
    "minimized-scan-indicator"
  );

  isModalMinimized = true;
  modal.classList.add("hidden");
  minimizedIndicator.classList.remove("hidden");
}

function maximizeScanProgressModal() {
  const modal = document.getElementById("scan-progress-modal");
  const minimizedIndicator = document.getElementById(
    "minimized-scan-indicator"
  );

  isModalMinimized = false;
  minimizedIndicator.classList.add("hidden");
  modal.classList.remove("hidden");
}

function hideScanProgressModal() {
  const modal = document.getElementById("scan-progress-modal");
  const minimizedIndicator = document.getElementById(
    "minimized-scan-indicator"
  );

  modal.classList.add("hidden");
  minimizedIndicator.classList.add("hidden");
  stopScanTimer();
  isModalMinimized = false;
  currentScanId = null;
}

function quitScan() {
  if (!currentScanId) return;

  // Show confirmation dialog
  if (
    confirm(
      "Are you sure you want to stop the current scan? This will terminate the scanning process."
    )
  ) {
    // Store the scan ID for reference
    const scanIdToStop = currentScanId;

    // Immediately hide the modal and reset state to improve UX
    hideScanProgressModal();
    showNotification("Stopping scan...", "info");

    // Call API to stop the scan
    apiRequest(`/scans/${scanIdToStop}`, {
      method: "PUT",
      body: JSON.stringify({
        status: "failed",
        progress: 0,
      }),
    })
      .then(() => {
        showNotification("Scan stopped successfully", "success");
        loadScans(); // Refresh scan list

        // Update local scan data immediately
        const scanIndex = appData.scans.findIndex((s) => s.id === scanIdToStop);
        if (scanIndex !== -1) {
          appData.scans[scanIndex].status = "failed";
          appData.scans[scanIndex].progress = 0;
        }
      })
      .catch((error) => {
        console.error("Failed to stop scan:", error);
        showNotification("Failed to stop scan", "error");

        // If stopping failed, show the modal again
        if (currentScanId === scanIdToStop) {
          const scan = appData.scans.find((s) => s.id === scanIdToStop);
          if (scan) {
            showScanProgressModal(scan);
          }
        }
      });
  }
}

function startScanTimer() {
  if (scanTimer) clearInterval(scanTimer);

  scanTimer = setInterval(() => {
    if (scanStartTime) {
      const elapsed = new Date() - scanStartTime;
      const minutes = Math.floor(elapsed / 60000);
      const seconds = Math.floor((elapsed % 60000) / 1000);
      const timeString = `${minutes.toString().padStart(2, "0")}:${seconds
        .toString()
        .padStart(2, "0")}`;

      const timeDisplay = document.getElementById("scan-elapsed-time");
      if (timeDisplay) {
        timeDisplay.textContent = timeString;
      }

      // Periodic sync check - query backend for latest scan status every 10 seconds
      if (currentScanId && elapsed % 10000 < 1000) {
        // Every 10 seconds (with 1 second tolerance)
        syncScanProgress();
      }
    }
  }, 1000);
}

function stopScanTimer() {
  if (scanTimer) {
    clearInterval(scanTimer);
    scanTimer = null;
  }
}

// Sync scan progress with backend (fallback if Socket.IO updates are missed)
async function syncScanProgress() {
  if (!currentScanId) return;

  try {
    const scan = await apiRequest(`/scans/${currentScanId}`);
    if (scan) {
      console.log(
        `🔄 Syncing scan progress: ${scan.progress}%, status: ${scan.status}`
      );

      // Update modal if open
      const modal = document.getElementById("scan-progress-modal");
      if (modal && !modal.classList.contains("hidden")) {
        updateScanProgressModal(scan);
      }

      // Update minimized indicator if visible
      const minimizedIndicator = document.getElementById(
        "minimized-scan-indicator"
      );
      if (
        minimizedIndicator &&
        !minimizedIndicator.classList.contains("hidden")
      ) {
        const minimizedProgress = document.getElementById("minimized-progress");
        if (minimizedProgress) {
          minimizedProgress.textContent = `${scan.progress || 0}%`;
        }
      }

      // Auto-cleanup if scan is completed
      if (scan.status === "completed" || scan.status === "failed") {
        if (!isModalMinimized) {
          setTimeout(() => {
            hideScanProgressModal();
          }, 3000);
        }
      }
    }
  } catch (error) {
    console.warn("Failed to sync scan progress:", error);
  }
}

function initializeScanModalControls() {
  // Minimize button
  const minimizeBtn = document.getElementById("minimize-scan-btn");
  if (minimizeBtn) {
    minimizeBtn.onclick = minimizeScanProgressModal;
  }

  // Quit button
  const quitBtn = document.getElementById("quit-scan-btn");
  if (quitBtn) {
    quitBtn.onclick = quitScan;
  }

  // Minimized indicator click to maximize
  const minimizedIndicator = document.getElementById(
    "minimized-scan-indicator"
  );
  if (minimizedIndicator) {
    minimizedIndicator.onclick = maximizeScanProgressModal;
  }
}

// Enhanced Reporting Functions

async function checkReportingCapabilities() {
  try {
    const response = await fetch("/api/reports/capabilities");
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    displayReportingCapabilities(data.capabilities);

    // Show the capabilities section
    document
      .getElementById("reporting-capabilities")
      .classList.remove("hidden");
  } catch (error) {
    console.error("Failed to check reporting capabilities:", error);
    showNotification(
      "Failed to check reporting capabilities: " + error.message,
      "error"
    );
  }
}

function displayReportingCapabilities(capabilities) {
  for (const [capability, available] of Object.entries(capabilities)) {
    const statusElement = document.getElementById(
      `${capability.replace(/_/g, "-")}-status`
    );
    if (statusElement) {
      statusElement.className = `w-3 h-3 rounded-full ${
        available ? "bg-green-500" : "bg-red-500"
      }`;
    }
  }
}

async function loadScansForReporting() {
  try {
    const response = await fetch("/api/scans");
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const scans = await response.json();
    const scanSelect = document.getElementById("scan-select");

    // Clear existing options except the first one
    scanSelect.innerHTML = '<option value="">Choose a scan...</option>';

    scans.forEach((scan) => {
      const option = document.createElement("option");
      option.value = scan.id;
      option.textContent = `${scan.target} - ${scan.scanType} (${scan.vulnerabilities} vulnerabilities)`;
      scanSelect.appendChild(option);
    });
  } catch (error) {
    console.error("Failed to load scans:", error);
    showNotification("Failed to load scans: " + error.message, "error");
  }
}

// Report type change handler
document.addEventListener("DOMContentLoaded", function () {
  const reportTypeSelect = document.getElementById("report-type-select");
  const complianceSection = document.getElementById(
    "compliance-framework-section"
  );

  if (reportTypeSelect) {
    reportTypeSelect.addEventListener("change", function () {
      if (this.value === "compliance") {
        complianceSection.classList.remove("hidden");
      } else {
        complianceSection.classList.add("hidden");
      }
    });
  }

  // Load scans when reports view is accessed
  const reportsNavItem = document.querySelector('[data-view="reports-view"]');
  if (reportsNavItem) {
    reportsNavItem.addEventListener("click", loadScansForReporting);
  }
});

async function generateEnhancedReport() {
  const scanId = document.getElementById("scan-select").value;
  const reportType = document.getElementById("report-type-select").value;
  const complianceFramework = document.getElementById(
    "compliance-framework"
  ).value;

  if (!scanId) {
    showNotification("Please select a scan first", "warning");
    return;
  }

  try {
    let endpoint;

    if (reportType === "executive") {
      endpoint = `/api/reports/enhanced/dashboard/${scanId}`;
    } else if (reportType === "technical") {
      endpoint = `/api/reports/enhanced/technical/${scanId}`;
    } else if (reportType === "compliance") {
      endpoint = `/api/reports/enhanced/compliance/${scanId}/${complianceFramework}`;
    }

    showNotification("Generating enhanced report...", "info");

    const response = await fetch(endpoint);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const reportData = await response.json();
    displayEnhancedReport(reportData, reportType);

    showNotification("Enhanced report generated successfully!", "success");
  } catch (error) {
    console.error("Failed to generate enhanced report:", error);
    showNotification("Failed to generate report: " + error.message, "error");
  }
}

function displayEnhancedReport(reportData, reportType) {
  const reportDisplay = document.getElementById("enhanced-report-display");
  const reportContent = document.getElementById("enhanced-report-content");

  // Clear previous content
  reportContent.innerHTML = "";

  if (reportType === "executive") {
    displayExecutiveDashboard(reportData, reportContent);
  } else if (reportType === "technical") {
    displayTechnicalReport(reportData, reportContent);
  } else if (reportType === "compliance") {
    displayComplianceReport(reportData, reportContent);
  }

  // Show the report display
  reportDisplay.classList.remove("hidden");
  reportDisplay.scrollIntoView({ behavior: "smooth" });
}

function displayExecutiveDashboard(data, container) {
  const summary = data.executive_summary || data.basic_summary || {};

  container.innerHTML = `
        <div class="space-y-6">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div class="bg-red-900 bg-opacity-20 border border-red-700 rounded-lg p-4">
                    <h5 class="text-red-400 font-semibold">Critical Issues</h5>
                    <p class="text-2xl font-bold text-white">${
                      summary.critical_count || 0
                    }</p>
                </div>
                <div class="bg-yellow-900 bg-opacity-20 border border-yellow-700 rounded-lg p-4">
                    <h5 class="text-yellow-400 font-semibold">High Priority</h5>
                    <p class="text-2xl font-bold text-white">${
                      summary.high_count || 0
                    }</p>
                </div>
                <div class="bg-blue-900 bg-opacity-20 border border-blue-700 rounded-lg p-4">
                    <h5 class="text-blue-400 font-semibold">Total Findings</h5>
                    <p class="text-2xl font-bold text-white">${
                      summary.total_vulnerabilities || 0
                    }</p>
                </div>
            </div>
            
            <div class="bg-gray-900 rounded-lg p-4">
                <h5 class="text-white font-semibold mb-3">Risk Assessment</h5>
                <div class="space-y-2">
                    <div class="flex justify-between">
                        <span>Overall Risk Level:</span>
                        <span class="text-${getRiskColor(
                          summary.risk_level
                        )}-400 font-semibold">${
    summary.risk_level || "Unknown"
  }</span>
                    </div>
                    <div class="flex justify-between">
                        <span>Security Score:</span>
                        <span class="text-blue-400 font-semibold">${
                          summary.security_score || "N/A"
                        }/100</span>
                    </div>
                </div>
            </div>
            
            ${
              summary.key_findings
                ? `
            <div class="bg-gray-900 rounded-lg p-4">
                <h5 class="text-white font-semibold mb-3">Key Findings</h5>
                <ul class="space-y-1">
                    ${summary.key_findings
                      .slice(0, 5)
                      .map(
                        (finding) => `
                        <li class="text-gray-300">• ${finding}</li>
                    `
                      )
                      .join("")}
                </ul>
            </div>
            `
                : ""
            }
        </div>
    `;
}

function displayTechnicalReport(data, container) {
  const report = data.report || data.basic_findings || {};
  const findings = report.detailed_findings || [];

  container.innerHTML = `
        <div class="space-y-6">
            <div class="bg-gray-900 rounded-lg p-4">
                <h5 class="text-white font-semibold mb-3">Vulnerability Summary</h5>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div class="text-center">
                        <p class="text-red-400 text-xl font-bold">${
                          findings.filter((v) => v.severity === "Critical")
                            .length
                        }</p>
                        <p class="text-sm text-gray-400">Critical</p>
                    </div>
                    <div class="text-center">
                        <p class="text-orange-400 text-xl font-bold">${
                          findings.filter((v) => v.severity === "High").length
                        }</p>
                        <p class="text-sm text-gray-400">High</p>
                    </div>
                    <div class="text-center">
                        <p class="text-yellow-400 text-xl font-bold">${
                          findings.filter((v) => v.severity === "Medium").length
                        }</p>
                        <p class="text-sm text-gray-400">Medium</p>
                    </div>
                    <div class="text-center">
                        <p class="text-green-400 text-xl font-bold">${
                          findings.filter((v) => v.severity === "Low").length
                        }</p>
                        <p class="text-sm text-gray-400">Low</p>
                    </div>
                </div>
            </div>
            
            <div class="bg-gray-900 rounded-lg p-4">
                <h5 class="text-white font-semibold mb-3">Top Vulnerabilities</h5>
                <div class="space-y-3">
                    ${findings
                      .slice(0, 10)
                      .map(
                        (vuln) => `
                        <div class="border border-gray-700 rounded-lg p-3">
                            <div class="flex justify-between items-start mb-2">
                                <h6 class="text-white font-medium">${
                                  vuln.title || "Unknown"
                                }</h6>
                                <span class="px-2 py-1 text-xs rounded ${getSeverityBadgeClass(
                                  vuln.severity
                                )}">${vuln.severity}</span>
                            </div>
                            <p class="text-gray-400 text-sm">${
                              vuln.description
                                ? vuln.description.substring(0, 150) + "..."
                                : "No description available"
                            }</p>
                            <p class="text-gray-500 text-xs mt-2">Discovered by: ${
                              vuln.discovered_by || "Unknown"
                            }</p>
                        </div>
                    `
                      )
                      .join("")}
                </div>
            </div>
        </div>
    `;
}

function displayComplianceReport(data, container) {
  const compliance = data.compliance_status || data.basic_compliance || {};

  container.innerHTML = `
        <div class="space-y-6">
            <div class="bg-gray-900 rounded-lg p-4">
                <h5 class="text-white font-semibold mb-3">Compliance Overview</h5>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="border border-gray-700 rounded-lg p-3">
                        <h6 class="text-white font-medium mb-2">Overall Status</h6>
                        <p class="text-${
                          compliance.overall_compliance === "Compliant"
                            ? "green"
                            : "red"
                        }-400 font-semibold">
                            ${compliance.overall_compliance || "Unknown"}
                        </p>
                    </div>
                    <div class="border border-gray-700 rounded-lg p-3">
                        <h6 class="text-white font-medium mb-2">Framework</h6>
                        <p class="text-blue-400">${
                          data.framework || "OWASP"
                        }</p>
                    </div>
                </div>
            </div>
            
            ${
              compliance.issues
                ? `
            <div class="bg-gray-900 rounded-lg p-4">
                <h5 class="text-white font-semibold mb-3">Compliance Issues</h5>
                <ul class="space-y-2">
                    ${compliance.issues
                      .slice(0, 10)
                      .map(
                        (issue) => `
                        <li class="text-gray-300">• ${issue}</li>
                    `
                      )
                      .join("")}
                </ul>
            </div>
            `
                : ""
            }
        </div>
    `;
}

function getRiskColor(riskLevel) {
  switch ((riskLevel || "").toLowerCase()) {
    case "critical":
      return "red";
    case "high":
      return "orange";
    case "medium":
      return "yellow";
    case "low":
      return "green";
    default:
      return "gray";
  }
}

function getSeverityBadgeClass(severity) {
  switch ((severity || "").toLowerCase()) {
    case "critical":
      return "bg-red-600 text-white";
    case "high":
      return "bg-orange-600 text-white";
    case "medium":
      return "bg-yellow-600 text-black";
    case "low":
      return "bg-green-600 text-white";
    default:
      return "bg-gray-600 text-white";
  }
}

async function exportReportPDF() {
  const scanId = document.getElementById("scan-select").value;
  const reportType = document.getElementById("report-type-select").value;

  if (!scanId) {
    showNotification("Please select a scan first", "warning");
    return;
  }

  try {
    showNotification("Generating PDF export...", "info");

    const response = await fetch(`/api/reports/enhanced/export/pdf/${scanId}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ report_type: reportType }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    // Download the PDF
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `security_report_${reportType}.pdf`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);

    showNotification("PDF exported successfully!", "success");
  } catch (error) {
    console.error("Failed to export PDF:", error);
    showNotification("Failed to export PDF: " + error.message, "error");
  }
}

async function exportVulnerabilitiesExcel() {
  const scanId = document.getElementById("scan-select").value;

  if (!scanId) {
    showNotification("Please select a scan first", "warning");
    return;
  }

  try {
    showNotification("Generating Excel export...", "info");

    const response = await fetch(
      `/api/reports/enhanced/export/excel/${scanId}`
    );

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    // Download the Excel file
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `vulnerabilities_report.xlsx`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);

    showNotification("Excel exported successfully!", "success");
  } catch (error) {
    console.error("Failed to export Excel:", error);
    showNotification("Failed to export Excel: " + error.message, "error");
  }
}

function closeEnhancedReport() {
  document.getElementById("enhanced-report-display").classList.add("hidden");
}

async function refreshReports() {
  await loadScansForReporting();
  showNotification("Reports refreshed", "success");
}
