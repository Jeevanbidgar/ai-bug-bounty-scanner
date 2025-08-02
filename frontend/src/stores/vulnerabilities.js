import { defineStore } from "pinia";
import { ref, computed } from "vue";
import axios from "axios";

export const useVulnerabilitiesStore = defineStore("vulnerabilities", () => {
  const vulnerabilities = ref([]);
  const loading = ref(false);
  const filters = ref({
    severity: "all",
    type: "all",
    status: "all",
    search: "",
  });

  const severityOrder = ["critical", "high", "medium", "low", "info"];

  const filteredVulnerabilities = computed(() => {
    let result = vulnerabilities.value;

    // Filter by severity
    if (filters.value.severity !== "all") {
      result = result.filter(
        (vuln) => vuln.severity === filters.value.severity
      );
    }

    // Filter by type
    if (filters.value.type !== "all") {
      result = result.filter(
        (vuln) => vuln.vulnerability_type === filters.value.type
      );
    }

    // Filter by status
    if (filters.value.status !== "all") {
      result = result.filter((vuln) => vuln.status === filters.value.status);
    }

    // Filter by search term
    if (filters.value.search) {
      const searchTerm = filters.value.search.toLowerCase();
      result = result.filter(
        (vuln) =>
          vuln.title?.toLowerCase().includes(searchTerm) ||
          vuln.description?.toLowerCase().includes(searchTerm) ||
          vuln.endpoint?.toLowerCase().includes(searchTerm)
      );
    }

    // Sort by severity (critical first)
    return result.sort((a, b) => {
      const aSeverityIndex = severityOrder.indexOf(a.severity);
      const bSeverityIndex = severityOrder.indexOf(b.severity);
      return aSeverityIndex - bSeverityIndex;
    });
  });

  const vulnerabilityStats = computed(() => {
    const stats = {
      total: vulnerabilities.value.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      open: 0,
      resolved: 0,
      false_positive: 0,
    };

    vulnerabilities.value.forEach((vuln) => {
      // Count by severity
      if (stats.hasOwnProperty(vuln.severity)) {
        stats[vuln.severity]++;
      }

      // Count by status
      if (vuln.status === "open") {
        stats.open++;
      } else if (vuln.status === "resolved") {
        stats.resolved++;
      } else if (vuln.status === "false_positive") {
        stats.false_positive++;
      }
    });

    return stats;
  });

  const uniqueTypes = computed(() => {
    const types = [
      ...new Set(vulnerabilities.value.map((v) => v.vulnerability_type)),
    ];
    return types.filter(Boolean).sort();
  });

  async function fetchVulnerabilities(scanId = null) {
    loading.value = true;
    try {
      const url = scanId
        ? `/api/scans/${scanId}/vulnerabilities`
        : "/api/vulnerabilities";
      const response = await axios.get(url);
      vulnerabilities.value = response.data;
    } catch (error) {
      console.error("Failed to fetch vulnerabilities:", error);
      throw error;
    } finally {
      loading.value = false;
    }
  }

  async function updateVulnerabilityStatus(vulnId, status) {
    try {
      const response = await axios.patch(`/api/vulnerabilities/${vulnId}`, {
        status,
      });

      // Update local state
      const vuln = vulnerabilities.value.find((v) => v.id === vulnId);
      if (vuln) {
        vuln.status = status;
        vuln.updated_at = new Date().toISOString();
      }

      return response.data;
    } catch (error) {
      console.error("Failed to update vulnerability status:", error);
      throw error;
    }
  }

  async function addNote(vulnId, note) {
    try {
      const response = await axios.post(
        `/api/vulnerabilities/${vulnId}/notes`,
        { note }
      );

      // Update local state
      const vuln = vulnerabilities.value.find((v) => v.id === vulnId);
      if (vuln) {
        if (!vuln.notes) vuln.notes = [];
        vuln.notes.push(response.data);
      }

      return response.data;
    } catch (error) {
      console.error("Failed to add note:", error);
      throw error;
    }
  }

  async function deleteVulnerability(vulnId) {
    try {
      await axios.delete(`/api/vulnerabilities/${vulnId}`);
      vulnerabilities.value = vulnerabilities.value.filter(
        (v) => v.id !== vulnId
      );
    } catch (error) {
      console.error("Failed to delete vulnerability:", error);
      throw error;
    }
  }

  async function exportVulnerabilities(format = "json", filterOptions = null) {
    try {
      const params = new URLSearchParams();
      if (filterOptions) {
        Object.entries(filterOptions).forEach(([key, value]) => {
          if (value !== "all" && value !== "") {
            params.append(key, value);
          }
        });
      }

      const response = await axios.get(
        `/api/vulnerabilities/export/${format}?${params}`,
        {
          responseType: "blob",
        }
      );

      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;

      // Determine file extension
      const extensions = {
        json: "json",
        pdf: "pdf",
        markdown: "md",
        csv: "csv",
      };
      const extension = extensions[format] || "txt";

      const timestamp = new Date().toISOString().split("T")[0];
      link.setAttribute(
        "download",
        `vulnerabilities_${timestamp}.${extension}`
      );
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);

      return true;
    } catch (error) {
      console.error("Failed to export vulnerabilities:", error);
      throw error;
    }
  }

  function setFilters(newFilters) {
    filters.value = { ...filters.value, ...newFilters };
  }

  function resetFilters() {
    filters.value = {
      severity: "all",
      type: "all",
      status: "all",
      search: "",
    };
  }

  function getSeverityColor(severity) {
    const colors = {
      critical: "text-red-600 bg-red-50",
      high: "text-orange-600 bg-orange-50",
      medium: "text-yellow-600 bg-yellow-50",
      low: "text-blue-600 bg-blue-50",
      info: "text-gray-600 bg-gray-50",
    };
    return colors[severity] || colors.info;
  }

  function getStatusColor(status) {
    const colors = {
      open: "text-red-600 bg-red-50",
      resolved: "text-green-600 bg-green-50",
      false_positive: "text-gray-600 bg-gray-50",
    };
    return colors[status] || colors.open;
  }

  return {
    vulnerabilities: computed(() => vulnerabilities.value),
    filteredVulnerabilities,
    vulnerabilityStats,
    uniqueTypes,
    loading: computed(() => loading.value),
    filters: computed(() => filters.value),
    fetchVulnerabilities,
    updateVulnerabilityStatus,
    addNote,
    deleteVulnerability,
    exportVulnerabilities,
    setFilters,
    resetFilters,
    getSeverityColor,
    getStatusColor,
  };
});
