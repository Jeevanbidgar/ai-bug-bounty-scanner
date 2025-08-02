/**
 * API Configuration with automatic adaptation to environment changes
 */
import axios from "axios";

// Environment detection
const isDevelopment = import.meta.env.MODE === "development";
const isProduction = import.meta.env.MODE === "production";

// Dynamic API configuration
class ApiConfig {
  constructor() {
    this.baseURL = this.getApiBaseUrl();
    this.setupAxios();
    this.setupInterceptors();

    // Watch for environment changes in development
    if (isDevelopment && import.meta.hot) {
      import.meta.hot.accept(() => {
        this.refreshConfig();
      });
    }
  }

  getApiBaseUrl() {
    // Priority: Environment variable > Development default > Production default
    return (
      import.meta.env.VITE_API_BASE_URL ||
      (isDevelopment ? "http://localhost:5000" : "")
    );
  }

  setupAxios() {
    // Configure axios defaults
    axios.defaults.baseURL = this.baseURL;
    axios.defaults.headers.common["Content-Type"] = "application/json";
    axios.defaults.timeout = isDevelopment ? 30000 : 10000; // Longer timeout in dev

    // Development-specific configuration
    if (isDevelopment) {
      axios.defaults.headers.common["X-Development-Mode"] = "true";
    }

    console.log(
      `🔗 API configured for ${isDevelopment ? "development" : "production"}`
    );
    console.log(`📡 Base URL: ${this.baseURL}`);
  }

  setupInterceptors() {
    // Request interceptor
    axios.interceptors.request.use(
      (config) => {
        // Add auth token if available
        const token = localStorage.getItem("auth_token");
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }

        // Development logging
        if (isDevelopment && import.meta.env.VITE_DEBUG_MODE) {
          console.log("📤 API Request:", {
            method: config.method?.toUpperCase(),
            url: config.url,
            baseURL: config.baseURL,
            data: config.data,
            headers: config.headers,
          });
        }

        return config;
      },
      (error) => {
        if (isDevelopment) {
          console.error("❌ Request Error:", error);
        }
        return Promise.reject(error);
      }
    );

    // Response interceptor
    axios.interceptors.response.use(
      (response) => {
        if (isDevelopment && import.meta.env.VITE_DEBUG_MODE) {
          console.log("📥 API Response:", {
            status: response.status,
            url: response.config.url,
            data: response.data,
          });
        }
        return response;
      },
      (error) => {
        if (isDevelopment) {
          console.error("❌ Response Error:", {
            status: error.response?.status,
            url: error.config?.url,
            message: error.message,
            data: error.response?.data,
          });
        }

        // Handle common errors
        if (error.response?.status === 401) {
          // Token expired or invalid
          localStorage.removeItem("auth_token");
          window.location.href = "/login";
        }

        return Promise.reject(error);
      }
    );
  }

  refreshConfig() {
    console.log("🔄 Refreshing API configuration...");
    this.baseURL = this.getApiBaseUrl();
    this.setupAxios();
    console.log("✅ API configuration updated");
  }

  // Method to manually update configuration
  updateConfig(newBaseUrl) {
    this.baseURL = newBaseUrl;
    axios.defaults.baseURL = newBaseUrl;
    console.log(`🔄 API base URL updated to: ${newBaseUrl}`);
  }

  // Health check method
  async healthCheck() {
    try {
      const response = await axios.get("/health");
      console.log("✅ Backend health check passed");
      return response.data;
    } catch (error) {
      console.warn("⚠️ Backend health check failed:", error.message);
      return null;
    }
  }

  // Connection test with retry
  async testConnection(retries = 3) {
    for (let i = 0; i < retries; i++) {
      try {
        await this.healthCheck();
        return true;
      } catch (error) {
        if (i === retries - 1) {
          console.error(
            "❌ Failed to connect to backend after",
            retries,
            "attempts"
          );
          return false;
        }
        console.log(`🔄 Retry ${i + 1}/${retries} in 2 seconds...`);
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }
    }
  }
}

// Create and export singleton instance
const apiConfig = new ApiConfig();

// Auto-test connection in development
if (isDevelopment) {
  setTimeout(() => {
    apiConfig.testConnection().then((connected) => {
      if (!connected) {
        console.warn(
          "⚠️ Backend connection failed. Make sure backend is running on",
          apiConfig.baseURL
        );
      }
    });
  }, 2000);
}

export default apiConfig;
export { axios };
