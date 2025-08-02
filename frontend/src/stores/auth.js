import { defineStore } from "pinia";
import { ref, computed } from "vue";
import { axios } from "@/utils/api";

export const useAuthStore = defineStore("auth", () => {
  const user = ref(null);
  const token = ref(localStorage.getItem("token"));
  const refreshToken = ref(localStorage.getItem("refreshToken"));

  const isAuthenticated = computed(() => !!token.value);

  // Configure axios defaults
  if (token.value) {
    axios.defaults.headers.common["Authorization"] = `Bearer ${token.value}`;
  }

  async function login(credentials) {
    try {
      const response = await axios.post("/api/auth/login", credentials);
      const { access_token, refresh_token, user: userData } = response.data;

      token.value = access_token;
      refreshToken.value = refresh_token;
      user.value = userData;

      // Store tokens
      localStorage.setItem("token", access_token);
      localStorage.setItem("refreshToken", refresh_token);

      // Set authorization header
      axios.defaults.headers.common["Authorization"] = `Bearer ${access_token}`;

      return { success: true, user: userData };
    } catch (error) {
      const message = error.response?.data?.error || "Login failed";
      return { success: false, error: message };
    }
  }

  async function register(userData) {
    try {
      const response = await axios.post("/api/auth/register", userData);
      return { success: true, user: response.data.user };
    } catch (error) {
      const message = error.response?.data?.error || "Registration failed";
      return { success: false, error: message };
    }
  }

  async function logout() {
    token.value = null;
    refreshToken.value = null;
    user.value = null;

    // Clear storage
    localStorage.removeItem("token");
    localStorage.removeItem("refreshToken");

    // Remove authorization header
    delete axios.defaults.headers.common["Authorization"];
  }

  async function checkAuth() {
    if (!token.value) return false;

    try {
      const response = await axios.get("/api/auth/profile");
      user.value = response.data;
      return true;
    } catch (error) {
      // Token is invalid, logout
      await logout();
      return false;
    }
  }

  async function refreshAccessToken() {
    if (!refreshToken.value) {
      await logout();
      return false;
    }

    try {
      const response = await axios.post(
        "/api/auth/refresh",
        {},
        {
          headers: { Authorization: `Bearer ${refreshToken.value}` },
        }
      );

      const { access_token } = response.data;
      token.value = access_token;

      localStorage.setItem("token", access_token);
      axios.defaults.headers.common["Authorization"] = `Bearer ${access_token}`;

      return true;
    } catch (error) {
      await logout();
      return false;
    }
  }

  // Setup axios interceptor for automatic token refresh
  axios.interceptors.response.use(
    (response) => response,
    async (error) => {
      if (error.response?.status === 401 && token.value) {
        // Try to refresh token
        const refreshed = await refreshAccessToken();
        if (refreshed) {
          // Retry the original request
          return axios.request(error.config);
        }
      }
      return Promise.reject(error);
    }
  );

  return {
    user: computed(() => user.value),
    token: computed(() => token.value),
    isAuthenticated,
    login,
    register,
    logout,
    checkAuth,
    refreshAccessToken,
  };
});
