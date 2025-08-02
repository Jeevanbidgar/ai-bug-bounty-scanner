import { createApp } from "vue";
import { createPinia } from "pinia";
import Toast from "vue-toastification";
import axios from "axios";
import App from "./App.vue";
import router from "./router";

// Styles
import "./style.css";
import "vue-toastification/dist/index.css";

// Environment-based configuration
const isDevelopment = import.meta.env.MODE === "development";
const apiBaseURL =
  import.meta.env.VITE_API_BASE_URL ||
  (isDevelopment ? "http://localhost:5000" : "");

// Configure Axios with environment variables
axios.defaults.baseURL = apiBaseURL;
axios.defaults.headers.common["Content-Type"] = "application/json";

// Development logging
if (isDevelopment) {
  console.log("🚀 Frontend running in development mode");
  console.log("📡 API Base URL:", apiBaseURL);
  console.log("🔌 Socket URL:", import.meta.env.VITE_SOCKET_URL);
  console.log("🔥 Hot Reload:", import.meta.env.VITE_HOT_RELOAD);

  // Add request/response interceptors for debugging
  axios.interceptors.request.use(
    (config) => {
      console.log(
        "📤 API Request:",
        config.method?.toUpperCase(),
        config.url,
        config.data
      );
      return config;
    },
    (error) => {
      console.error("❌ API Request Error:", error);
      return Promise.reject(error);
    }
  );

  axios.interceptors.response.use(
    (response) => {
      console.log("📥 API Response:", response.status, response.config.url);
      return response;
    },
    (error) => {
      console.error(
        "❌ API Response Error:",
        error.response?.status,
        error.config?.url,
        error.message
      );
      return Promise.reject(error);
    }
  );
}

const app = createApp(App);

// Enable Vue DevTools in development
if (isDevelopment && import.meta.env.VITE_ENABLE_DEVTOOLS) {
  app.config.devtools = true;
  app.config.performance = true;
}

// Click outside directive
app.directive("click-outside", {
  beforeMount(el, binding) {
    el.clickOutsideEvent = function (event) {
      if (!(el === event.target || el.contains(event.target))) {
        binding.value(event);
      }
    };
    document.addEventListener("click", el.clickOutsideEvent);
  },
  unmounted(el) {
    document.removeEventListener("click", el.clickOutsideEvent);
  },
});

// Auto-focus directive for better UX
app.directive("auto-focus", {
  mounted(el) {
    el.focus();
  },
});

// Configure toast notifications
const toastOptions = {
  position: "top-right",
  timeout: isDevelopment ? 8000 : 5000, // Longer timeout in development
  closeOnClick: true,
  pauseOnFocusLoss: true,
  pauseOnHover: true,
  draggable: true,
  draggablePercent: 0.6,
  showCloseButtonOnHover: false,
  hideProgressBar: false,
  closeButton: "button",
  icon: true,
  rtl: false,
};

app.use(createPinia());
app.use(router);
app.use(Toast, toastOptions);

// Development features
if (isDevelopment) {
  // Enable hot module replacement
  if (import.meta.hot) {
    import.meta.hot.accept();
    console.log("🔥 Hot Module Replacement enabled");
  }

  // Performance monitoring
  if (import.meta.env.VITE_SHOW_PERFORMANCE_OVERLAY) {
    app.config.performance = true;
    console.log("📊 Performance monitoring enabled");
  }

  // Global error handler for development
  app.config.errorHandler = (err, vm, info) => {
    console.error("💥 Vue Error:", err);
    console.error("🔍 Component:", vm);
    console.error("ℹ️ Info:", info);
  };
}

app.mount("#app");
