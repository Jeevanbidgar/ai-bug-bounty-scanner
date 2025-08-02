import { defineStore } from "pinia";
import { ref, computed } from "vue";
import { io } from "socket.io-client";

export const useSocketStore = defineStore("socket", () => {
  const socket = ref(null);
  const isConnected = ref(false);
  const isReconnecting = ref(false);
  const connectionError = ref(null);

  // Environment-aware socket URL
  const getSocketUrl = () => {
    return (
      import.meta.env.VITE_SOCKET_URL ||
      (import.meta.env.MODE === "development" ? "http://localhost:5000" : "")
    );
  };

  const connect = () => {
    if (socket.value && socket.value.connected) {
      return;
    }

    // Get token from auth store
    const token = localStorage.getItem("token");
    const socketUrl = getSocketUrl();

    console.log("🔌 Connecting to socket server:", socketUrl);

    socket.value = io(socketUrl, {
      auth: {
        token: token,
      },
      transports: ["websocket", "polling"],
      // Development-specific options
      ...(import.meta.env.MODE === "development" && {
        forceNew: true,
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
        timeout: 10000,
      }),
    });

    socket.value.on("connect", () => {
      isConnected.value = true;
      isReconnecting.value = false;
      connectionError.value = null;
      console.log("Socket connected");
    });

    socket.value.on("disconnect", () => {
      isConnected.value = false;
      console.log("Socket disconnected");
    });

    socket.value.on("connect_error", (error) => {
      connectionError.value = error.message;
      console.error("Socket connection error:", error);
    });

    socket.value.on("reconnect_attempt", () => {
      isReconnecting.value = true;
      console.log("Socket reconnecting...");
    });

    socket.value.on("reconnect", () => {
      isReconnecting.value = false;
      console.log("Socket reconnected");
    });

    // Listen for scan updates
    socket.value.on("scan_update", (data) => {
      // Emit custom event for components to listen to
      window.dispatchEvent(new CustomEvent("scan-update", { detail: data }));
    });

    // Listen for vulnerability updates
    socket.value.on("vulnerability_found", (data) => {
      window.dispatchEvent(
        new CustomEvent("vulnerability-found", { detail: data })
      );
    });

    // Listen for task progress updates
    socket.value.on("task_progress", (data) => {
      window.dispatchEvent(new CustomEvent("task-progress", { detail: data }));
    });
  };

  const disconnect = () => {
    if (socket.value) {
      socket.value.disconnect();
      socket.value = null;
      isConnected.value = false;
      isReconnecting.value = false;
    }
  };

  const emit = (event, data) => {
    if (socket.value && socket.value.connected) {
      socket.value.emit(event, data);
    }
  };

  const on = (event, callback) => {
    if (socket.value) {
      socket.value.on(event, callback);
    }
  };

  const off = (event, callback) => {
    if (socket.value) {
      socket.value.off(event, callback);
    }
  };

  return {
    socket: computed(() => socket.value),
    isConnected: computed(() => isConnected.value),
    isReconnecting: computed(() => isReconnecting.value),
    connectionError: computed(() => connectionError.value),
    connect,
    disconnect,
    emit,
    on,
    off,
  };
});
