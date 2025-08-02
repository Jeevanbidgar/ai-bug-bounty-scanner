<template>
    <div class="fixed bottom-4 right-4 z-50">
        <!-- Connection Status Indicator -->
        <div v-if="!socketStore.isConnected"
            class="bg-red-600 text-white px-4 py-2 rounded-lg shadow-lg flex items-center space-x-2">
            <svg class="w-4 h-4 animate-pulse" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd"
                    d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"
                    clip-rule="evenodd" />
            </svg>
            <span class="text-sm">Connection Lost</span>
        </div>

        <!-- Reconnecting Status -->
        <div v-else-if="socketStore.isReconnecting"
            class="bg-yellow-600 text-white px-4 py-2 rounded-lg shadow-lg flex items-center space-x-2">
            <svg class="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            <span class="text-sm">Reconnecting...</span>
        </div>

        <!-- Notifications -->
        <div v-for="notification in notifications" :key="notification.id"
            class="mb-2 p-4 rounded-lg shadow-lg max-w-sm transform transition-all duration-300"
            :class="getNotificationClass(notification.type)">
            <div class="flex items-start">
                <div class="flex-shrink-0">
                    <svg v-if="notification.type === 'success'" class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd"
                            d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                            clip-rule="evenodd" />
                    </svg>
                    <svg v-else-if="notification.type === 'error'" class="w-5 h-5" fill="currentColor"
                        viewBox="0 0 20 20">
                        <path fill-rule="evenodd"
                            d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"
                            clip-rule="evenodd" />
                    </svg>
                    <svg v-else-if="notification.type === 'warning'" class="w-5 h-5" fill="currentColor"
                        viewBox="0 0 20 20">
                        <path fill-rule="evenodd"
                            d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
                            clip-rule="evenodd" />
                    </svg>
                    <svg v-else class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd"
                            d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"
                            clip-rule="evenodd" />
                    </svg>
                </div>
                <div class="ml-3 flex-1">
                    <h4 class="font-medium">{{ notification.title }}</h4>
                    <p class="text-sm opacity-90">{{ notification.message }}</p>
                </div>
                <button @click="removeNotification(notification.id)"
                    class="ml-2 flex-shrink-0 opacity-70 hover:opacity-100">
                    <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd"
                            d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
                            clip-rule="evenodd" />
                    </svg>
                </button>
            </div>
        </div>
    </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useSocketStore } from '@/stores/socket'

const socketStore = useSocketStore()
const notifications = ref([])

const getNotificationClass = (type) => {
    const classes = {
        success: 'bg-green-600 text-white',
        error: 'bg-red-600 text-white',
        warning: 'bg-yellow-600 text-white',
        info: 'bg-blue-600 text-white'
    }
    return classes[type] || classes.info
}

const addNotification = (notification) => {
    const id = Date.now() + Math.random()
    notifications.value.push({
        id,
        ...notification
    })

    // Auto-remove after 5 seconds
    setTimeout(() => {
        removeNotification(id)
    }, 5000)
}

const removeNotification = (id) => {
    const index = notifications.value.findIndex(n => n.id === id)
    if (index > -1) {
        notifications.value.splice(index, 1)
    }
}

// Listen for custom notification events
const handleNotification = (event) => {
    addNotification(event.detail)
}

onMounted(() => {
    window.addEventListener('app-notification', handleNotification)
})

onUnmounted(() => {
    window.removeEventListener('app-notification', handleNotification)
})

// Export function to trigger notifications from other components
window.showNotification = (title, message, type = 'info') => {
    addNotification({ title, message, type })
}
</script>
