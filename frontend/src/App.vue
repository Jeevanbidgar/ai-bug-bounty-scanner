<template>
    <div id="app" class="min-h-screen bg-slate-900">
        <!-- Main Application -->
        <div class="flex h-screen bg-slate-900">
            <!-- Sidebar -->
            <Sidebar />

            <!-- Main Content -->
            <div class="flex-1 flex flex-col overflow-hidden">
                <!-- Top Navigation -->
                <TopNavigation />

                <!-- Page Content -->
                <main class="flex-1 overflow-x-hidden overflow-y-auto bg-slate-900">
                    <div class="container mx-auto px-6 py-8">
                        <router-view v-slot="{ Component }">
                            <transition name="page" enter-active-class="duration-300 ease-out"
                                enter-from-class="transform opacity-0 scale-95"
                                enter-to-class="transform opacity-100 scale-100"
                                leave-active-class="duration-200 ease-in"
                                leave-from-class="transform opacity-100 scale-100"
                                leave-to-class="transform opacity-0 scale-95">
                                <component :is="Component" />
                            </transition>
                        </router-view>
                    </div>
                </main>
            </div>
        </div>

        <!-- Global Notifications -->
        <ConnectionStatus />
    </div>
</template>

<script setup>
import { onMounted } from 'vue'
import { useSocketStore } from '@/stores/socket'
import Sidebar from '@/components/layout/Sidebar.vue'
import TopNavigation from '@/components/layout/TopNavigation.vue'
import ConnectionStatus from '@/components/common/ConnectionStatus.vue'

const socketStore = useSocketStore()

onMounted(async () => {
    // Initialize socket connection
    socketStore.connect()
})
</script>

<style>
.page-enter-active,
.page-leave-active {
    transition: all 0.3s ease;
}

.page-enter-from,
.page-leave-to {
    opacity: 0;
    transform: translateY(20px);
}
</style>
