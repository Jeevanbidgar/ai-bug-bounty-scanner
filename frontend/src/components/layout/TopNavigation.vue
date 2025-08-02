<template>
    <header class="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div class="flex items-center justify-between">
            <!-- Page Title -->
            <div>
                <h1 class="text-xl font-semibold text-white">{{ pageTitle }}</h1>
                <p class="text-gray-400 text-sm">{{ pageDescription }}</p>
            </div>

            <!-- Actions and User Menu -->
            <div class="flex items-center space-x-4">
                <!-- Notifications -->
                <button class="relative p-2 text-gray-400 hover:text-white transition-colors">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M15 17h5l-5-5-5 5h5v-7a1 1 0 011-1h4a1 1 0 011 1v7z" />
                    </svg>
                    <span class="absolute top-0 right-0 h-2 w-2 bg-red-500 rounded-full"></span>
                </button>

                <!-- User Menu -->
                <div class="relative">
                    <button @click="showUserMenu = !showUserMenu"
                        class="flex items-center space-x-3 text-gray-300 hover:text-white transition-colors">
                        <div class="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center">
                            <span class="text-sm font-medium">A</span>
                        </div>
                        <div class="hidden md:block text-left">
                            <p class="text-sm font-medium">Admin</p>
                            <p class="text-xs text-gray-400">administrator</p>
                        </div>
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                        </svg>
                    </button>

                    <!-- Dropdown Menu -->
                    <div v-if="showUserMenu" v-click-outside="() => showUserMenu = false"
                        class="absolute right-0 mt-2 w-48 bg-gray-800 border border-gray-700 rounded-lg shadow-lg py-1 z-50">
                        <router-link to="/profile"
                            class="block px-4 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-700"
                            @click="showUserMenu = false">
                            Profile
                        </router-link>
                        <router-link to="/settings"
                            class="block px-4 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-700"
                            @click="showUserMenu = false">
                            Settings
                        </router-link>
                    </div>
                </div>
            </div>
        </div>
    </header>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()
const showUserMenu = ref(false)

const pageTitle = computed(() => {
    const titles = {
        Dashboard: 'Dashboard',
        Scans: 'Security Scans',
        Vulnerabilities: 'Vulnerabilities',
        Reports: 'Reports',
        Tools: 'Security Tools',
        Settings: 'Settings',
        Profile: 'Profile'
    }
    return titles[route.name] || 'AI Bug Bounty Scanner'
})

const pageDescription = computed(() => {
    const descriptions = {
        Dashboard: 'Overview of your security scanning activities',
        Scans: 'Manage and monitor security scans',
        Vulnerabilities: 'View and manage discovered vulnerabilities',
        Reports: 'Generate and download security reports',
        Tools: 'Configure external security tools',
        Settings: 'Application settings and configuration',
        Profile: 'Manage your user profile'
    }
    return descriptions[route.name] || 'Advanced AI-powered vulnerability scanning platform'
})
</script>
