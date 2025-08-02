<template>
    <div class="space-y-6">
        <!-- Header -->
        <div class="bg-gray-800 rounded-lg p-6">
            <h1 class="text-2xl font-bold text-white mb-2">Dashboard</h1>
            <p class="text-gray-400">Welcome to AI Bug Bounty Scanner</p>
        </div>

        <!-- Stats Grid -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div class="bg-gray-800 rounded-lg p-6">
                <div class="flex items-center">
                    <div class="p-2 bg-blue-600 rounded-lg">
                        <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                        </svg>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-400">Total Scans</p>
                        <p class="text-2xl font-bold text-white">{{ stats.totalScans }}</p>
                    </div>
                </div>
            </div>

            <div class="bg-gray-800 rounded-lg p-6">
                <div class="flex items-center">
                    <div class="p-2 bg-red-600 rounded-lg">
                        <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                        </svg>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-400">Vulnerabilities</p>
                        <p class="text-2xl font-bold text-white">{{ stats.totalVulnerabilities }}</p>
                    </div>
                </div>
            </div>

            <div class="bg-gray-800 rounded-lg p-6">
                <div class="flex items-center">
                    <div class="p-2 bg-yellow-600 rounded-lg">
                        <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-400">Active Scans</p>
                        <p class="text-2xl font-bold text-white">{{ stats.activeScans }}</p>
                    </div>
                </div>
            </div>

            <div class="bg-gray-800 rounded-lg p-6">
                <div class="flex items-center">
                    <div class="p-2 bg-green-600 rounded-lg">
                        <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-400">Completed</p>
                        <p class="text-2xl font-bold text-white">{{ stats.completedScans }}</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Recent Activity -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <!-- Recent Scans -->
            <div class="bg-gray-800 rounded-lg p-6">
                <h3 class="text-lg font-medium text-white mb-4">Recent Scans</h3>
                <div class="space-y-4">
                    <div v-for="scan in recentScans" :key="scan.id"
                        class="flex items-center justify-between p-3 bg-gray-700 rounded-lg">
                        <div>
                            <p class="font-medium text-white">{{ scan.target }}</p>
                            <p class="text-sm text-gray-400">{{ formatDate(scan.created_at) }}</p>
                        </div>
                        <div class="text-right">
                            <span :class="getStatusClass(scan.status)"
                                class="px-2 py-1 text-xs font-medium rounded-full">
                                {{ scan.status }}
                            </span>
                        </div>
                    </div>
                    <div v-if="recentScans.length === 0" class="text-center py-8 text-gray-400">
                        No scans available
                    </div>
                </div>
            </div>

            <!-- Recent Vulnerabilities -->
            <div class="bg-gray-800 rounded-lg p-6">
                <h3 class="text-lg font-medium text-white mb-4">Recent Vulnerabilities</h3>
                <div class="space-y-4">
                    <div v-for="vuln in recentVulnerabilities" :key="vuln.id"
                        class="flex items-center justify-between p-3 bg-gray-700 rounded-lg">
                        <div>
                            <p class="font-medium text-white">{{ vuln.title }}</p>
                            <p class="text-sm text-gray-400">{{ vuln.target }}</p>
                        </div>
                        <div class="text-right">
                            <span :class="getSeverityClass(vuln.severity)"
                                class="px-2 py-1 text-xs font-medium rounded-full">
                                {{ vuln.severity }}
                            </span>
                        </div>
                    </div>
                    <div v-if="recentVulnerabilities.length === 0" class="text-center py-8 text-gray-400">
                        No vulnerabilities found
                    </div>
                </div>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="bg-gray-800 rounded-lg p-6">
            <h3 class="text-lg font-medium text-white mb-4">Quick Actions</h3>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <router-link to="/scans/new"
                    class="flex items-center p-4 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
                    <svg class="w-6 h-6 text-white mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                    </svg>
                    <span class="font-medium text-white">New Scan</span>
                </router-link>

                <router-link to="/scans"
                    class="flex items-center p-4 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors">
                    <svg class="w-6 h-6 text-white mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                    <span class="font-medium text-white">View Scans</span>
                </router-link>

                <router-link to="/reports"
                    class="flex items-center p-4 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors">
                    <svg class="w-6 h-6 text-white mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    <span class="font-medium text-white">Generate Report</span>
                </router-link>
            </div>
        </div>
    </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import axios from 'axios'

const stats = ref({
    totalScans: 0,
    totalVulnerabilities: 0,
    activeScans: 0,
    completedScans: 0
})

const recentScans = ref([])
const recentVulnerabilities = ref([])
const loading = ref(true)

const loadDashboardData = async () => {
    try {
        // Load dashboard stats
        const statsResponse = await axios.get('/api/dashboard/stats')
        stats.value = statsResponse.data

        // Load recent activity
        const activityResponse = await axios.get('/api/dashboard/recent-activity')
        recentScans.value = activityResponse.data.recentScans || []
        recentVulnerabilities.value = activityResponse.data.recentVulnerabilities || []
    } catch (error) {
        console.error('Failed to load dashboard data:', error)
        // Set default values if API calls fail
        stats.value = {
            totalScans: 0,
            totalVulnerabilities: 0,
            activeScans: 0,
            completedScans: 0
        }
    } finally {
        loading.value = false
    }
}

const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString()
}

const getStatusClass = (status) => {
    const classes = {
        'completed': 'bg-green-200 text-green-800',
        'running': 'bg-yellow-200 text-yellow-800',
        'failed': 'bg-red-200 text-red-800',
        'pending': 'bg-gray-200 text-gray-800'
    }
    return classes[status] || classes.pending
}

const getSeverityClass = (severity) => {
    const classes = {
        'critical': 'bg-red-200 text-red-800',
        'high': 'bg-orange-200 text-orange-800',
        'medium': 'bg-yellow-200 text-yellow-800',
        'low': 'bg-green-200 text-green-800',
        'info': 'bg-blue-200 text-blue-800'
    }
    return classes[severity] || classes.info
}

onMounted(() => {
    loadDashboardData()
})
</script>
