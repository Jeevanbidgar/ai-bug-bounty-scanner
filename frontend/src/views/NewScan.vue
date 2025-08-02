<template>
    <div class="bg-gray-800 rounded-lg p-6">
        <h1 class="text-2xl font-bold text-white mb-4">New Vulnerability Scan</h1>
        <p class="text-gray-400 mb-6">Configure and start a new security scan</p>

        <form @submit.prevent="startScan" class="max-w-2xl space-y-6">
            <!-- Target URL -->
            <div>
                <label class="block text-sm font-medium text-gray-300 mb-2">
                    Target URL or IP *
                </label>
                <input v-model="form.target" type="text" required placeholder="https://example.com or 192.168.1.1"
                    class="w-full px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    :disabled="loading" />
            </div>

            <!-- Scan Name -->
            <div>
                <label class="block text-sm font-medium text-gray-300 mb-2">
                    Scan Name
                </label>
                <input v-model="form.name" type="text" placeholder="My Website Scan"
                    class="w-full px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    :disabled="loading" />
            </div>

            <!-- Scan Types -->
            <div>
                <label class="block text-sm font-medium text-gray-300 mb-3">
                    Scan Types
                </label>
                <div class="grid grid-cols-2 gap-3">
                    <label class="flex items-center p-3 bg-gray-700 rounded-lg cursor-pointer hover:bg-gray-600">
                        <input v-model="form.scan_types" type="checkbox" value="recon" class="mr-3 text-blue-600"
                            :disabled="loading" />
                        <div>
                            <p class="text-white font-medium">Reconnaissance</p>
                            <p class="text-gray-400 text-sm">Subdomain discovery, port scanning</p>
                        </div>
                    </label>

                    <label class="flex items-center p-3 bg-gray-700 rounded-lg cursor-pointer hover:bg-gray-600">
                        <input v-model="form.scan_types" type="checkbox" value="webapp" class="mr-3 text-blue-600"
                            :disabled="loading" />
                        <div>
                            <p class="text-white font-medium">Web Application</p>
                            <p class="text-gray-400 text-sm">OWASP Top 10, XSS, SQL injection</p>
                        </div>
                    </label>

                    <label class="flex items-center p-3 bg-gray-700 rounded-lg cursor-pointer hover:bg-gray-600">
                        <input v-model="form.scan_types" type="checkbox" value="network" class="mr-3 text-blue-600"
                            :disabled="loading" />
                        <div>
                            <p class="text-white font-medium">Network</p>
                            <p class="text-gray-400 text-sm">Network vulnerabilities, services</p>
                        </div>
                    </label>

                    <label class="flex items-center p-3 bg-gray-700 rounded-lg cursor-pointer hover:bg-gray-600">
                        <input v-model="form.scan_types" type="checkbox" value="api" class="mr-3 text-blue-600"
                            :disabled="loading" />
                        <div>
                            <p class="text-white font-medium">API Testing</p>
                            <p class="text-gray-400 text-sm">REST API security testing</p>
                        </div>
                    </label>
                </div>
            </div>

            <!-- Priority -->
            <div>
                <label class="block text-sm font-medium text-gray-300 mb-2">
                    Priority
                </label>
                <select v-model="form.priority"
                    class="w-full px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    :disabled="loading">
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                </select>
            </div>

            <!-- Actions -->
            <div class="flex space-x-4 pt-4">
                <button type="submit" :disabled="loading || form.scan_types.length === 0"
                    class="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
                    {{ loading ? 'Starting Scan...' : 'Start Scan' }}
                </button>

                <router-link to="/scans"
                    class="px-6 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-md transition-colors">
                    Cancel
                </router-link>
            </div>
        </form>

        <!-- Error/Success Messages -->
        <div v-if="message" class="mt-6 p-4 rounded-md" :class="messageClass">
            {{ message }}
        </div>
    </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import axios from 'axios'

const router = useRouter()

const form = ref({
    target: '',
    name: '',
    scan_types: [],
    priority: 'medium'
})

const loading = ref(false)
const message = ref('')
const messageType = ref('success')

const messageClass = computed(() => {
    return messageType.value === 'success'
        ? 'bg-green-900 border border-green-700 text-green-300'
        : 'bg-red-900 border border-red-700 text-red-300'
})

const startScan = async () => {
    try {
        loading.value = true
        message.value = ''

        const scanData = {
            target: form.value.target,
            name: form.value.name || `Scan of ${form.value.target}`,
            scan_types: form.value.scan_types,
            priority: form.value.priority,
            options: {}
        }

        const response = await axios.post('/api/scans', scanData)

        message.value = 'Scan started successfully!'
        messageType.value = 'success'

        // Redirect to scan details after a short delay
        setTimeout(() => {
            router.push(`/scans/${response.data.scan_id}`)
        }, 2000)

    } catch (error) {
        message.value = error.response?.data?.message || 'Failed to start scan'
        messageType.value = 'error'
    } finally {
        loading.value = false
    }
}
</script>
