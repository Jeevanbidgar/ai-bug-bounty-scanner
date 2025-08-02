<template>
    <div class="bg-gray-800 rounded-lg p-6">
        <h1 class="text-2xl font-bold text-white mb-4">User Profile</h1>

        <div class="max-w-md">
            <form @submit.prevent="updateProfile" class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-2">
                        Username
                    </label>
                    <input v-model="form.username" type="text"
                        class="w-full px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        :disabled="loading" />
                </div>

                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-2">
                        Email
                    </label>
                    <input v-model="form.email" type="email"
                        class="w-full px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        :disabled="loading" />
                </div>

                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-2">
                        First Name
                    </label>
                    <input v-model="form.first_name" type="text"
                        class="w-full px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        :disabled="loading" />
                </div>

                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-2">
                        Last Name
                    </label>
                    <input v-model="form.last_name" type="text"
                        class="w-full px-3 py-2 bg-gray-700 border border-gray-600 text-white rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        :disabled="loading" />
                </div>

                <div class="flex space-x-4">
                    <button type="submit" :disabled="loading"
                        class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors disabled:opacity-50">
                        {{ loading ? 'Saving...' : 'Save Profile' }}
                    </button>

                    <router-link to="/"
                        class="px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-md transition-colors">
                        Cancel
                    </router-link>
                </div>
            </form>
        </div>

        <div v-if="message" class="mt-4 p-4 rounded-md" :class="messageClass">
            {{ message }}
        </div>
    </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import { useAuthStore } from '@/stores/auth'
import axios from 'axios'

const authStore = useAuthStore()

const form = ref({
    username: '',
    email: '',
    first_name: '',
    last_name: ''
})

const loading = ref(false)
const message = ref('')
const messageType = ref('success')

const messageClass = computed(() => {
    return messageType.value === 'success'
        ? 'bg-green-900 border border-green-700 text-green-300'
        : 'bg-red-900 border border-red-700 text-red-300'
})

const loadProfile = async () => {
    try {
        const response = await axios.get('/api/users/profile')
        const user = response.data.user

        if (user) {
            form.value = {
                username: user.username || '',
                email: user.email || '',
                first_name: user.first_name || '',
                last_name: user.last_name || ''
            }
        }
    } catch (error) {
        console.error('Failed to load profile:', error)
        message.value = 'Failed to load profile data'
        messageType.value = 'error'
    }
}

const updateProfile = async () => {
    try {
        loading.value = true
        message.value = ''

        const response = await axios.put('/api/users/profile', form.value)

        message.value = 'Profile updated successfully'
        messageType.value = 'success'

        // Update auth store
        if (response.data.user) {
            authStore.user = response.data.user
        }

    } catch (error) {
        message.value = error.response?.data?.message || 'Failed to update profile'
        messageType.value = 'error'
    } finally {
        loading.value = false
    }
}

onMounted(() => {
    // Load current user data
    if (authStore.user) {
        form.value = {
            username: authStore.user.username || '',
            email: authStore.user.email || '',
            first_name: authStore.user.first_name || '',
            last_name: authStore.user.last_name || ''
        }
    }

    // Also try to fetch from API
    loadProfile()
})
</script>
