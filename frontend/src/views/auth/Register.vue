<template>
    <div class="min-h-screen flex items-center justify-center bg-gray-900">
        <div class="max-w-md w-full space-y-8">
            <div>
                <div class="mx-auto h-12 w-12 flex items-center justify-center bg-blue-600 rounded-xl">
                    <svg class="h-8 w-8 text-white" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd"
                            d="M9.504 1.132a1 1 0 01.992 0l1.75 1a1 1 0 11-.992 1.736L10 3.152l-1.254.716a1 1 0 11-.992-1.736l1.75-1z"
                            clip-rule="evenodd" />
                    </svg>
                </div>
                <h2 class="mt-6 text-center text-3xl font-extrabold text-white">
                    Create your account
                </h2>
                <p class="mt-2 text-center text-sm text-gray-400">
                    Join AI Bug Bounty Scanner
                </p>
            </div>

            <form class="mt-8 space-y-6" @submit.prevent="handleRegister">
                <div class="space-y-4">
                    <div>
                        <label for="username" class="block text-sm font-medium text-gray-300">
                            Username
                        </label>
                        <input id="username" v-model="form.username" type="text" required
                            class="mt-1 block w-full px-3 py-2 bg-gray-800 border border-gray-700 placeholder-gray-500 text-white rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                            placeholder="Choose a username" />
                    </div>

                    <div>
                        <label for="email" class="block text-sm font-medium text-gray-300">
                            Email
                        </label>
                        <input id="email" v-model="form.email" type="email" required
                            class="mt-1 block w-full px-3 py-2 bg-gray-800 border border-gray-700 placeholder-gray-500 text-white rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                            placeholder="Enter your email" />
                    </div>

                    <div>
                        <label for="password" class="block text-sm font-medium text-gray-300">
                            Password
                        </label>
                        <input id="password" v-model="form.password" type="password" required
                            class="mt-1 block w-full px-3 py-2 bg-gray-800 border border-gray-700 placeholder-gray-500 text-white rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                            placeholder="Create a password" />
                    </div>

                    <div>
                        <label for="confirm-password" class="block text-sm font-medium text-gray-300">
                            Confirm Password
                        </label>
                        <input id="confirm-password" v-model="form.confirmPassword" type="password" required
                            class="mt-1 block w-full px-3 py-2 bg-gray-800 border border-gray-700 placeholder-gray-500 text-white rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                            placeholder="Confirm your password" />
                    </div>
                </div>

                <div>
                    <button type="submit" :disabled="loading"
                        class="w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50">
                        {{ loading ? 'Creating account...' : 'Create account' }}
                    </button>
                </div>

                <div class="text-center">
                    <p class="text-sm text-gray-400">
                        Already have an account?
                        <router-link to="/login" class="font-medium text-blue-400 hover:text-blue-300">
                            Sign in
                        </router-link>
                    </p>
                </div>
            </form>

            <div v-if="error" class="mt-4 p-4 bg-red-900 border border-red-700 rounded-md">
                <p class="text-red-300 text-sm">{{ error }}</p>
            </div>
        </div>
    </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const authStore = useAuthStore()

const form = ref({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
})

const loading = ref(false)
const error = ref('')

const handleRegister = async () => {
    if (form.value.password !== form.value.confirmPassword) {
        error.value = 'Passwords do not match'
        return
    }

    try {
        loading.value = true
        error.value = ''

        await authStore.register({
            username: form.value.username,
            email: form.value.email,
            password: form.value.password
        })

        router.push('/')
    } catch (err) {
        error.value = err.response?.data?.message || 'Registration failed. Please try again.'
    } finally {
        loading.value = false
    }
}
</script>
