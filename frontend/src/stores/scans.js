import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import axios from 'axios'
import { io } from 'socket.io-client'

export const useScansStore = defineStore('scans', () => {
  const scans = ref([])
  const currentScan = ref(null)
  const scanResults = ref({})
  const loading = ref(false)
  const socket = ref(null)

  const recentScans = computed(() => 
    scans.value
      .slice()
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
      .slice(0, 5)
  )

  const activeScan = computed(() => 
    scans.value.find(scan => scan.status === 'running')
  )

  const completedScans = computed(() => 
    scans.value.filter(scan => scan.status === 'completed')
  )

  function initializeSocket() {
    if (!socket.value) {
      socket.value = io('http://localhost:5000', {
        auth: {
          token: localStorage.getItem('token')
        }
      })

      socket.value.on('scan_progress', (data) => {
        updateScanProgress(data)
      })

      socket.value.on('scan_completed', (data) => {
        updateScanStatus(data.scan_id, 'completed')
        fetchScanResults(data.scan_id)
      })

      socket.value.on('scan_error', (data) => {
        updateScanStatus(data.scan_id, 'failed')
      })
    }
  }

  function disconnectSocket() {
    if (socket.value) {
      socket.value.disconnect()
      socket.value = null
    }
  }

  async function fetchScans() {
    loading.value = true
    try {
      const response = await axios.get('/api/scans')
      scans.value = response.data
    } catch (error) {
      console.error('Failed to fetch scans:', error)
      throw error
    } finally {
      loading.value = false
    }
  }

  async function fetchScan(scanId) {
    try {
      const response = await axios.get(`/api/scans/${scanId}`)
      currentScan.value = response.data
      return response.data
    } catch (error) {
      console.error('Failed to fetch scan:', error)
      throw error
    }
  }

  async function createScan(scanConfig) {
    loading.value = true
    try {
      const response = await axios.post('/api/scans', scanConfig)
      const newScan = response.data
      scans.value.unshift(newScan)
      
      // Initialize socket for real-time updates
      initializeSocket()
      
      return newScan
    } catch (error) {
      console.error('Failed to create scan:', error)
      throw error
    } finally {
      loading.value = false
    }
  }

  async function startScan(scanId) {
    try {
      const response = await axios.post(`/api/scans/${scanId}/start`)
      updateScanStatus(scanId, 'running')
      
      // Initialize socket for real-time updates
      initializeSocket()
      
      return response.data
    } catch (error) {
      console.error('Failed to start scan:', error)
      throw error
    }
  }

  async function stopScan(scanId) {
    try {
      const response = await axios.post(`/api/scans/${scanId}/stop`)
      updateScanStatus(scanId, 'stopped')
      return response.data
    } catch (error) {
      console.error('Failed to stop scan:', error)
      throw error
    }
  }

  async function deleteScan(scanId) {
    try {
      await axios.delete(`/api/scans/${scanId}`)
      scans.value = scans.value.filter(scan => scan.id !== scanId)
      if (currentScan.value?.id === scanId) {
        currentScan.value = null
      }
      delete scanResults.value[scanId]
    } catch (error) {
      console.error('Failed to delete scan:', error)
      throw error
    }
  }

  async function fetchScanResults(scanId) {
    try {
      const response = await axios.get(`/api/scans/${scanId}/results`)
      scanResults.value[scanId] = response.data
      return response.data
    } catch (error) {
      console.error('Failed to fetch scan results:', error)
      throw error
    }
  }

  async function exportScanResults(scanId, format = 'json') {
    try {
      const response = await axios.get(`/api/scans/${scanId}/export/${format}`, {
        responseType: 'blob'
      })
      
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      
      // Determine file extension
      const extensions = { json: 'json', pdf: 'pdf', markdown: 'md' }
      const extension = extensions[format] || 'txt'
      
      link.setAttribute('download', `scan_${scanId}_results.${extension}`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
      
      return true
    } catch (error) {
      console.error('Failed to export scan results:', error)
      throw error
    }
  }

  function updateScanStatus(scanId, status) {
    const scan = scans.value.find(s => s.id === scanId)
    if (scan) {
      scan.status = status
      scan.updated_at = new Date().toISOString()
    }
    
    if (currentScan.value?.id === scanId) {
      currentScan.value.status = status
      currentScan.value.updated_at = new Date().toISOString()
    }
  }

  function updateScanProgress(data) {
    const { scan_id, progress, stage, message } = data
    const scan = scans.value.find(s => s.id === scan_id)
    
    if (scan) {
      scan.progress = progress
      scan.current_stage = stage
      scan.status_message = message
    }
    
    if (currentScan.value?.id === scan_id) {
      currentScan.value.progress = progress
      currentScan.value.current_stage = stage
      currentScan.value.status_message = message
    }
  }

  function getScanResults(scanId) {
    return scanResults.value[scanId] || null
  }

  function clearCurrentScan() {
    currentScan.value = null
  }

  return {
    scans: computed(() => scans.value),
    currentScan: computed(() => currentScan.value),
    scanResults: computed(() => scanResults.value),
    loading: computed(() => loading.value),
    recentScans,
    activeScan,
    completedScans,
    fetchScans,
    fetchScan,
    createScan,
    startScan,
    stopScan,
    deleteScan,
    fetchScanResults,
    exportScanResults,
    getScanResults,
    clearCurrentScan,
    initializeSocket,
    disconnectSocket
  }
})
