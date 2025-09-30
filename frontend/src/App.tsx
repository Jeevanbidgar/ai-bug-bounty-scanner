import { Routes, Route } from 'react-router-dom'
import { useEffect, useState } from 'react'
import Dashboard from './pages/Dashboard'
import ScansPage from './pages/ScansPage'
import ToolsPage from './pages/ToolsPage'
import ReportsPage from './pages/ReportsPage'
import SettingsPage from './pages/SettingsPage'
import Layout from './components/Layout'
import { invoke } from '@tauri-apps/api/tauri'

function App() {
  const [backendStarted, setBackendStarted] = useState(false)
  const [startupError, setStartupError] = useState<string | null>(null)
  const [isDesktopApp, setIsDesktopApp] = useState(false)

  useEffect(() => {
    // Desktop app ONLY - always use Tauri
    setIsDesktopApp(true)
    
    const checkBackend = async () => {
      try {
        console.log('🚀 Checking backend connection...')
        
        // Check if backend is running (started by start.bat/start.ps1)
        let attempts = 0
        const maxAttempts = 10
        
        while (attempts < maxAttempts) {
          try {
            const response = await fetch('http://localhost:8000/api/health/')
            const data = await response.json()
            if (response.ok && data.status === 'healthy') {
              console.log('✅ Backend connected!', data)
              setBackendStarted(true)
              return
            }
          } catch (e) {
            console.log(`Backend not ready yet (attempt ${attempts + 1}/${maxAttempts}):`, e)
          }
          
          await new Promise(resolve => setTimeout(resolve, 1000))
          attempts++
        }
        
        setStartupError('Backend not responding. Please ensure start.bat/start.ps1 is running.')
      } catch (error) {
        console.error('Desktop app startup error:', error)
        setStartupError(`Desktop app error: ${error}`)
      }
    }

    checkBackend()
  }, [])

  if (startupError) {
    return (
      <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
        <div className="text-center max-w-lg px-4">
          <div className="text-red-500 text-6xl mb-4">⚠️</div>
          <h1 className="text-2xl font-bold mb-4">Startup Error</h1>
          <p className="text-gray-400 mb-6">{startupError}</p>
          <div className="bg-gray-800 p-4 rounded-lg text-left">
            <p className="text-sm text-gray-300 mb-2">Troubleshooting:</p>
            <ul className="text-xs text-gray-400 space-y-1 list-disc list-inside">
              <li>Ensure Python 3.11+ is installed</li>
              <li>Check if port 8000 is available</li>
              <li>Verify backend dependencies are installed</li>
              <li>Try running: cd backend && python run.py</li>
            </ul>
          </div>
        </div>
      </div>
    )
  }

  if (!backendStarted) {
    return (
      <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-lg">Starting AI Bug Bounty Scanner...</p>
          <p className="text-sm text-gray-400 mt-2">
            {isDesktopApp ? 'Initializing backend services' : 'Connecting to backend...'}
          </p>
        </div>
      </div>
    )
  }

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scans" element={<ScansPage />} />
        <Route path="/tools" element={<ToolsPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Routes>
    </Layout>
  )
}

export default App
