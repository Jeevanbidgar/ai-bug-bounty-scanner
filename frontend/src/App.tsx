import { Routes, Route } from 'react-router-dom'
import { useEffect, useState } from 'react'
import Dashboard from './pages/Dashboard'
import ScansPage from './pages/ScansPage'
import ToolsPage from './pages/ToolsPage'
import ReportsPage from './pages/ReportsPage'
import SettingsPage from './pages/SettingsPage'
import Layout from './components/Layout'
// import { invoke } from '@tauri-apps/api/tauri' // Will be used when needed

function App() {
  const [backendStarted, setBackendStarted] = useState(false)
  const [startupError, setStartupError] = useState<string | null>(null)
  const [isDesktopApp, setIsDesktopApp] = useState(false)

  useEffect(() => {
    // Desktop app - start backend automatically
    setIsDesktopApp(true)

    const startDesktopApp = async () => {
      try {
        console.log('🚀 Starting AI Bug Bounty Scanner Desktop App...')

        // Start the backend server using Tauri command
        try {
          const { invoke } = await import('@tauri-apps/api/tauri')
          console.log('🔧 Starting backend server...')

          // Execute the Python backend
          const backendResult = await invoke('start_backend')
          console.log('✅ Backend started:', backendResult)

          // Wait a moment for backend to initialize
          await new Promise(resolve => setTimeout(resolve, 2000))

        } catch (tauriError) {
          console.log('⚠️ Tauri command failed, trying direct backend check:', tauriError)
        }

        // Check if backend is running
        let attempts = 0
        const maxAttempts = 15

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

        setStartupError('Backend failed to start. Please check if Python and dependencies are installed.')
      } catch (error) {
        console.error('Desktop app startup error:', error)
        setStartupError(`Desktop app error: ${error}`)
      }
    }

    startDesktopApp()
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
              <li>Check if all security tools are installed (sqlmap, naabu, nuclei, etc.)</li>
              <li>Verify backend dependencies: pip install -r requirements.txt</li>
              <li>Try running manually: python run.py</li>
              <li>Check if antivirus is blocking the desktop app</li>
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
