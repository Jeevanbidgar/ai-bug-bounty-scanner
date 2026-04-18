import { Routes, Route } from 'react-router-dom'
import { useEffect, useState } from 'react'
import Dashboard from './pages/Dashboard'
import ScansPage from './pages/ScansPage'
import ToolsPage from './pages/ToolsPage'
import AdaptersPage from './pages/AdaptersPage'
import ReportsPage from './pages/ReportsPage'
import SettingsPage from './pages/SettingsPage'
import Layout from './components/Layout'
import { ErrorBoundary } from './components/ErrorBoundary'

function App() {
  const [backendStarted, setBackendStarted] = useState(false)
  const [startupError, setStartupError] = useState<string | null>(null)
  const [isDesktopApp, setIsDesktopApp] = useState(false)

  useEffect(() => {
    // Check if we're in Tauri environment and try to connect to backend
    const initializeApp = async () => {
      try {
        // Check if we're in a Tauri environment (updated for Tauri 2.0)
        const isTauriEnv = typeof window !== 'undefined' &&
          ('__TAURI_INTERNALS__' in window || '__TAURI__' in window)

        console.log('🚀 App initialization started')
        console.log('Environment check:', {
          hasTauriInternals: '__TAURI_INTERNALS__' in window,
          hasTauri: '__TAURI__' in window,
          isTauriEnv
        })

        if (isTauriEnv) {
          setIsDesktopApp(true)
          console.log('🖥️ Running in Tauri desktop environment')

          // Try to connect to Rust backend via Tauri commands
          try {
            console.log('🔧 Testing Rust backend connection...')
            const { invoke } = await import('@tauri-apps/api/core')
            console.log('Tauri invoke imported successfully')

            // Test if we can call a simple Tauri command
            const health = await invoke('get_system_info')
            console.log('✅ Rust backend connected!', health)

            setBackendStarted(true)
          } catch (tauriError) {
            console.error('❌ Failed to connect to Rust backend:', tauriError)
            setStartupError('Failed to connect to Rust backend. Please ensure the application is running correctly.')
            return
          }
        } else {
          console.log('🌐 Running in web environment')
          setIsDesktopApp(false)
          setBackendStarted(true)
        }
      } catch (error) {
        console.error('App initialization error:', error)
        setStartupError(error instanceof Error ? error.message : 'Unknown initialization error')
      }
    }

    initializeApp()
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
              <li>Ensure the desktop app is properly installed</li>
              <li>Check if all security tools are installed (sqlmap, naabu, nuclei, etc.)</li>
              <li>Verify antivirus is not blocking the desktop app</li>
              <li>Try restarting the application</li>
              <li>Check the console for detailed error messages</li>
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
          <p className="text-lg">Starting UniHack...</p>
          <p className="text-sm text-gray-400 mt-2">
            {isDesktopApp ? 'Initializing backend services' : 'Connecting to backend...'}
          </p>
        </div>
      </div>
    )
  }

  return (
    <ErrorBoundary
      onError={(error, errorInfo) => {
        console.error('Application Error:', error, errorInfo)
        // In production, send to error tracking service
      }}
    >
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scans" element={<ScansPage />} />
          <Route path="/tools" element={<ToolsPage />} />
          <Route path="/adapters" element={<AdaptersPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </Layout>
    </ErrorBoundary>
  )
}

export default App
