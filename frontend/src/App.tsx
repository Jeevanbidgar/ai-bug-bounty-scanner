import { Routes, Route } from 'react-router-dom'
import { lazy, Suspense, useEffect, useState } from 'react'
import Layout from './components/Layout'
import { ErrorBoundary } from './components/ErrorBoundary'
import { appBridge } from './bridge/appBridge'
import { PageTransition } from './components/PageTransition'
import { useNotificationStore } from './stores/notificationStore'

const Dashboard = lazy(() => import('./pages/Dashboard'))
const WorkflowsPage = lazy(() => import('./pages/WorkflowsPage'))
const ReadinessPage = lazy(() => import('./pages/ReadinessPage'))
const ScansPage = lazy(() => import('./pages/ScansPage'))
const ToolsPage = lazy(() => import('./pages/ToolsPage'))
const AdaptersPage = lazy(() => import('./pages/AdaptersPage'))
const ReportsPage = lazy(() => import('./pages/ReportsPage'))
const IntegrationsPage = lazy(() => import('./pages/IntegrationsPage'))
const SettingsPage = lazy(() => import('./pages/SettingsPage'))
const NotFoundPage = lazy(() => import('./pages/NotFoundPage'))

function App() {
  const [backendStarted, setBackendStarted] = useState(false)
  const [startupError, setStartupError] = useState<string | null>(null)
  const [isDesktopApp, setIsDesktopApp] = useState(false)
  const addNotification = useNotificationStore((state) => state.addNotification)

  useEffect(() => {
    // Check if we're in Tauri environment and try to connect to backend
    const initializeApp = async () => {
      try {
        // Check if we're in a Tauri environment (updated for Tauri 2.0)
        const isTauriEnv = appBridge.capabilities.desktop

        if (isTauriEnv) {
          setIsDesktopApp(true)
          try {
            await appBridge.invoke('get_system_info')
            setBackendStarted(true)
            addNotification({
              level: 'success',
              title: 'Native backend ready',
              message: 'Local execution, workflow history, and managed evidence are available.',
              dedupeKey: 'system:backend-ready',
            })
          } catch (tauriError) {
            console.error('❌ Failed to connect to Rust backend:', tauriError)
            setStartupError('Failed to connect to Rust backend. Please ensure the application is running correctly.')
            return
          }
        } else {
          setIsDesktopApp(false)
          setBackendStarted(true)
          addNotification({
            level: 'info',
            title: 'Preview environment active',
            message: 'Deterministic fixtures are loaded. Browser actions never execute security tools.',
            dedupeKey: 'system:preview-ready',
          })
        }
      } catch (error) {
        console.error('App initialization error:', error)
        setStartupError(error instanceof Error ? error.message : 'Unknown initialization error')
      }
    }

    initializeApp()
  }, [addNotification])

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
              <li>Verify UniHack can read and write its local application-data directory</li>
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
        <Suspense fallback={<RouteLoading />}>
          <PageTransition>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/workflows" element={<WorkflowsPage />} />
              <Route path="/readiness" element={<ReadinessPage />} />
              <Route path="/scans" element={<ScansPage />} />
              <Route path="/tools" element={<ToolsPage />} />
              <Route path="/adapters" element={<AdaptersPage />} />
              <Route path="/reports" element={<ReportsPage />} />
              <Route path="/integrations" element={<IntegrationsPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="*" element={<NotFoundPage />} />
            </Routes>
          </PageTransition>
        </Suspense>
      </Layout>
    </ErrorBoundary>
  )
}

const RouteLoading = () => (
  <div className="grid min-h-[60vh] place-items-center" role="status" aria-live="polite">
    <div className="text-center">
      <div className="mx-auto h-10 w-10 animate-spin rounded-full border-2 border-slate-700 border-t-cyan-300" />
      <p className="mt-4 text-sm text-slate-500">Loading operation module…</p>
    </div>
  </div>
)

export default App
