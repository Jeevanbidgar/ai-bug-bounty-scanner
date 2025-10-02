import { invoke } from '@tauri-apps/api/tauri'
import { useState } from 'react'

interface PackageManager {
  manager_type: 'Go' | 'Pipx' | 'Apt' | 'WinGet'
  available: boolean
  version?: string
  path?: string
  error?: string
}

interface InstallationProgress {
  step: string
  output: string
  success: boolean
  requires_elevation: boolean
}

interface InstallationResult {
  success: boolean
  message: string
  steps: InstallationProgress[]
  requires_restart: boolean
}

export function PackageManagerTest() {
  const [managers, setManagers] = useState<PackageManager[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [installing, setInstalling] = useState<string | null>(null)
  const [installResult, setInstallResult] = useState<InstallationResult | null>(null)

  const detectManagers = async () => {
    setLoading(true)
    setError(null)
    setInstallResult(null)
    try {
      const result = await invoke<PackageManager[]>('detect_package_managers')
      console.log('Package managers detected:', result)
      setManagers(result)
    } catch (err) {
      console.error('Failed to detect package managers:', err)
      setError(String(err))
    } finally {
      setLoading(false)
    }
  }

  const installManager = async (managerType: string) => {
    setInstalling(managerType)
    setInstallResult(null)
    setError(null)
    
    try {
      let result: InstallationResult
      
      switch (managerType) {
        case 'Go':
          result = await invoke<InstallationResult>('install_package_manager_go')
          break
        case 'Pipx':
          result = await invoke<InstallationResult>('install_package_manager_pipx')
          break
        case 'Apt':
          // For APT, we'd need to specify which package, but for testing let's use golang-go
          result = await invoke<InstallationResult>('install_package_manager_apt', { packageName: 'golang-go' })
          break
        case 'WinGet':
          result = await invoke<InstallationResult>('install_package_manager_winget')
          break
        default:
          throw new Error(`Unknown manager type: ${managerType}`)
      }
      
      setInstallResult(result)
      
      // If successful and requires restart, show a message
      if (result.success && result.requires_restart) {
        console.log('Installation complete. Please restart your terminal.')
      }
    } catch (err) {
      console.error(`Failed to install ${managerType}:`, err)
      setError(String(err))
    } finally {
      setInstalling(null)
    }
  }

  const getBadgeColor = (type: string) => {
    switch (type) {
      case 'Go': return 'bg-green-500'
      case 'Pipx': return 'bg-yellow-500'
      case 'Apt': return 'bg-blue-500'
      case 'WinGet': return 'bg-blue-500'
      default: return 'bg-gray-500'
    }
  }

  return (
    <div className="p-6">
      <div className="mb-6">
        <h2 className="text-2xl font-bold mb-2">Package Manager Detection</h2>
        <p className="text-gray-400 mb-4">
          Test the package manager detection for Phase 1 implementation
        </p>
        
        <div className="flex gap-3">
          <button
            onClick={detectManagers}
            disabled={loading}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 rounded text-white font-medium transition-colors"
          >
            {loading ? 'Detecting...' : managers.length > 0 ? 'Refresh Detection' : 'Detect Package Managers'}
          </button>
          
          {managers.length > 0 && !loading && (
            <button
              onClick={() => {
                setManagers([])
                setError(null)
              }}
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-white font-medium transition-colors"
            >
              Clear Results
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="mb-4 p-4 bg-red-900/50 border border-red-600 rounded">
          <p className="text-red-200">Error: {error}</p>
        </div>
      )}

      {managers.length > 0 && (
        <div className="space-y-4">
          <h3 className="text-lg font-semibold">
            Detected Managers ({managers.filter(m => m.available).length}/{managers.length} available)
          </h3>
          
          <div className="grid gap-4">
            {managers.map((manager) => (
              <div
                key={manager.manager_type}
                className={`p-4 rounded border ${
                  manager.available
                    ? 'bg-green-900/20 border-green-600'
                    : 'bg-gray-800 border-gray-600'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    <span className={`px-3 py-1 rounded text-sm font-medium ${getBadgeColor(manager.manager_type)} text-white`}>
                      {manager.manager_type}
                    </span>
                    <span className={`text-lg ${manager.available ? 'text-green-400' : 'text-red-400'}`}>
                      {manager.available ? '✓' : '✗'}
                    </span>
                  </div>
                  
                  <div className="flex items-center gap-3">
                    {manager.version && (
                      <span className="text-sm text-gray-300">
                        v{manager.version}
                      </span>
                    )}
                    
                    {!manager.available && (
                      <button
                        onClick={() => installManager(manager.manager_type)}
                        disabled={installing === manager.manager_type}
                        className="px-3 py-1 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed rounded text-sm text-white font-medium transition-colors"
                      >
                        {installing === manager.manager_type ? 'Installing...' : 'Install'}
                      </button>
                    )}
                  </div>
                </div>
                
                {manager.error && !installing && (
                  <div className="mt-3 p-3 bg-gray-900/50 rounded border border-gray-700">
                    <p className="text-sm text-gray-300 font-medium mb-1">How to install:</p>
                    <p className="text-sm text-gray-400 whitespace-pre-wrap">
                      {manager.error}
                    </p>
                    {manager.manager_type === 'Apt' && (
                      <p className="text-xs text-yellow-400 mt-2">⚠ Requires sudo on Linux</p>
                    )}
                    {manager.manager_type === 'WinGet' && (
                      <p className="text-xs text-blue-400 mt-2">ℹ May trigger UAC prompt if required</p>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Summary */}
          <div className="mt-6 p-4 bg-blue-900/20 border border-blue-600 rounded">
            <h4 className="font-semibold mb-2">Summary:</h4>
            <ul className="space-y-1 text-sm">
              {managers.filter(m => m.available).map(m => (
                <li key={m.manager_type} className="text-green-400">
                  ✓ {m.manager_type} is available{m.version ? ` (v${m.version})` : ''}
                </li>
              ))}
              {managers.filter(m => !m.available).map(m => (
                <li key={m.manager_type} className="text-gray-400">
                  ✗ {m.manager_type} is not available
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Installation Result */}
      {installResult && (
        <div className={`mt-4 p-4 rounded border ${
          installResult.success
            ? 'bg-green-900/20 border-green-600'
            : 'bg-red-900/20 border-red-600'
        }`}>
          <div className="flex items-center justify-between mb-3">
            <h4 className="font-semibold">
              {installResult.success ? '✓ Installation Complete' : '✗ Installation Failed'}
            </h4>
            <button
              onClick={() => setInstallResult(null)}
              className="text-gray-400 hover:text-white"
            >
              ✕
            </button>
          </div>
          
          <p className="text-sm mb-3">{installResult.message}</p>
          
          {installResult.requires_restart && (
            <div className="mb-3 p-2 bg-yellow-900/30 border border-yellow-600 rounded">
              <p className="text-sm text-yellow-200">
                ⚠ Please restart your terminal for changes to take effect
              </p>
            </div>
          )}
          
          {installResult.steps.length > 0 && (
            <div className="space-y-2">
              <p className="text-sm font-medium">Installation Steps:</p>
              {installResult.steps.map((step, idx) => (
                <div
                  key={idx}
                  className={`p-2 rounded text-sm ${
                    step.success
                      ? 'bg-green-900/20 border border-green-700'
                      : 'bg-gray-800 border border-gray-600'
                  }`}
                >
                  <div className="flex items-start gap-2">
                    <span className={step.success ? 'text-green-400' : 'text-gray-400'}>
                      {step.success ? '✓' : '⋯'}
                    </span>
                    <div className="flex-1">
                      <p className="font-medium mb-1">{step.step}</p>
                      <p className="text-xs text-gray-400 whitespace-pre-wrap font-mono">
                        {step.output}
                      </p>
                      {step.requires_elevation && (
                        <p className="text-xs text-yellow-400 mt-1">
                          ⚠ May require administrator privileges
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
          
          {installResult.success && (
            <button
              onClick={detectManagers}
              className="mt-3 w-full px-3 py-2 bg-blue-600 hover:bg-blue-700 rounded text-sm text-white font-medium transition-colors"
            >
              Refresh Detection
            </button>
          )}
        </div>
      )}
    </div>
  )
}
