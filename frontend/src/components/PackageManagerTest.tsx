import { invoke } from '@tauri-apps/api/tauri'
import { useState } from 'react'

interface PackageManager {
  manager_type: 'Go' | 'Pipx' | 'Apt' | 'WinGet'
  available: boolean
  version?: string
  path?: string
  error?: string
}

export function PackageManagerTest() {
  const [managers, setManagers] = useState<PackageManager[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const detectManagers = async () => {
    setLoading(true)
    setError(null)
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
        
        <button
          onClick={detectManagers}
          disabled={loading}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 rounded text-white font-medium"
        >
          {loading ? 'Detecting...' : 'Detect Package Managers'}
        </button>
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
                  
                  {manager.version && (
                    <span className="text-sm text-gray-300">
                      v{manager.version}
                    </span>
                  )}
                </div>
                
                {manager.error && (
                  <p className="text-sm text-gray-400 mt-2">
                    {manager.error}
                  </p>
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
    </div>
  )
}
