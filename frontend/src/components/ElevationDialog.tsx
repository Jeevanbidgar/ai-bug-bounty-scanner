import { invoke } from '@tauri-apps/api/core'
import { useState } from 'react'

interface ElevationDialogProps {
  isOpen: boolean
  reason: string
  command: string
  onAllow: () => void
  onDeny: () => void
}

export function ElevationDialog({ isOpen, reason, command, onAllow, onDeny }: ElevationDialogProps) {
  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-gray-800 border border-yellow-600 rounded-lg shadow-2xl max-w-md w-full mx-4">
        {/* Header */}
        <div className="flex items-center gap-3 p-4 border-b border-gray-700">
          <div className="flex-shrink-0 w-12 h-12 flex items-center justify-center bg-yellow-600/20 rounded-full">
            <svg className="w-6 h-6 text-yellow-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <div>
            <h3 className="text-lg font-semibold text-white">Administrator Access Required</h3>
            <p className="text-sm text-gray-400">This action requires elevated privileges</p>
          </div>
        </div>

        {/* Content */}
        <div className="p-4 space-y-4">
          <div className="bg-gray-900/50 p-3 rounded border border-gray-700">
            <p className="text-sm font-medium text-gray-300 mb-1">Reason:</p>
            <p className="text-sm text-white">{reason}</p>
          </div>

          <div className="bg-gray-900/50 p-3 rounded border border-gray-700">
            <p className="text-sm font-medium text-gray-300 mb-1">Command:</p>
            <p className="text-xs text-gray-400 font-mono break-all">{command}</p>
          </div>

          <div className="flex items-start gap-2 p-3 bg-yellow-900/20 border border-yellow-700/50 rounded">
            <svg className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <div className="text-xs text-yellow-200">
              <p className="font-medium mb-1">Security Notice:</p>
              <ul className="list-disc list-inside space-y-0.5 text-yellow-300/80">
                <li>This will trigger a system elevation prompt (UAC/sudo)</li>
                <li>Only approve if you trust this action</li>
                <li>Your system password may be required</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex gap-3 p-4 border-t border-gray-700">
          <button
            onClick={onDeny}
            className="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-white font-medium transition-colors"
          >
            Deny
          </button>
          <button
            onClick={onAllow}
            className="flex-1 px-4 py-2 bg-yellow-600 hover:bg-yellow-700 rounded text-white font-medium transition-colors"
          >
            Allow Once
          </button>
        </div>
      </div>
    </div>
  )
}

interface ElevationMethod {
  WindowsUAC?: null
  LinuxPolkit?: null
  LinuxSudoAskpass?: null
  None?: null
}

interface ElevationResult {
  success: boolean
  output: string
  elevated: boolean
  error?: string
}

export function useElevation() {
  const [elevationMethod, setElevationMethod] = useState<ElevationMethod | null>(null)
  const [pendingElevation, setPendingElevation] = useState<{
    command: string
    args: string[]
    reason: string
    timeoutSecs: number
    resolve: (result: ElevationResult) => void
    reject: (error: string) => void
  } | null>(null)

  // Check elevation support on mount
  useState(() => {
    invoke<ElevationMethod>('check_elevation_support')
      .then(setElevationMethod)
      .catch(console.error)
  })

  const tryCommandWithElevation = async (
    command: string,
    args: string[],
    reason: string,
    timeoutSecs: number = 60
  ): Promise<ElevationResult> => {
    return new Promise((resolve, reject) => {
      // Try user-scope first
      invoke<ElevationResult>('try_command_with_elevation', {
        command,
        args,
        reason,
        timeoutSecs
      })
        .then(resolve)
        .catch((error: string) => {
          if (error.startsWith('ELEVATION_REQUIRED:')) {
            // Elevation needed - show dialog
            setPendingElevation({
              command: `${command} ${args.join(' ')}`,
              args,
              reason: error.replace('ELEVATION_REQUIRED: ', ''),
              timeoutSecs,
              resolve,
              reject
            })
          } else {
            reject(error)
          }
        })
    })
  }

  const handleElevationAllow = async () => {
    if (!pendingElevation) return

    const { command, args, timeoutSecs, resolve, reject } = pendingElevation
    setPendingElevation(null)

    try {
      const result = await invoke<ElevationResult>('execute_elevated_command', {
        command: command.split(' ')[0], // Extract base command
        args,
        timeoutSecs
      })
      resolve(result)
    } catch (error) {
      reject(String(error))
    }
  }

  const handleElevationDeny = () => {
    if (!pendingElevation) return

    const { reject } = pendingElevation
    setPendingElevation(null)
    reject('User denied elevation request')
  }

  return {
    elevationMethod,
    tryCommandWithElevation,
    pendingElevation,
    handleElevationAllow,
    handleElevationDeny,
    ElevationDialog: () => pendingElevation ? (
      <ElevationDialog
        isOpen={true}
        reason={pendingElevation.reason}
        command={pendingElevation.command}
        onAllow={handleElevationAllow}
        onDeny={handleElevationDeny}
      />
    ) : null
  }
}
