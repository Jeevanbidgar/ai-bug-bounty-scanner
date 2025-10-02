import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { AlertTriangle, Check, X, RefreshCw, Trash2 } from 'lucide-react';

interface PipxPathInfo {
  in_path: boolean;
  local_bin: string;
  multiple_installations: boolean;
  old_location?: string;
  new_location?: string;
  old_exists?: boolean;
  new_exists?: boolean;
}

export const PipxPathWarning: React.FC = () => {
  const [pathInfo, setPathInfo] = useState<PipxPathInfo | null>(null);
  const [isFixing, setIsFixing] = useState(false);
  const [isCleaning, setIsCleaning] = useState(false);
  const [showWarning, setShowWarning] = useState(true);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  useEffect(() => {
    checkPipxPath();
  }, []);

  const checkPipxPath = async () => {
    try {
      const info = await invoke<PipxPathInfo>('check_pipx_path');
      setPathInfo(info);
    } catch (error) {
      console.error('Failed to check pipx PATH:', error);
    }
  };

  const fixPath = async () => {
    setIsFixing(true);
    setMessage(null);
    try {
      const result = await invoke<string>('fix_pipx_path');
      setMessage({ type: 'success', text: result });
      // Recheck PATH status
      setTimeout(() => checkPipxPath(), 1000);
    } catch (error: any) {
      setMessage({ type: 'error', text: error.toString() });
    } finally {
      setIsFixing(false);
    }
  };

  const cleanupOldPipx = async () => {
    if (!confirm('This will uninstall all tools from the old pipx location and remove the directory. Continue?')) {
      return;
    }

    setIsCleaning(true);
    setMessage(null);
    try {
      const result = await invoke<string>('cleanup_old_pipx');
      setMessage({ type: 'success', text: result });
      // Recheck PATH status
      setTimeout(() => checkPipxPath(), 1000);
    } catch (error: any) {
      setMessage({ type: 'error', text: error.toString() });
    } finally {
      setIsCleaning(false);
    }
  };

  if (!pathInfo || (pathInfo.in_path && !pathInfo.multiple_installations) || !showWarning) {
    return null;
  }

  return (
    <div className="mb-6 bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
      <div className="flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
        <div className="flex-1">
          <h3 className="font-semibold text-yellow-500 mb-2">
            pipx Configuration Issue Detected
          </h3>
          
          {!pathInfo.in_path && (
            <div className="mb-3">
              <p className="text-sm text-gray-300 mb-2">
                The directory <code className="px-1 py-0.5 bg-gray-800 rounded text-xs">{pathInfo.local_bin}</code> is not in your system PATH.
                Tools installed via pipx won't be accessible until this is fixed.
              </p>
              <button
                onClick={fixPath}
                disabled={isFixing}
                className="flex items-center gap-2 px-4 py-2 bg-yellow-600 hover:bg-yellow-700 disabled:bg-gray-700 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors"
              >
                {isFixing ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Fixing PATH...</span>
                  </>
                ) : (
                  <>
                    <Check className="w-4 h-4" />
                    <span>Fix PATH Automatically</span>
                  </>
                )}
              </button>
            </div>
          )}

          {pathInfo.multiple_installations && (
            <div className="mb-3 pt-3 border-t border-yellow-500/30">
              <p className="text-sm text-gray-300 mb-2">
                Multiple pipx installations detected:
              </p>
              <ul className="text-xs text-gray-400 space-y-1 mb-3">
                {pathInfo.old_exists && (
                  <li className="flex items-center gap-2">
                    <span className="text-red-400">⚠️</span>
                    <span>Old location: <code className="px-1 py-0.5 bg-gray-800 rounded">{pathInfo.old_location}</code></span>
                  </li>
                )}
                {pathInfo.new_exists && (
                  <li className="flex items-center gap-2">
                    <span className="text-green-400">✅</span>
                    <span>Current location: <code className="px-1 py-0.5 bg-gray-800 rounded">{pathInfo.new_location}</code></span>
                  </li>
                )}
              </ul>
              <p className="text-sm text-gray-300 mb-2">
                Having multiple installations can cause conflicts. It's recommended to clean up the old installation.
              </p>
              <button
                onClick={cleanupOldPipx}
                disabled={isCleaning}
                className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-700 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors"
              >
                {isCleaning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Cleaning up...</span>
                  </>
                ) : (
                  <>
                    <Trash2 className="w-4 h-4" />
                    <span>Clean Up Old Installation</span>
                  </>
                )}
              </button>
            </div>
          )}

          {message && (
            <div className={`mt-3 p-3 rounded-lg text-sm ${
              message.type === 'success' 
                ? 'bg-green-500/20 border border-green-500/30 text-green-400'
                : 'bg-red-500/20 border border-red-500/30 text-red-400'
            }`}>
              <pre className="whitespace-pre-wrap font-mono text-xs">{message.text}</pre>
            </div>
          )}

          <div className="mt-3 pt-3 border-t border-yellow-500/30">
            <p className="text-xs text-gray-400">
              💡 <strong>Tip:</strong> After fixing these issues, restart your terminal and this app for changes to take effect.
            </p>
          </div>
        </div>

        <button
          onClick={() => setShowWarning(false)}
          className="p-1 hover:bg-yellow-500/20 rounded transition-colors flex-shrink-0"
          title="Dismiss warning"
        >
          <X className="w-4 h-4 text-yellow-500" />
        </button>
      </div>
    </div>
  );
};

export default PipxPathWarning;
