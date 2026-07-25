import React, { useState, useEffect, useRef } from 'react';
import { X, Terminal, Check, AlertCircle, Loader2, Minimize2, Maximize2 } from 'lucide-react';
import { Badge } from './ui/Badge';
import apiService from '../services/api';
import { appBridge } from '../bridge/appBridge';

interface InstallationProgressModalProps {
  isOpen: boolean;
  toolName: string;
  onClose: () => void;
}

interface OutputLine {
  type: 'stdout' | 'stderr';
  line: string;
  timestamp: string;
}

interface InstallationInfo {
  name: string;
  install_method: string;
  go_module: string | null;
  pipx_package: string | null;
  apt_package: string | null;
  winget_id: string | null;
  description: string;
  category: string;
}

const INSTALL_METHOD_META: Record<string, { label: string; badgeClass: string; helperText?: string }> = {
  go: { label: 'Go Install', badgeClass: 'bg-emerald-700 text-emerald-100', helperText: 'Builds from source using go install' },
  'git-pip': { label: 'Git + Pip', badgeClass: 'bg-yellow-700 text-yellow-100', helperText: 'Clones repository and installs via pip' },
  pipx: { label: 'pipx', badgeClass: 'bg-sky-700 text-sky-100', helperText: 'Isolated Python environment via pipx' },
  apt: { label: 'APT', badgeClass: 'bg-blue-700 text-blue-100', helperText: 'Installs via Debian/Ubuntu package manager' },
  winget: { label: 'WinGet', badgeClass: 'bg-indigo-700 text-indigo-100', helperText: 'Installs via Windows package manager' },
  cargo: { label: 'Cargo', badgeClass: 'bg-orange-700 text-orange-100', helperText: 'Rust crate installation' },
  gem: { label: 'Ruby Gem', badgeClass: 'bg-rose-700 text-rose-100', helperText: 'Installs via gem' },
  npm: { label: 'npm', badgeClass: 'bg-red-700 text-red-100', helperText: 'Installs via Node package manager' },
  homebrew: { label: 'Homebrew', badgeClass: 'bg-amber-700 text-amber-100', helperText: 'Installs via brew' },
  manual: { label: 'Manual', badgeClass: 'bg-gray-700 text-gray-100', helperText: 'Manual steps required after install' },
  runtime: { label: 'Runtime', badgeClass: 'bg-slate-700 text-slate-100', helperText: 'Provided by runtime environment' },
};

const AUTO_INSTALL_METHODS = new Set(['go', 'git-pip', 'pipx', 'apt', 'winget', 'cargo', 'gem', 'npm', 'homebrew']);

const getMethodDetail = (info: InstallationInfo | null): string | null => {
  if (!info) return null;
  switch (info.install_method) {
    case 'go':
      return info.go_module ? `Module: ${info.go_module}` : null;
    case 'pipx':
      return info.pipx_package ? `Package: ${info.pipx_package}` : null;
    case 'apt':
      return info.apt_package ? `Package: ${info.apt_package}` : null;
    case 'winget':
      return info.winget_id ? `ID: ${info.winget_id}` : null;
    default:
      return null;
  }
};

export const InstallationProgressModal: React.FC<InstallationProgressModalProps> = ({
  isOpen,
  toolName,
  onClose,
}) => {
  const [status, setStatus] = useState<'installing' | 'completed' | 'failed'>('installing');
  const [outputLines, setOutputLines] = useState<OutputLine[]>([]);
  const [finalMessage, setFinalMessage] = useState<string>('');
  const [isMinimized, setIsMinimized] = useState(false);
  const outputEndRef = useRef<HTMLDivElement>(null);
  const [allowForceClose, setAllowForceClose] = useState(false);
  const [installationInfo, setInstallationInfo] = useState<InstallationInfo | null>(null);

  const methodMeta = installationInfo ? INSTALL_METHOD_META[installationInfo.install_method] : undefined;
  const methodLabel = methodMeta?.label ?? installationInfo?.install_method ?? 'Unknown';
  const methodDetailText = getMethodDetail(installationInfo);
  const isAutomatedInstall = installationInfo ? AUTO_INSTALL_METHODS.has(installationInfo.install_method) : false;

  useEffect(() => {
    if (!isOpen) {
      setInstallationInfo(null);
      return;
    }

    let active = true;
    (async () => {
      try {
        const info = await apiService.getToolInstallationInfo(toolName);
        if (!active) return;
        setInstallationInfo(info);
      } catch (error) {
        console.error('Failed to load installation info:', error);
        if (!active) return;
        setInstallationInfo(null);
      }
    })();

    return () => {
      active = false;
    };
  }, [isOpen, toolName]);

  useEffect(() => {
    if (!isOpen) return;

    // Reset state when modal opens
    setStatus('installing');
    setOutputLines([]);
    setFinalMessage('');
    setAllowForceClose(false);

    // Add timeout to allow force close after 5 minutes
    const forceCloseTimer = setTimeout(() => {
      setAllowForceClose(true);
    }, 5 * 60 * 1000); // 5 minutes

    // Listen for installation events
    const unlistenStart = appBridge.listen<any>('tool:installation_started', (payload) => {
      if (payload.tool_name === toolName) {
        setStatus('installing');
        setOutputLines([{
          type: 'stdout',
          line: `Starting ${payload.installation_method || payload.install_method || 'installation'}...`,
          timestamp: payload.timestamp
        }]);
      }
    });

    const unlistenOutput = appBridge.listen<any>('tool:installation_output', (payload) => {
      if (payload.tool_name === toolName && payload.line) {
        setOutputLines(prev => [...prev, {
          type: payload.output_type,
          line: payload.line,
          timestamp: payload.timestamp
        }]);
      }
    });

    const unlistenComplete = appBridge.listen<any>('tool:installation_completed', (payload) => {
      if (payload.tool_name === toolName) {
        setStatus(payload.success ? 'completed' : 'failed');
        setFinalMessage(payload.message);
        setOutputLines(prev => [...prev, {
          type: payload.success ? 'stdout' : 'stderr',
          line: payload.message,
          timestamp: payload.timestamp
        }]);
      }
    });

    return () => {
      clearTimeout(forceCloseTimer);
      unlistenStart.then(fn => fn());
      unlistenOutput.then(fn => fn());
      unlistenComplete.then(fn => fn());
    };
  }, [isOpen, toolName]);

  // Auto-scroll to bottom when new output arrives
  useEffect(() => {
    outputEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [outputLines]);

  if (!isOpen) return null;

  // Minimized view (bottom-right corner)
  if (isMinimized) {
    return (
      <div className="fixed bottom-4 right-4 z-50">
        <div className="bg-gray-900 border border-gray-700 rounded-lg shadow-2xl p-4 min-w-[320px]">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-3 flex-1">
              <Terminal className="w-5 h-5 text-blue-400 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <h3 className="text-sm font-semibold text-white truncate">
                  Installing {toolName}
                </h3>
                {status === 'installing' && (
                  <div className="flex items-center gap-2 text-xs text-gray-400 mt-1">
                    <Loader2 className="w-3 h-3 animate-spin" />
                    <span>{outputLines.length} lines...</span>
                  </div>
                )}
                {status === 'completed' && (
                  <div className="flex items-center gap-1 text-xs text-green-400 mt-1">
                    <Check className="w-3 h-3" />
                    <span>Completed</span>
                  </div>
                )}
                {status === 'failed' && (
                  <div className="flex items-center gap-1 text-xs text-red-400 mt-1">
                    <AlertCircle className="w-3 h-3" />
                    <span>Failed</span>
                  </div>
                )}
              </div>
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setIsMinimized(false)}
                className="p-1 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
                title="Maximize"
              >
                <Maximize2 className="w-4 h-4" />
              </button>
              {status !== 'installing' && (
                <button
                  onClick={onClose}
                  className="p-1 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
                  title="Close"
                >
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Full modal view
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-gray-900 border border-gray-700 rounded-lg shadow-2xl w-full max-w-4xl max-h-[80vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700">
          <div className="flex items-center gap-3">
            <Terminal className="w-5 h-5 text-blue-400" />
            <h2 className="text-lg font-semibold text-white">
              Installing {toolName}
            </h2>
            {installationInfo && (
              <Badge className={`${methodMeta?.badgeClass ?? 'bg-gray-700 text-gray-100'} text-xs px-2 py-0.5`}>
                {methodLabel}
              </Badge>
            )}
            {status === 'installing' && (
              <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />
            )}
            {status === 'completed' && (
              <div className="flex items-center gap-1 px-2 py-1 bg-green-500/20 rounded text-green-400 text-xs font-medium">
                <Check className="w-3 h-3" />
                <span>Completed</span>
              </div>
            )}
            {status === 'failed' && (
              <div className="flex items-center gap-1 px-2 py-1 bg-red-500/20 rounded text-red-400 text-xs font-medium">
                <AlertCircle className="w-3 h-3" />
                <span>Failed</span>
              </div>
            )}
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setIsMinimized(true)}
              className="p-1 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
              title="Minimize"
            >
              <Minimize2 className="w-5 h-5" />
            </button>
            <button
              onClick={onClose}
              disabled={status === 'installing' && !allowForceClose}
              className={`p-1 rounded-lg transition-colors ${
                status === 'installing' && !allowForceClose
                  ? 'text-gray-600 cursor-not-allowed'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700'
              }`}
              title={
                status === 'installing' && !allowForceClose
                  ? 'Please wait for installation to complete'
                  : status === 'installing' && allowForceClose
                  ? 'Force close (installation is taking longer than expected)'
                  : 'Close'
              }
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {finalMessage && status !== 'installing' && (
          <div className={`mx-6 mt-4 rounded border p-3 text-sm ${
            status === 'completed'
              ? 'border-green-700 bg-green-950/40 text-green-200'
              : 'border-red-700 bg-red-950/40 text-red-200'
          }`}>
            {finalMessage}
          </div>
        )}

        {/* Output Terminal */}
        <div className="flex-1 overflow-auto bg-black p-4 font-mono text-sm">
          <div className="space-y-1">
            {outputLines.map((line, index) => (
              <div
                key={index}
                className={`whitespace-pre-wrap break-words ${
                  line.type === 'stderr' ? 'text-yellow-400' : 'text-green-400'
                }`}
              >
                <span className="text-gray-500 select-none">
                  {new Date(line.timestamp).toLocaleTimeString()} |{' '}
                </span>
                {line.line}
              </div>
            ))}
            {outputLines.length === 0 && status === 'installing' && (
              <div className="text-gray-500 flex items-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Waiting for installation to start...</span>
              </div>
            )}
            <div ref={outputEndRef} />
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-gray-700 flex items-center justify-between">
          <div className="flex flex-col gap-2 text-sm text-gray-400">
            {installationInfo && (
              <div className="flex flex-wrap items-center gap-2 text-xs text-gray-400">
                <span className="font-medium text-gray-300">Method:</span>
                <span>{methodLabel}</span>
                {methodDetailText && <span className="text-gray-500">({methodDetailText})</span>}
                {methodMeta?.helperText && (
                  <span className="text-gray-500">{methodMeta.helperText}</span>
                )}
                {!isAutomatedInstall && (
                  <span className="text-yellow-400">Manual follow-up steps required</span>
                )}
              </div>
            )}
            {status === 'installing' && (
              <div className="flex flex-col gap-1">
                <span className="flex items-center gap-2">
                  <Loader2 className="w-3 h-3 animate-spin" />
                  Installation in progress... This may take 30-60 seconds.
                </span>
                {allowForceClose && (
                  <span className="text-yellow-400 text-xs">
                    ⚠️ Taking longer than expected. You can force close if needed.
                  </span>
                )}
              </div>
            )}
            {status === 'completed' && (
              <span className="text-green-400">
                ✅ Installation completed successfully!
              </span>
            )}
            {status === 'failed' && (
              <span className="text-red-400">
                ❌ Installation failed. Check the output above for details.
              </span>
            )}
          </div>
          <button
            onClick={onClose}
            disabled={status === 'installing'}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              status === 'installing'
                ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                : status === 'completed'
                ? 'bg-green-600 hover:bg-green-700 text-white'
                : 'bg-gray-700 hover:bg-gray-600 text-white'
            }`}
          >
            {status === 'installing' ? 'Installing...' : 'Close'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default InstallationProgressModal;
