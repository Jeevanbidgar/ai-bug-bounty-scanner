import React, { useState, useEffect, useRef } from 'react';
import { listen } from '@tauri-apps/api/event';
import { X, Terminal, Check, AlertCircle, Loader2, Minimize2, Maximize2 } from 'lucide-react';

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
  const [currentEventId, setCurrentEventId] = useState<string | null>(null);
  const [allowForceClose, setAllowForceClose] = useState(false);

  useEffect(() => {
    if (!isOpen) return;

    // Reset state when modal opens
    setStatus('installing');
    setOutputLines([]);
    setFinalMessage('');
    setCurrentEventId(null);
    setAllowForceClose(false);

    // Add timeout to allow force close after 5 minutes
    const forceCloseTimer = setTimeout(() => {
      setAllowForceClose(true);
    }, 5 * 60 * 1000); // 5 minutes

    // Listen for installation events
    const unlistenStart = listen('tool:installation_started', (event: any) => {
      console.log('📦 Installation started event:', event.payload);
      if (event.payload.tool_name === toolName) {
        setStatus('installing');
        setOutputLines([{
          type: 'stdout',
          line: `🚀 Starting ${event.payload.installation_method || event.payload.install_method || 'installation'}...`,
          timestamp: event.payload.timestamp
        }]);
      }
    });

    const unlistenOutput = listen('tool:installation_output', (event: any) => {
      console.log('📝 Installation output event:', event.payload);
      // New format from cargo/gem/npm/go installers: {event_id, output}
      // Accept all events (no tool_name filtering since backend doesn't send it)
      if (event.payload.output) {
        setOutputLines(prev => [...prev, {
          type: 'stdout',  // Backend doesn't distinguish, default to stdout
          line: event.payload.output,
          timestamp: new Date().toISOString()
        }]);
      } 
      // Legacy format from other installers: {tool_name, output_type, line, timestamp}
      else if (event.payload.tool_name === toolName && event.payload.line) {
        setOutputLines(prev => [...prev, {
          type: event.payload.output_type,
          line: event.payload.line,
          timestamp: event.payload.timestamp
        }]);
      }
    });

    const unlistenComplete = listen('tool:installation_completed', (event: any) => {
      console.log('✅ Installation completed event:', event.payload);
      if (event.payload.tool_name === toolName) {
        setStatus(event.payload.success ? 'completed' : 'failed');
        setFinalMessage(event.payload.message);
        setOutputLines(prev => [...prev, {
          type: event.payload.success ? 'stdout' : 'stderr',
          line: event.payload.message,
          timestamp: event.payload.timestamp
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
          <div className="text-sm text-gray-400">
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
