import React, { useState, useEffect, useRef } from 'react';
import { listen } from '@tauri-apps/api/event';
import { X, Terminal, Check, AlertCircle, Loader2 } from 'lucide-react';

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
  const outputEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isOpen) return;

    // Reset state when modal opens
    setStatus('installing');
    setOutputLines([]);
    setFinalMessage('');

    // Listen for installation events
    const unlistenStart = listen('tool:installation_started', (event: any) => {
      if (event.payload.tool_name === toolName) {
        setStatus('installing');
        setOutputLines([{
          type: 'stdout',
          line: `🚀 Starting ${event.payload.installation_method} installation...`,
          timestamp: event.payload.timestamp
        }]);
      }
    });

    const unlistenOutput = listen('tool:installation_output', (event: any) => {
      if (event.payload.tool_name === toolName) {
        setOutputLines(prev => [...prev, {
          type: event.payload.output_type,
          line: event.payload.line,
          timestamp: event.payload.timestamp
        }]);
      }
    });

    const unlistenComplete = listen('tool:installation_completed', (event: any) => {
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
          <button
            onClick={onClose}
            disabled={status === 'installing'}
            className={`p-1 rounded-lg transition-colors ${
              status === 'installing'
                ? 'text-gray-600 cursor-not-allowed'
                : 'text-gray-400 hover:text-white hover:bg-gray-700'
            }`}
            title={status === 'installing' ? 'Please wait for installation to complete' : 'Close'}
          >
            <X className="w-5 h-5" />
          </button>
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
              <span className="flex items-center gap-2">
                <Loader2 className="w-3 h-3 animate-spin" />
                Installation in progress... This may take 30-60 seconds.
              </span>
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
