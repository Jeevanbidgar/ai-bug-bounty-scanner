import { useEffect } from 'react';
import { listen, UnlistenFn } from '@tauri-apps/api/event';

interface ScanEvent {
  scan_id: string;
  timestamp: string;
}

interface ScanProgressEvent {
  scan_id: string;
  progress: number;
  current_test?: string;
  status: string;
  timestamp: string;
}

interface ScanErrorEvent {
  scan_id: string;
  error: string;
  severity: string;
  timestamp: string;
}

interface ScanEventHandlers {
  onScanStarted?: (event: ScanEvent) => void;
  onScanCompleted?: (event: ScanEvent) => void;
  onScanFailed?: (event: ScanEvent) => void;
  onProgressUpdate?: (event: ScanProgressEvent) => void;
  onError?: (event: ScanErrorEvent) => void;
}

export const useScanEvents = (handlers: ScanEventHandlers, scanId?: string) => {
  useEffect(() => {
    const unlisteners: UnlistenFn[] = [];

    const setupListeners = async () => {
      if (handlers.onScanStarted) {
        const unlisten = await listen('scan:started', (event) => {
          const payload = event.payload as ScanEvent;
          if (!scanId || payload.scan_id === scanId) {
            handlers.onScanStarted!(payload);
          }
        });
        unlisteners.push(unlisten);
      }

      if (handlers.onScanCompleted) {
        const unlisten = await listen('scan:completed', (event) => {
          const payload = event.payload as ScanEvent;
          if (!scanId || payload.scan_id === scanId) {
            handlers.onScanCompleted!(payload);
          }
        });
        unlisteners.push(unlisten);
      }

      if (handlers.onScanFailed) {
        const unlisten = await listen('scan:failed', (event) => {
          const payload = event.payload as ScanEvent;
          if (!scanId || payload.scan_id === scanId) {
            handlers.onScanFailed!(payload);
          }
        });
        unlisteners.push(unlisten);
      }

      if (handlers.onProgressUpdate) {
        const unlisten = await listen('scan:progress_update', (event) => {
          const payload = event.payload as ScanProgressEvent;
          if (!scanId || payload.scan_id === scanId) {
            handlers.onProgressUpdate!(payload);
          }
        });
        unlisteners.push(unlisten);
      }

      if (handlers.onError) {
        const unlisten = await listen('scan:error', (event) => {
          const payload = event.payload as ScanErrorEvent;
          if (!scanId || payload.scan_id === scanId) {
            handlers.onError!(payload);
          }
        });
        unlisteners.push(unlisten);
      }
    };

    setupListeners();

    // Cleanup on unmount
    return () => {
      unlisteners.forEach((unlisten) => unlisten());
    };
  }, [handlers, scanId]);
};
