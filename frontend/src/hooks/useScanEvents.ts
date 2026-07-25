import { useEffect, useRef } from 'react';
import { appBridge } from '../bridge/appBridge';

type UnlistenFn = () => void;

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
  onScanCancelled?: (event: ScanEvent) => void;
  onProgressUpdate?: (event: ScanProgressEvent) => void;
  onError?: (event: ScanErrorEvent) => void;
}

export const useScanEvents = (handlers: ScanEventHandlers, scanId?: string) => {
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;

  useEffect(() => {
    const unlisteners: UnlistenFn[] = [];

    const setupListeners = async () => {
      if (handlersRef.current.onScanStarted) {
        const unlisten = await appBridge.listen<ScanEvent>('scan:started', (payload) => {
          if (!scanId || payload.scan_id === scanId) {
            handlersRef.current.onScanStarted?.(payload);
          }
        });
        unlisteners.push(unlisten);
      }

      if (handlersRef.current.onScanCompleted) {
        const unlisten = await appBridge.listen<ScanEvent>('scan:completed', (payload) => {
          if (!scanId || payload.scan_id === scanId) {
            handlersRef.current.onScanCompleted?.(payload);
          }
        });
        unlisteners.push(unlisten);
      }

      if (handlersRef.current.onScanFailed) {
        const unlisten = await appBridge.listen<ScanEvent>('scan:failed', (payload) => {
          if (!scanId || payload.scan_id === scanId) {
            handlersRef.current.onScanFailed?.(payload);
          }
        });
        unlisteners.push(unlisten);
      }

      if (handlersRef.current.onScanCancelled) {
        const unlisten = await appBridge.listen<ScanEvent>('scan:cancelled', (payload) => {
          if (!scanId || payload.scan_id === scanId) {
            handlersRef.current.onScanCancelled?.(payload);
          }
        });
        unlisteners.push(unlisten);
      }

      if (handlersRef.current.onProgressUpdate) {
        const unlisten = await appBridge.listen<ScanProgressEvent>('scan:progress_update', (payload) => {
          if (!scanId || payload.scan_id === scanId) {
            handlersRef.current.onProgressUpdate?.(payload);
          }
        });
        unlisteners.push(unlisten);
      }

      if (handlersRef.current.onError) {
        const unlisten = await appBridge.listen<ScanErrorEvent>('scan:error', (payload) => {
          if (!scanId || payload.scan_id === scanId) {
            handlersRef.current.onError?.(payload);
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
  }, [scanId]);
};
