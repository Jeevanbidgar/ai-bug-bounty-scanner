import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { MutationCache, QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './App.tsx'
import { ErrorBoundary } from './components/ErrorBoundary'
import './index.css'
import { useNotificationStore } from './stores/notificationStore'

// Create a client with better error handling
const queryClient = new QueryClient({
  mutationCache: new MutationCache({
    onError: (error) => {
      useNotificationStore.getState().addNotification({
        level: 'error',
        title: 'Action failed',
        message: error instanceof Error ? error.message : String(error),
      })
    },
  }),
  defaultOptions: {
    queries: {
      retry: 2, // Retry failed queries 2 times
      retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
      refetchOnWindowFocus: false,
      refetchOnMount: true,
      staleTime: 0, // Always consider data stale
      gcTime: 1000 * 60 * 5, // 5 minutes
      // Let errors propagate instead of silently failing
      throwOnError: false,
    },
    mutations: {
      retry: 1,
      // Individual screens and the global notification center surface failures.
      throwOnError: false,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <App />
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  </React.StrictMode>,
)
