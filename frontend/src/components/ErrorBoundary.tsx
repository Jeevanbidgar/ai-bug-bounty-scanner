import React, { Component, ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from './ui/Card'
import { Button } from './ui/Button'

interface Props {
  children: ReactNode
  fallback?: ReactNode
  onError?: (error: Error, errorInfo: React.ErrorInfo) => void
}

interface State {
  hasError: boolean
  error: Error | null
  errorInfo: React.ErrorInfo | null
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null
    }
  }

  static getDerivedStateFromError(error: Error): State {
    return {
      hasError: true,
      error,
      errorInfo: null
    }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo)
    this.setState({
      error,
      errorInfo
    })
    
    // Call custom error handler if provided
    if (this.props.onError) {
      this.props.onError(error, errorInfo)
    }
  }

  handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null
    })
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback
      }

      return (
        <div className="flex items-center justify-center min-h-screen bg-gray-900 p-4">
          <Card className="max-w-2xl w-full bg-gray-800 border-red-500">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-red-400">
                <AlertTriangle className="h-6 w-6" />
                Something went wrong
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="bg-gray-900 p-4 rounded-lg">
                <p className="text-red-300 font-semibold mb-2">Error:</p>
                <p className="text-gray-300 font-mono text-sm">
                  {this.state.error?.message || 'Unknown error'}
                </p>
              </div>

              {this.state.errorInfo && (
                <details className="bg-gray-900 p-4 rounded-lg">
                  <summary className="text-gray-400 cursor-pointer hover:text-gray-300">
                    Error Details (Click to expand)
                  </summary>
                  <pre className="text-xs text-gray-400 mt-2 overflow-auto max-h-64">
                    {this.state.errorInfo.componentStack}
                  </pre>
                </details>
              )}

              <div className="flex gap-2">
                <Button 
                  onClick={this.handleReset}
                  variant="outline"
                  className="flex-1"
                >
                  Try Again
                </Button>
                <Button 
                  onClick={() => window.location.reload()}
                  className="flex-1 bg-blue-600 hover:bg-blue-700"
                >
                  Reload App
                </Button>
              </div>

              <p className="text-sm text-gray-400">
                If this error persists, please check the console (F12) for more details
                or contact support.
              </p>
            </CardContent>
          </Card>
        </div>
      )
    }

    return this.props.children
  }
}

// Hook-based error fallback component
export const ErrorFallback: React.FC<{ error: Error; resetError?: () => void }> = ({ 
  error, 
  resetError 
}) => {
  return (
    <div className="flex items-center justify-center p-8">
      <Card className="max-w-lg w-full bg-gray-800 border-red-500">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-red-400">
            <AlertTriangle className="h-5 w-5" />
            Error Loading Data
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="bg-gray-900 p-3 rounded-lg">
            <p className="text-sm text-gray-300 font-mono">
              {error.message}
            </p>
          </div>

          {resetError && (
            <Button 
              onClick={resetError}
              variant="outline"
              className="w-full"
            >
              Try Again
            </Button>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
