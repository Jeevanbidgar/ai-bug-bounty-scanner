import React, { useState, useEffect } from 'react'
import { Card } from './ui/Card'
import { Button } from './ui/Button'
import { Badge } from './ui/Badge'
import { apiService } from '../services/api'

interface TelemetrySummary {
  total_events: number
  update_checks_started: number
  update_checks_completed: number
  manager_checks_started: number
  manager_checks_completed: number
  commands_executed: number
  cache_hits: number
  cache_misses: number
  errors: number
  total_duration: number
  average_duration: number
  success_rate: number
  error_rate: number
}

interface TelemetryEvent {
  type: string
  package_name?: string
  manager?: string
  duration?: number
  success?: boolean
  has_update?: boolean
  error?: string
  timestamp: string
}

interface TelemetryData {
  summary: TelemetrySummary
  recent_events: TelemetryEvent[]
  events_json: string
}

export const TelemetryDebugView: React.FC = () => {
  const [telemetryData, setTelemetryData] = useState<TelemetryData | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showRawJson, setShowRawJson] = useState(false)

  const loadTelemetryData = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await apiService.getUpdateCheckerTelemetry()
      setTelemetryData(data as TelemetryData)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load telemetry data')
    } finally {
      setLoading(false)
    }
  }

  const clearTelemetry = async () => {
    setLoading(true)
    setError(null)
    try {
      await apiService.clearUpdateCheckerTelemetry()
      setTelemetryData(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to clear telemetry data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadTelemetryData()
  }, [])

  const formatDuration = (ms: number) => {
    if (ms < 1000) {
      return `${ms.toFixed(0)}ms`
    }
    return `${(ms / 1000).toFixed(2)}s`
  }

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString()
  }

  const getEventIcon = (eventType: string) => {
    switch (eventType) {
      case 'UpdateCheckStarted':
        return '🔍'
      case 'UpdateCheckCompleted':
        return '✅'
      case 'ManagerCheckStarted':
        return '🔄'
      case 'ManagerCheckCompleted':
        return '📊'
      case 'CommandExecuted':
        return '⚡'
      case 'CacheHit':
        return '💾'
      case 'CacheMiss':
        return '❌'
      case 'ErrorOccurred':
        return '🚨'
      default:
        return '📝'
    }
  }

  const getEventColor = (eventType: string) => {
    switch (eventType) {
      case 'UpdateCheckStarted':
        return 'bg-blue-100 text-blue-800'
      case 'UpdateCheckCompleted':
        return 'bg-green-100 text-green-800'
      case 'ManagerCheckStarted':
        return 'bg-yellow-100 text-yellow-800'
      case 'ManagerCheckCompleted':
        return 'bg-purple-100 text-purple-800'
      case 'CommandExecuted':
        return 'bg-orange-100 text-orange-800'
      case 'CacheHit':
        return 'bg-green-100 text-green-800'
      case 'CacheMiss':
        return 'bg-red-100 text-red-800'
      case 'ErrorOccurred':
        return 'bg-red-100 text-red-800'
      default:
        return 'bg-gray-100 text-gray-800'
    }
  }

  if (loading && !telemetryData) {
    return (
      <Card className="p-6">
        <div className="flex items-center justify-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          <span className="ml-2">Loading telemetry data...</span>
        </div>
      </Card>
    )
  }

  if (error) {
    return (
      <Card className="p-6">
        <div className="text-red-600 mb-4">
          <h3 className="font-semibold">Error</h3>
          <p>{error}</p>
        </div>
        <Button onClick={loadTelemetryData} disabled={loading}>
          Retry
        </Button>
      </Card>
    )
  }

  if (!telemetryData) {
    return (
      <Card className="p-6">
        <div className="text-center">
          <h3 className="font-semibold mb-2">No Telemetry Data</h3>
          <p className="text-gray-600 mb-4">
            No telemetry data available. Run some update checks to see telemetry information.
          </p>
          <Button onClick={loadTelemetryData} disabled={loading}>
            Refresh
          </Button>
        </div>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {/* Summary Card */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">Telemetry Summary</h3>
          <div className="flex space-x-2">
            <Button onClick={loadTelemetryData} disabled={loading} variant="outline">
              Refresh
            </Button>
            <Button onClick={clearTelemetry} disabled={loading} variant="outline">
              Clear
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-600">{telemetryData.summary.total_events}</div>
            <div className="text-sm text-gray-600">Total Events</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-green-600">{telemetryData.summary.update_checks_completed}</div>
            <div className="text-sm text-gray-600">Update Checks</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-purple-600">{telemetryData.summary.commands_executed}</div>
            <div className="text-sm text-gray-600">Commands</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-orange-600">{telemetryData.summary.cache_hits}</div>
            <div className="text-sm text-gray-600">Cache Hits</div>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center">
            <div className="text-lg font-semibold text-red-600">{telemetryData.summary.errors}</div>
            <div className="text-sm text-gray-600">Errors</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-semibold text-blue-600">
              {formatDuration(telemetryData.summary.total_duration)}
            </div>
            <div className="text-sm text-gray-600">Total Duration</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-semibold text-green-600">
              {formatDuration(telemetryData.summary.average_duration)}
            </div>
            <div className="text-sm text-gray-600">Avg Duration</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-semibold text-purple-600">
              {(telemetryData.summary.success_rate * 100).toFixed(1)}%
            </div>
            <div className="text-sm text-gray-600">Success Rate</div>
          </div>
        </div>
      </Card>

      {/* Recent Events */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">Recent Events</h3>
          <Button
            onClick={() => setShowRawJson(!showRawJson)}
            variant="outline"
            size="sm"
          >
            {showRawJson ? 'Hide' : 'Show'} Raw JSON
          </Button>
        </div>

        {showRawJson ? (
          <pre className="bg-gray-100 p-4 rounded text-sm overflow-auto max-h-96">
            {telemetryData.events_json}
          </pre>
        ) : (
          <div className="space-y-2 max-h-96 overflow-auto">
            {telemetryData.recent_events.map((event, index) => (
              <div key={index} className="flex items-center space-x-3 p-3 bg-gray-50 rounded">
                <span className="text-lg">{getEventIcon(event.type)}</span>
                <div className="flex-1">
                  <div className="flex items-center space-x-2">
                    <Badge className={getEventColor(event.type)}>
                      {event.type}
                    </Badge>
                    {event.package_name && (
                      <span className="text-sm font-medium">{event.package_name}</span>
                    )}
                    {event.manager && (
                      <span className="text-sm text-gray-600">({event.manager})</span>
                    )}
                  </div>
                  <div className="text-xs text-gray-500 mt-1">
                    {formatTimestamp(event.timestamp)}
                    {event.duration && (
                      <span className="ml-2">
                        Duration: {formatDuration(event.duration)}
                      </span>
                    )}
                    {event.success !== undefined && (
                      <span className="ml-2">
                        Success: {event.success ? '✅' : '❌'}
                      </span>
                    )}
                    {event.has_update !== undefined && (
                      <span className="ml-2">
                        Update: {event.has_update ? 'Available' : 'Up to date'}
                      </span>
                    )}
                  </div>
                  {event.error && (
                    <div className="text-xs text-red-600 mt-1">
                      Error: {event.error}
                    </div>
                  )}
                </div>
              </div>
            ))}
            {telemetryData.recent_events.length === 0 && (
              <div className="text-center text-gray-500 py-8">
                No recent events
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  )
}
