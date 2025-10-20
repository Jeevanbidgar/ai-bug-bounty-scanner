import React from 'react'
import { Badge } from './ui/Badge'
import { ArrowUpCircle, CheckCircle, XCircle, AlertTriangle, Clock } from 'lucide-react'
import type { EnhancedVersionCheckResult, CoordinatedUpdateResult } from '../services/api'

interface UpdateStatusBadgeProps {
  result?: EnhancedVersionCheckResult | CoordinatedUpdateResult
  isLoading?: boolean
  className?: string
}

const UpdateStatusBadge: React.FC<UpdateStatusBadgeProps> = ({ 
  result, 
  isLoading = false, 
  className = '' 
}) => {
  if (isLoading) {
    return (
      <Badge className={`bg-blue-700 text-blue-100 ${className}`}>
        <Clock className="h-3 w-3 mr-1 animate-spin" />
        Checking...
      </Badge>
    )
  }

  if (!result) {
    return (
      <Badge className={`bg-gray-700 text-gray-100 ${className}`}>
        <XCircle className="h-3 w-3 mr-1" />
        Unknown
      </Badge>
    )
  }

  // Handle coordinated result
  if ('managers_checked' in result) {
    const coordinatedResult = result as CoordinatedUpdateResult
    
    if (coordinatedResult.has_update && coordinatedResult.best_result) {
      return <UpdateStatusBadge result={coordinatedResult.best_result} className={className} />
    }
    
    if (coordinatedResult.managers_checked === 0) {
      return (
        <Badge className={`bg-red-700 text-red-100 ${className}`}>
          <XCircle className="h-3 w-3 mr-1" />
          No managers available
        </Badge>
      )
    }
    
    return (
      <Badge className={`bg-green-700 text-green-100 ${className}`}>
        <CheckCircle className="h-3 w-3 mr-1" />
        Up to date
      </Badge>
    )
  }

  // Handle enhanced result
  const enhancedResult = result as EnhancedVersionCheckResult

  if (enhancedResult.error) {
    return (
      <Badge className={`bg-red-700 text-red-100 ${className}`}>
        <XCircle className="h-3 w-3 mr-1" />
        Error
      </Badge>
    )
  }

  if (enhancedResult.has_update) {
    const updateType = enhancedResult.update_type
    let badgeColor = 'bg-yellow-700 text-yellow-100'
    let icon = <ArrowUpCircle className="h-3 w-3 mr-1" />
    let label = 'Update available'

    switch (updateType) {
      case 'major':
        badgeColor = 'bg-red-700 text-red-100'
        label = 'Major update'
        break
      case 'minor':
        badgeColor = 'bg-orange-700 text-orange-100'
        label = 'Minor update'
        break
      case 'patch':
        badgeColor = 'bg-blue-700 text-blue-100'
        label = 'Patch update'
        break
      case 'prerelease':
        badgeColor = 'bg-purple-700 text-purple-100'
        label = 'Pre-release'
        break
    }

    return (
      <Badge className={`${badgeColor} ${className}`}>
        {icon}
        {label}
      </Badge>
    )
  }

  return (
    <Badge className={`bg-green-700 text-green-100 ${className}`}>
      <CheckCircle className="h-3 w-3 mr-1" />
      Up to date
    </Badge>
  )
}

export default UpdateStatusBadge
