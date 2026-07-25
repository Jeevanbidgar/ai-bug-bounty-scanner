export type VisualQuality = 'auto' | 'high' | 'balanced' | 'low'
export type MotionPreference = 'full' | 'reduced'

export interface UiPreferences {
  visualQuality: VisualQuality
  motion: MotionPreference
  immersiveVisuals: boolean
  highContrast: boolean
}

export interface AppCapabilities {
  desktop: boolean
  events: boolean
  filesystem: boolean
  mock: boolean
}

export type ExecutionTarget = 'native' | 'wsl' | 'container' | 'remote'

export interface TopologyNode {
  id: string
  label: string
  kind: 'host' | 'tool' | 'workflow' | 'finding' | 'artifact' | 'resource'
  status: 'ready' | 'running' | 'warning' | 'offline' | 'complete'
  detail: string
}
