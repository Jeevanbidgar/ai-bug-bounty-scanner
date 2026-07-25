import type { ExecutionTarget } from './ui'

export type WorkflowNodeKind = 'tool' | 'condition' | 'transform' | 'artifact-input' | 'report-output'

export interface WorkflowNode {
  id: string
  kind: WorkflowNodeKind
  label: string
  position: { x: number; y: number }
  executable?: string
  argv?: string[]
  parameters: Record<string, unknown>
}

export interface WorkflowEdge {
  id: string
  source: string
  target: string
  artifactContract?: string
}

export interface WorkflowDraft {
  id: string
  name: string
  baseWorkflowId?: string
  nodes: WorkflowNode[]
  edges: WorkflowEdge[]
  updatedAt: string
  imported: boolean
  quarantineReason?: string
}

export interface WorkflowRevision {
  id: string
  draftId: string
  revisionHash: string
  nodes: WorkflowNode[]
  edges: WorkflowEdge[]
  createdAt: string
  immutable: true
}

export interface WorkflowValidation {
  valid: boolean
  errors: string[]
  warnings: string[]
  missingTools: string[]
  incompatibleTargets: ExecutionTarget[]
}

export interface WorkflowTrust {
  revisionHash: string
  reviewedExecutableArgv: Array<{ executable: string; argv: string[] }>
  trustedAt: string
  revokedAt?: string
}

export interface RunnerProbe {
  target: ExecutionTarget
  available: boolean
  reason?: string
  requirements: string[]
}

export interface RunnerExecutionRequest {
  revisionHash: string
  executable: string
  argv: string[]
  environment: Record<string, string>
  workingDirectory: string
}

export interface RunnerExecutionHandle {
  executionId: string
  target: ExecutionTarget
}

export interface Runner {
  readonly target: ExecutionTarget
  probe(): Promise<RunnerProbe>
  prepare(request: RunnerExecutionRequest): Promise<void>
  execute(request: RunnerExecutionRequest): Promise<RunnerExecutionHandle>
  cancel(executionId: string): Promise<void>
  collectArtifacts(executionId: string): Promise<string[]>
}
