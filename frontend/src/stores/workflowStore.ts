import { addEdge, applyEdgeChanges, applyNodeChanges, type Connection, type Edge, type EdgeChange, type Node, type NodeChange } from '@xyflow/react'
import { create } from 'zustand'
import type { WorkflowStep, WorkflowTemplate } from '../services/api'

export interface WorkflowNodeData extends Record<string, unknown> {
  label: string
  description: string
  tool: string
  missing: boolean
  timeout?: number
}

export type WorkflowCanvasNode = Node<WorkflowNodeData, 'workflow'>
export type WorkflowCanvasEdge = Edge

interface Snapshot {
  nodes: WorkflowCanvasNode[]
  edges: WorkflowCanvasEdge[]
}

interface WorkflowEditorState {
  workflowId: string | null
  workflowName: string
  nodes: WorkflowCanvasNode[]
  edges: WorkflowCanvasEdge[]
  baseline: Snapshot
  past: Snapshot[]
  future: Snapshot[]
  dirty: boolean
  selectedNodeId: string | null
  loadWorkflow: (workflow: WorkflowTemplate & { steps?: WorkflowStep[] }) => void
  applyNodeChanges: (changes: NodeChange<WorkflowCanvasNode>[]) => void
  applyEdgeChanges: (changes: EdgeChange<WorkflowCanvasEdge>[]) => void
  captureSnapshot: () => void
  connect: (connection: Connection) => void
  selectNode: (nodeId: string | null) => void
  updateSelectedNode: (patch: Partial<WorkflowNodeData>) => void
  deleteSelectedNode: () => void
  undo: () => void
  redo: () => void
  reset: () => void
  restoreSnapshot: (snapshot: Snapshot) => void
  markSaved: () => void
}

const cloneSnapshot = (snapshot: Snapshot): Snapshot => ({
  nodes: snapshot.nodes.map((node) => ({ ...node, data: { ...node.data }, position: { ...node.position } })),
  edges: snapshot.edges.map((edge) => ({ ...edge })),
})

const layoutSteps = (steps: WorkflowStep[], missingTools: string[]): Snapshot => {
  const depth = new Map<string, number>()
  const byId = new Map(steps.map((step) => [step.id, step]))

  const getDepth = (step: WorkflowStep, visiting = new Set<string>()): number => {
    if (depth.has(step.id)) return depth.get(step.id) ?? 0
    if (visiting.has(step.id)) return 0
    visiting.add(step.id)
    const value = step.needs?.length
      ? Math.max(...step.needs.map((id) => byId.get(id)).filter(Boolean).map((dependency) => getDepth(dependency!, visiting))) + 1
      : 0
    depth.set(step.id, value)
    visiting.delete(step.id)
    return value
  }

  steps.forEach((step) => getDepth(step))
  const rowsByDepth = new Map<number, number>()
  const nodes: WorkflowCanvasNode[] = steps.map((step) => {
    const column = depth.get(step.id) ?? 0
    const row = rowsByDepth.get(column) ?? 0
    rowsByDepth.set(column, row + 1)
    const tool = step.run?.[0] ?? 'unknown'
    return {
      id: step.id,
      type: 'workflow',
      position: { x: 70 + column * 300, y: 80 + row * 190 },
      data: {
        label: step.name,
        description: step.description ?? 'No step description',
        tool,
        missing: missingTools.includes(tool),
        timeout: step.timeout,
      },
    }
  })

  const edges: WorkflowCanvasEdge[] = steps.flatMap((step) =>
    (step.needs ?? []).map((source) => ({
      id: `${source}-${step.id}`,
      source,
      target: step.id,
      animated: true,
      style: { stroke: '#22d3ee', strokeWidth: 1.5 },
    })),
  )

  return { nodes, edges }
}

export const useWorkflowStore = create<WorkflowEditorState>((set, get) => ({
  workflowId: null,
  workflowName: '',
  nodes: [],
  edges: [],
  baseline: { nodes: [], edges: [] },
  past: [],
  future: [],
  dirty: false,
  selectedNodeId: null,

  loadWorkflow: (workflow) => {
    const snapshot = layoutSteps(workflow.steps ?? [], workflow.compatibility?.missing_tools ?? [])
    set({
      workflowId: workflow.id,
      workflowName: workflow.name,
      ...cloneSnapshot(snapshot),
      baseline: cloneSnapshot(snapshot),
      past: [],
      future: [],
      dirty: false,
      selectedNodeId: snapshot.nodes[0]?.id ?? null,
    })
  },

  applyNodeChanges: (changes) => set((state) => {
    // React Flow emits dimension measurements while mounting and after responsive
    // layout changes. Those measurements are canvas metadata, not workflow edits.
    const changesWorkflow = changes.some((change) =>
      change.type === 'position' || change.type === 'add' || change.type === 'remove' || change.type === 'replace',
    )

    return {
      nodes: applyNodeChanges(changes, state.nodes),
      dirty: changesWorkflow ? true : state.dirty,
    }
  }),

  applyEdgeChanges: (changes) => set((state) => {
    const changesWorkflow = changes.some((change) =>
      change.type === 'add' || change.type === 'remove' || change.type === 'replace',
    )
    if (!changesWorkflow) return { edges: applyEdgeChanges(changes, state.edges) }
    const past = [...state.past, cloneSnapshot(state)].slice(-40)
    return { edges: applyEdgeChanges(changes, state.edges), past, future: [], dirty: true }
  }),

  captureSnapshot: () => {
    const state = get()
    set({ past: [...state.past, cloneSnapshot(state)].slice(-40), future: [] })
  },

  connect: (connection) => {
    const state = get()
    const past = [...state.past, cloneSnapshot(state)].slice(-40)
    set({
      edges: addEdge({ ...connection, animated: true, style: { stroke: '#22d3ee', strokeWidth: 1.5 } }, state.edges),
      past,
      future: [],
      dirty: true,
    })
  },

  selectNode: (selectedNodeId) => set({ selectedNodeId }),

  updateSelectedNode: (patch) => {
    const state = get()
    if (!state.selectedNodeId) return
    const past = [...state.past, cloneSnapshot(state)].slice(-40)
    set({
      nodes: state.nodes.map((node) => node.id === state.selectedNodeId ? { ...node, data: { ...node.data, ...patch } } : node),
      past,
      future: [],
      dirty: true,
    })
  },

  deleteSelectedNode: () => {
    const state = get()
    if (!state.selectedNodeId) return
    const past = [...state.past, cloneSnapshot(state)].slice(-40)
    set({
      nodes: state.nodes.filter((node) => node.id !== state.selectedNodeId),
      edges: state.edges.filter((edge) => edge.source !== state.selectedNodeId && edge.target !== state.selectedNodeId),
      selectedNodeId: null,
      past,
      future: [],
      dirty: true,
    })
  },

  undo: () => {
    const state = get()
    const previous = state.past.at(-1)
    if (!previous) return
    set({
      ...cloneSnapshot(previous),
      past: state.past.slice(0, -1),
      future: [cloneSnapshot(state), ...state.future].slice(0, 40),
      dirty: true,
    })
  },

  redo: () => {
    const state = get()
    const next = state.future[0]
    if (!next) return
    set({
      ...cloneSnapshot(next),
      past: [...state.past, cloneSnapshot(state)].slice(-40),
      future: state.future.slice(1),
      dirty: true,
    })
  },

  reset: () => {
    const state = get()
    set({ ...cloneSnapshot(state.baseline), past: [], future: [], dirty: false, selectedNodeId: state.baseline.nodes[0]?.id ?? null })
  },

  restoreSnapshot: (snapshot) => {
    const state = get()
    set({
      ...cloneSnapshot(snapshot),
      past: [...state.past, cloneSnapshot(state)].slice(-40),
      future: [],
      dirty: true,
      selectedNodeId: snapshot.nodes[0]?.id ?? null,
    })
  },

  markSaved: () => set({ dirty: false }),
}))
