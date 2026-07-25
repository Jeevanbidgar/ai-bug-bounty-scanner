import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  ReactFlow,
  type Connection,
  type EdgeChange,
  type NodeChange,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import {
  Box,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Clock3,
  Code2,
  GitBranch,
  History,
  Loader2,
  LockKeyhole,
  Play,
  Redo2,
  RotateCcw,
  Save,
  Search,
  ShieldCheck,
  Trash2,
  Undo2,
  Workflow,
} from 'lucide-react'
import apiService, { type WorkflowStep, type WorkflowTemplate } from '../services/api'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { Input } from '../components/ui/Input'
import WorkflowNodeCard from '../components/workflows/WorkflowNodeCard'
import { useWorkflowStore, type WorkflowCanvasEdge, type WorkflowCanvasNode } from '../stores/workflowStore'
import { getTargetPlaceholder, getWorkflowCatalogEntry, workflowActivityStyles } from '../data/workflowCatalog'
import { useNotificationStore } from '../stores/notificationStore'

const WorkflowTopologyPreview = lazy(() => import('../components/workflows/WorkflowTopologyPreview'))
const nodeTypes = { workflow: WorkflowNodeCard }

interface DraftRevision {
  id: string
  workflowId: string
  createdAt: string
  nodes: WorkflowCanvasNode[]
  edges: WorkflowCanvasEdge[]
  trust: 'draft'
}

const DRAFT_STORAGE_KEY = 'unihack-workflow-draft-revisions'

const readDraftRevisions = (): DraftRevision[] => {
  try {
    const value = localStorage.getItem(DRAFT_STORAGE_KEY)
    return value ? JSON.parse(value) as DraftRevision[] : []
  } catch {
    return []
  }
}

const hasCycle = (nodes: WorkflowCanvasNode[], edges: WorkflowCanvasEdge[]) => {
  const adjacency = new Map(nodes.map((node) => [node.id, [] as string[]]))
  edges.forEach((edge) => adjacency.get(edge.source)?.push(edge.target))
  const visiting = new Set<string>()
  const visited = new Set<string>()

  const visit = (id: string): boolean => {
    if (visiting.has(id)) return true
    if (visited.has(id)) return false
    visiting.add(id)
    if ((adjacency.get(id) ?? []).some(visit)) return true
    visiting.delete(id)
    visited.add(id)
    return false
  }

  return nodes.some((node) => visit(node.id))
}

const graphContract = (nodes: WorkflowCanvasNode[], edges: WorkflowCanvasEdge[]) => JSON.stringify({
  nodes: nodes.map((node) => ({ id: node.id, position: node.position, data: node.data })),
  edges: edges.map((edge) => ({ id: edge.id, source: edge.source, target: edge.target })),
})

const WorkflowsPage = () => {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [selectedTemplateId, setSelectedTemplateId] = useState(() => searchParams.get('workflow') ?? '')
  const [librarySearch, setLibrarySearch] = useState('')
  const [mode, setMode] = useState<'design' | 'preview'>('design')
  const [target, setTarget] = useState('')
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false)
  const [revisions, setRevisions] = useState<DraftRevision[]>(readDraftRevisions)
  const loadedWorkflowId = useRef<string | null>(null)
  const addNotification = useNotificationStore((state) => state.addNotification)

  const editor = useWorkflowStore()
  const selectedNode = editor.nodes.find((node) => node.id === editor.selectedNodeId) ?? null

  const templatesQuery = useQuery({
    queryKey: ['workflow-templates'],
    queryFn: async () => (await apiService.getWorkflowTemplates(true)).data as WorkflowTemplate[],
  })

  const detailsQuery = useQuery({
    queryKey: ['workflow-details', selectedTemplateId],
    queryFn: async () => (await apiService.getWorkflowDetails(selectedTemplateId)).data as WorkflowTemplate & { steps: WorkflowStep[] },
    enabled: Boolean(selectedTemplateId),
  })

  useEffect(() => {
    if (!templatesQuery.data?.length) return
    if (!selectedTemplateId || !templatesQuery.data.some((workflow) => workflow.id === selectedTemplateId)) {
      const fallbackId = templatesQuery.data[0].id
      setSelectedTemplateId(fallbackId)
      setSearchParams({ workflow: fallbackId }, { replace: true })
      loadedWorkflowId.current = null
    }
  }, [selectedTemplateId, setSearchParams, templatesQuery.data])

  useEffect(() => {
    if (!detailsQuery.data || loadedWorkflowId.current === detailsQuery.data.id) return
    const summary = templatesQuery.data?.find((workflow) => workflow.id === detailsQuery.data.id)
    editor.loadWorkflow({ ...detailsQuery.data, compatibility: summary?.compatibility })
    loadedWorkflowId.current = detailsQuery.data.id
  }, [detailsQuery.data, editor, templatesQuery.data])

  const cycle = useMemo(() => hasCycle(editor.nodes, editor.edges), [editor.edges, editor.nodes])
  const modifiedFromPackage = useMemo(
    () => graphContract(editor.nodes, editor.edges) !== graphContract(editor.baseline.nodes, editor.baseline.edges),
    [editor.baseline.edges, editor.baseline.nodes, editor.edges, editor.nodes],
  )
  const missingTools = editor.nodes.filter((node) => node.data.missing)
  const danglingEdges = editor.edges.filter((edge) => !editor.nodes.some((node) => node.id === edge.source) || !editor.nodes.some((node) => node.id === edge.target))
  const validationErrors = [
    editor.nodes.length === 0 ? 'Workflow contains no executable steps.' : null,
    cycle ? 'Dependency cycle detected. The Rust DAG runner will reject this graph.' : null,
    danglingEdges.length ? 'One or more dependencies reference a missing step.' : null,
    missingTools.length ? `${missingTools.length} required tool${missingTools.length === 1 ? ' is' : 's are'} unavailable on this host.` : null,
  ].filter(Boolean) as string[]

  const currentTemplate = templatesQuery.data?.find((workflow) => workflow.id === selectedTemplateId)
  const currentMetadata = currentTemplate ? getWorkflowCatalogEntry(currentTemplate) : null
  const filteredTemplates = useMemo(() => {
    const search = librarySearch.trim().toLowerCase()
    return (templatesQuery.data ?? []).filter((workflow) => !search || [
      workflow.name,
      workflow.description,
      workflow.category,
      getWorkflowCatalogEntry(workflow).intent,
    ].some((value) => value.toLowerCase().includes(search)))
  }, [librarySearch, templatesQuery.data])
  const templateRevisions = revisions.filter((revision) => revision.workflowId === selectedTemplateId)

  const executeWorkflow = useMutation({
    mutationFn: () => apiService.executeWorkflow(selectedTemplateId, { target: target.trim() }, { authorizationConfirmed }),
    onSuccess: () => navigate('/scans'),
  })

  const saveDraft = () => {
    if (!editor.workflowId) return
    const revision: DraftRevision = {
      id: crypto.randomUUID?.() ?? `${Date.now()}`,
      workflowId: editor.workflowId,
      createdAt: new Date().toISOString(),
      nodes: editor.nodes,
      edges: editor.edges,
      trust: 'draft',
    }
    const next = [revision, ...revisions].slice(0, 80)
    localStorage.setItem(DRAFT_STORAGE_KEY, JSON.stringify(next))
    setRevisions(next)
    editor.markSaved()
    addNotification({
      level: 'success',
      title: 'Draft revision saved',
      message: `${editor.workflowName} was stored locally as an untrusted draft. Reset to the packaged graph before execution.`,
      href: '/workflows',
      actionLabel: 'Open draft',
    })
  }

  const restoreRevision = (revision: DraftRevision) => {
    editor.restoreSnapshot({ nodes: revision.nodes, edges: revision.edges })
    addNotification({
      level: 'info',
      title: 'Draft revision restored',
      message: 'The local graph is editable again. It remains untrusted and cannot execute.',
    })
  }

  const switchTemplate = (workflowId: string) => {
    setSelectedTemplateId(workflowId)
    setSearchParams({ workflow: workflowId }, { replace: true })
    loadedWorkflowId.current = null
    setAuthorizationConfirmed(false)
    setTarget('')
  }

  return (
    <div className="space-y-5">
      <header className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <div className="mb-3 flex items-center gap-2"><GitBranch className="h-4 w-4 text-cyan-300" /><span className="console-label text-cyan-200">Visual orchestration</span></div>
          <h1 className="console-heading text-3xl sm:text-4xl">Workflow Studio</h1>
          <p className="mt-3 max-w-2xl text-sm text-slate-400">Inspect packaged DAGs, explore host compatibility, and compose versioned drafts without bypassing backend command policy.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {editor.dirty && <Badge variant="outline" className="border-amber-400/25 text-amber-200">Unsaved draft</Badge>}
          {!editor.dirty && modifiedFromPackage && <Badge variant="outline" className="border-violet-400/25 text-violet-200">Saved local draft</Badge>}
          <Button variant="outline" size="sm" onClick={editor.undo} disabled={!editor.past.length}><Undo2 className="mr-2 h-3.5 w-3.5" />Undo</Button>
          <Button variant="outline" size="sm" onClick={editor.redo} disabled={!editor.future.length}><Redo2 className="mr-2 h-3.5 w-3.5" />Redo</Button>
          <Button variant="outline" size="sm" onClick={editor.reset} disabled={!modifiedFromPackage}><RotateCcw className="mr-2 h-3.5 w-3.5" />Reset</Button>
          <Button size="sm" onClick={saveDraft} disabled={!editor.workflowId || !editor.dirty}><Save className="mr-2 h-3.5 w-3.5" />Save revision</Button>
        </div>
      </header>

      <div className="grid gap-4 xl:grid-cols-[300px_minmax(0,1fr)_290px]">
        <aside className="surface-panel rounded-2xl p-3 xl:min-h-[690px]" aria-label="Workflow library">
          <div className="flex items-center justify-between px-2 pb-3 pt-1">
            <div><p className="console-label">Ready-made library</p><p className="mt-1 text-xs text-slate-500">{templatesQuery.data?.length ?? 0} packaged workflows</p></div>
            <Workflow className="h-4 w-4 text-violet-300" />
          </div>
          <div className="relative mb-2"><Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-700" /><Input className="h-9 pl-8 text-xs" value={librarySearch} onChange={(event) => setLibrarySearch(event.target.value)} placeholder="Search outcomes…" aria-label="Search workflow library" /></div>
          <div className="max-h-[560px] space-y-1.5 overflow-y-auto pr-1 xl:max-h-[610px]">
            {templatesQuery.isLoading && <p className="p-3 text-xs text-slate-500">Loading workflow catalog…</p>}
            {templatesQuery.error && <div className="m-2 rounded-xl border border-red-400/15 bg-red-400/[0.05] p-3 text-xs text-red-200"><p>Workflow catalog could not be loaded.</p><button type="button" onClick={() => templatesQuery.refetch()} className="mt-2 font-semibold text-cyan-300">Try again</button></div>}
            {filteredTemplates.map((workflow) => {
              const selected = workflow.id === selectedTemplateId
              const compatible = workflow.compatibility?.compatible !== false
              const metadata = getWorkflowCatalogEntry(workflow)
              return (
                <button key={workflow.id} type="button" onClick={() => switchTemplate(workflow.id)} className={`w-full rounded-xl border p-3 text-left transition-colors ${selected ? 'border-cyan-400/25 bg-cyan-400/[0.075]' : 'border-transparent hover:border-white/[0.07] hover:bg-white/[0.03]'}`}>
                  <div className="flex items-start gap-2.5">
                    <span className={`mt-1.5 h-2 w-2 flex-shrink-0 rounded-full ${compatible ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,.6)]' : 'bg-amber-400'}`} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-xs font-semibold text-slate-100">{workflow.name}</span>
                      <span className="mt-1 block line-clamp-2 text-[10px] leading-relaxed text-slate-500">{metadata.intent}</span>
                      <span className="mt-2 flex items-center gap-1.5"><span className={`rounded-full border px-1.5 py-0.5 text-[8px] font-semibold uppercase tracking-wider ${workflowActivityStyles[metadata.activity]}`}>{metadata.activity}</span><span className="text-[9px] uppercase tracking-wider text-slate-700">{workflow.steps_count} steps · {metadata.duration}</span></span>
                    </span>
                    <ChevronRight className={`h-3.5 w-3.5 ${selected ? 'text-cyan-300' : 'text-slate-700'}`} />
                  </div>
                </button>
              )
            })}
            {!filteredTemplates.length && !templatesQuery.isLoading && <p className="p-5 text-center text-xs text-slate-600">No workflows match this search.</p>}
          </div>
        </aside>

        <main className="min-w-0">
          <div className="mb-3 flex flex-col gap-3 rounded-xl border border-white/[0.07] bg-white/[0.025] p-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><h2 className="truncate text-sm font-semibold text-slate-100">{currentTemplate?.name ?? 'Select a workflow'}</h2>{currentMetadata && <span className={`rounded-full border px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider ${workflowActivityStyles[currentMetadata.activity]}`}>{currentMetadata.activity}</span>}</div>{currentMetadata && <p className="mt-1 truncate text-[11px] text-slate-600">{currentMetadata.bestFor}</p>}</div>
            <div className="flex items-center gap-1 self-start sm:self-auto">
              <button type="button" onClick={() => setMode('design')} className={`flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-medium ${mode === 'design' ? 'bg-cyan-400/10 text-cyan-100' : 'text-slate-500 hover:text-white'}`}><Code2 className="h-3.5 w-3.5" />Design</button>
              <button type="button" onClick={() => setMode('preview')} className={`flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-medium ${mode === 'preview' ? 'bg-violet-400/10 text-violet-100' : 'text-slate-500 hover:text-white'}`}><Box className="h-3.5 w-3.5" />3D preview</button>
            </div>
          </div>

          {detailsQuery.isLoading ? (
            <div className="surface-panel grid h-[610px] place-items-center rounded-2xl"><Loader2 className="h-7 w-7 animate-spin text-cyan-300" /></div>
          ) : detailsQuery.error ? (
            <div className="surface-panel grid h-[610px] place-items-center rounded-2xl p-8 text-center" role="alert"><div><CircleAlert className="mx-auto h-8 w-8 text-red-300" /><h2 className="mt-4 text-base font-semibold text-white">Workflow details could not be loaded</h2><p className="mt-2 max-w-md text-xs text-slate-500">{detailsQuery.error.message}</p><Button className="mt-4" variant="outline" onClick={() => detailsQuery.refetch()}>Try again</Button></div></div>
          ) : mode === 'design' ? (
            <div className="h-[610px] overflow-hidden rounded-2xl border border-white/[0.08] bg-[#050a12]">
              <ReactFlow<WorkflowCanvasNode, WorkflowCanvasEdge>
                nodes={editor.nodes}
                edges={editor.edges}
                nodeTypes={nodeTypes}
                onNodesChange={(changes: NodeChange<WorkflowCanvasNode>[]) => editor.applyNodeChanges(changes)}
                onEdgesChange={(changes: EdgeChange<WorkflowCanvasEdge>[]) => editor.applyEdgeChanges(changes)}
                onConnect={(connection: Connection) => editor.connect(connection)}
                onNodeClick={(_, node) => editor.selectNode(node.id)}
                onNodeDragStart={() => editor.captureSnapshot()}
                onPaneClick={() => editor.selectNode(null)}
                fitView
                fitViewOptions={{ padding: 0.25 }}
                minZoom={0.35}
                maxZoom={1.7}
                colorMode="dark"
                deleteKeyCode={null}
              >
                <Background color="#17304a" gap={24} size={1} variant={BackgroundVariant.Dots} />
                <Controls className="!overflow-hidden !rounded-xl !border !border-white/10 !bg-slate-950/80 !shadow-xl [&>button]:!border-white/10 [&>button]:!bg-transparent [&>button]:!fill-slate-300 [&>button:hover]:!bg-white/5" />
                <MiniMap nodeColor={(node) => node.data.missing ? '#fbbf24' : '#22d3ee'} maskColor="rgba(3,7,14,.78)" className="!rounded-xl !border !border-white/10 !bg-slate-950/75" />
              </ReactFlow>
            </div>
          ) : (
            <Suspense fallback={<div className="surface-panel grid h-[610px] place-items-center rounded-2xl text-xs text-slate-500">Loading spatial preview…</div>}>
              <WorkflowTopologyPreview nodes={editor.nodes} edges={editor.edges} />
            </Suspense>
          )}
        </main>

        <aside className="space-y-4" aria-label="Workflow inspector">
          {currentMetadata && <section className="surface-panel rounded-2xl p-4"><p className="console-label">Mission brief</p><p className="mt-3 text-xs leading-relaxed text-slate-300">{currentMetadata.intent}</p><div className="mt-3 flex items-center gap-3 text-[10px] uppercase tracking-wider text-slate-600"><span className="flex items-center gap-1.5"><Clock3 className="h-3.5 w-3.5 text-violet-300" />{currentMetadata.duration}</span><span>{currentMetadata.targetKind} target</span></div><div className="mt-3 flex flex-wrap gap-1.5">{currentMetadata.evidence.slice(0, 4).map((item) => <span key={item} className="rounded-lg border border-white/[0.07] bg-white/[0.025] px-2 py-1 text-[9px] text-slate-500">{item}</span>)}</div></section>}
          <section className="surface-panel rounded-2xl p-4">
            <div className="flex items-center justify-between"><p className="console-label">Validation</p>{validationErrors.length ? <CircleAlert className="h-4 w-4 text-amber-300" /> : <CheckCircle2 className="h-4 w-4 text-emerald-300" />}</div>
            {validationErrors.length ? (
              <ul className="mt-3 space-y-2">{validationErrors.map((error) => <li key={error} className="rounded-lg border border-amber-400/10 bg-amber-400/[0.04] p-2.5 text-[11px] leading-relaxed text-amber-100/80">{error}</li>)}</ul>
            ) : <p className="mt-3 text-xs leading-relaxed text-emerald-200/80">Graph structure and host tool compatibility are ready.</p>}
          </section>

          <section className="surface-panel rounded-2xl p-4">
            <div className="flex items-center justify-between"><p className="console-label">Step inspector</p>{selectedNode && <button type="button" onClick={editor.deleteSelectedNode} className="rounded-lg p-1.5 text-slate-600 hover:bg-red-400/10 hover:text-red-300" aria-label="Delete selected draft step"><Trash2 className="h-3.5 w-3.5" /></button>}</div>
            {selectedNode ? (
              <div className="mt-4 space-y-3">
                <label className="block text-[11px] text-slate-500">Display name<Input className="mt-1.5" value={selectedNode.data.label} onChange={(event) => editor.updateSelectedNode({ label: event.target.value })} /></label>
                <label className="block text-[11px] text-slate-500">Executable key<Input className="mt-1.5 font-mono" value={selectedNode.data.tool} onChange={(event) => editor.updateSelectedNode({ tool: event.target.value })} /></label>
                <label className="block text-[11px] text-slate-500">Description<textarea className="mt-1.5 min-h-20 w-full resize-none rounded-xl border border-white/10 bg-slate-950/60 p-3 text-xs text-white outline-none focus:border-cyan-400/40" value={selectedNode.data.description} onChange={(event) => editor.updateSelectedNode({ description: event.target.value })} /></label>
              </div>
            ) : <p className="mt-3 text-xs text-slate-600">Select a node to inspect its draft metadata.</p>}
          </section>

          <section className="surface-panel rounded-2xl p-4">
            <div className="flex items-center justify-between"><p className="console-label">Authorized run</p><ShieldCheck className="h-4 w-4 text-cyan-300" /></div>
            <p className="mt-3 text-[11px] leading-relaxed text-slate-500">Only the immutable packaged workflow can execute. Modified drafts require a future backend-reviewed revision and cannot become commands from this UI.</p>
            <Input className="mt-3" placeholder={currentMetadata ? getTargetPlaceholder(currentMetadata.targetKind) : 'example.com or authorized target'} value={target} onChange={(event) => setTarget(event.target.value)} />
            {currentMetadata?.prerequisites?.map((prerequisite) => <p key={prerequisite} className="mt-2 rounded-lg border border-violet-400/10 bg-violet-400/[0.035] p-2 text-[10px] leading-relaxed text-violet-100/70">{prerequisite}</p>)}
            <label className="mt-3 flex items-start gap-2.5 rounded-xl border border-amber-400/15 bg-amber-400/[0.04] p-3 text-[11px] leading-relaxed text-slate-300">
              <input type="checkbox" checked={authorizationConfirmed} onChange={(event) => setAuthorizationConfirmed(event.target.checked)} className="mt-0.5 accent-cyan-400" />I own this target or have explicit authorization to test it.
            </label>
            <Button className="mt-3 w-full" disabled={!selectedTemplateId || !target.trim() || !authorizationConfirmed || modifiedFromPackage || validationErrors.length > 0 || executeWorkflow.isPending} onClick={() => executeWorkflow.mutate()}>
              {executeWorkflow.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Play className="mr-2 h-4 w-4" />}
              {modifiedFromPackage ? 'Reset draft to run' : 'Run packaged workflow'}
            </Button>
            {executeWorkflow.error && <p role="alert" className="mt-3 text-[11px] text-red-300">{executeWorkflow.error.message}</p>}
          </section>

          <section className="rounded-2xl border border-violet-400/15 bg-violet-400/[0.035] p-4">
            <div className="flex items-center gap-2 text-xs font-semibold text-violet-100"><LockKeyhole className="h-4 w-4" />Advanced Mode boundary</div>
            <p className="mt-2 text-[11px] leading-relaxed text-slate-500">Executable paths and argv trust remain backend-owned. No shell string, silent elevation, or imported draft execution is enabled.</p>
          </section>
        </aside>
      </div>

      <section className="surface-panel rounded-2xl p-4">
        <div className="flex items-center gap-2"><History className="h-4 w-4 text-violet-300" /><p className="console-label">Local draft history</p></div>
        <div className="mt-3 flex gap-2 overflow-x-auto pb-1">
          {templateRevisions.length ? templateRevisions.slice(0, 8).map((revision, index) => (
            <div key={revision.id} className="min-w-[210px] rounded-xl border border-white/[0.07] bg-white/[0.025] p-3">
              <div className="flex items-center justify-between text-xs text-white"><span>Draft r{templateRevisions.length - index}</span><Badge variant="outline">untrusted</Badge></div>
              <p className="mt-2 text-[10px] text-slate-600">{new Date(revision.createdAt).toLocaleString()}</p>
              <Button size="sm" variant="ghost" className="mt-3 w-full" onClick={() => restoreRevision(revision)}>Restore draft</Button>
            </div>
          )) : <p className="text-xs text-slate-600">No local draft revisions for {currentTemplate?.name ?? 'this workflow'}.</p>}
        </div>
      </section>
    </div>
  )
}

export default WorkflowsPage
