import { lazy, Suspense, useEffect, useMemo, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { AdaptiveDpr, Grid, OrbitControls, PerformanceMonitor } from '@react-three/drei'
import { Bloom, EffectComposer, Vignette } from '@react-three/postprocessing'
import { RefreshCw, Rotate3D, Sparkles, TriangleAlert } from 'lucide-react'
import type { Group } from 'three'
import { useRef } from 'react'
import type { Scan, SystemInfo, Tool, WorkflowTemplate } from '../../services/api'
import type { TopologyNode, VisualQuality } from '../../types/ui'
import { useReducedMotion, useUiStore } from '../../stores/uiStore'

const DevSceneControls = import.meta.env.DEV ? lazy(() => import('./DevSceneControls')) : null
const PhysicsTopologyNodes = lazy(() => import('./PhysicsTopologyNodes'))
const sceneControlsEnabled = import.meta.env.DEV
  && typeof window !== 'undefined'
  && new URLSearchParams(window.location.search).get('sceneControls') === '1'

interface MissionTopologyProps {
  systemInfo: SystemInfo | null
  tools: Tool[]
  workflows: WorkflowTemplate[]
  scans: Scan[]
}

interface SceneTuning {
  bloomIntensity: number
  nodeScale: number
  gridOpacity: number
}

const defaultTuning: SceneTuning = {
  bloomIntensity: 0.48,
  nodeScale: 1,
  gridOpacity: 0.2,
}

const statusColor: Record<TopologyNode['status'], string> = {
  ready: '#22d3ee',
  running: '#a78bfa',
  warning: '#fbbf24',
  offline: '#64748b',
  complete: '#34d399',
}

const supportsWebGl = () => {
  if (typeof document === 'undefined') return false
  try {
    const canvas = document.createElement('canvas')
    return Boolean(canvas.getContext('webgl2') || canvas.getContext('webgl'))
  } catch {
    return false
  }
}

const useDocumentVisible = () => {
  const [visible, setVisible] = useState(() => typeof document === 'undefined' || document.visibilityState === 'visible')

  useEffect(() => {
    const updateVisibility = () => setVisible(document.visibilityState === 'visible')
    document.addEventListener('visibilitychange', updateVisibility)
    return () => document.removeEventListener('visibilitychange', updateVisibility)
  }, [])

  return visible
}

export const MissionTopology = ({ systemInfo, tools, workflows, scans }: MissionTopologyProps) => {
  const quality = useUiStore((state) => state.visualQuality)
  const immersiveVisuals = useUiStore((state) => state.immersiveVisuals)
  const selectedId = useUiStore((state) => state.selectedTopologyNode)
  const setSelectedId = useUiStore((state) => state.setSelectedTopologyNode)
  const reducedMotion = useReducedMotion()
  const documentVisible = useDocumentVisible()
  const vmBaselineMemoryMb = useUiStore((state) => state.vmBaselineMemoryMb)
  const [resetKey, setResetKey] = useState(0)
  const [tuning, setTuning] = useState(defaultTuning)
  const [autoQuality, setAutoQuality] = useState<Exclude<VisualQuality, 'auto'>>('balanced')
  const effectiveQuality = quality === 'auto' ? autoQuality : quality
  const webGl = useMemo(supportsWebGl, [])

  const installedTools = tools.filter((tool) => tool.installed)
  const missingTools = tools.filter((tool) => !tool.installed)
  const activeScans = scans.filter((scan) => scan.status.toLowerCase() === 'running')
  const totalFindings = scans.reduce((total, scan) => total + (scan.vulnerabilities ?? 0), 0)
  const processMemoryMb = systemInfo?.process_memory_mb ?? 0
  const estimatedMemoryAvoidedMb = Math.max(0, vmBaselineMemoryMb - processMemoryMb)

  const nodes: TopologyNode[] = useMemo(() => [
    {
      id: 'host',
      label: systemInfo ? `${systemInfo.os} · ${systemInfo.arch}` : 'Local host',
      kind: 'host',
      status: 'ready',
      detail: systemInfo ? `${systemInfo.cpu_cores} cores · ${Math.round(systemInfo.available_memory_mb / 1024)} GB available` : 'Native runtime information is loading',
    },
    {
      id: 'tools-ready',
      label: `${installedTools.length} tools ready`,
      kind: 'tool',
      status: installedTools.length ? 'ready' : 'offline',
      detail: installedTools.slice(0, 5).map((tool) => tool.name).join(', ') || 'No discovered tools',
    },
    {
      id: 'tools-missing',
      label: `${missingTools.length} tools missing`,
      kind: 'tool',
      status: missingTools.length ? 'warning' : 'complete',
      detail: missingTools.slice(0, 5).map((tool) => tool.name).join(', ') || 'All catalog tools are ready',
    },
    {
      id: 'workflows',
      label: `${workflows.length} workflows`,
      kind: 'workflow',
      status: workflows.length ? 'ready' : 'offline',
      detail: `${workflows.filter((workflow) => workflow.compatibility?.compatible).length} compatible on this host`,
    },
    {
      id: 'active-scans',
      label: activeScans.length ? `${activeScans.length} active scan${activeScans.length === 1 ? '' : 's'}` : 'Execution idle',
      kind: 'workflow',
      status: activeScans.length ? 'running' : 'ready',
      detail: activeScans[0]?.current_step || 'Ready for an authorized workflow',
    },
    {
      id: 'findings',
      label: `${totalFindings} findings`,
      kind: 'finding',
      status: totalFindings ? 'warning' : 'complete',
      detail: 'Normalized evidence preserved with raw artifacts',
    },
    {
      id: 'resource-savings',
      label: `${(estimatedMemoryAvoidedMb / 1024).toFixed(1)} GB VM RAM avoided`,
      kind: 'resource',
      status: estimatedMemoryAvoidedMb > 0 ? 'complete' : 'warning',
      detail: `${processMemoryMb} MB UniHack RSS compared with a ${(vmBaselineMemoryMb / 1024).toFixed(1)} GB configurable VM baseline`,
    },
  ], [activeScans, estimatedMemoryAvoidedMb, installedTools, missingTools, processMemoryMb, systemInfo, totalFindings, vmBaselineMemoryMb, workflows])

  const selected = nodes.find((node) => node.id === selectedId) ?? nodes[0]
  const showCanvas = immersiveVisuals && webGl

  return (
    <section className="surface-panel overflow-hidden rounded-2xl" aria-labelledby="mission-topology-title">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.07] px-5 py-4">
        <div>
          <div className="flex items-center gap-2">
            <Rotate3D className="h-4 w-4 text-cyan-300" />
            <h2 id="mission-topology-title" className="text-sm font-semibold text-white">Mission topology</h2>
            <span className="rounded-full border border-cyan-400/15 bg-cyan-400/[0.06] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-cyan-200">{effectiveQuality}</span>
          </div>
          <p className="mt-1 text-xs text-slate-500">Local runtime, tools, workflows, and evidence relationships</p>
        </div>
        <button type="button" onClick={() => setResetKey((value) => value + 1)} className="flex items-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-xs text-slate-400 hover:border-cyan-400/20 hover:text-white" disabled={!showCanvas}>
          <RefreshCw className="h-3.5 w-3.5" />Reset view
        </button>
      </div>

      <div className="grid min-h-[390px] lg:grid-cols-[minmax(0,1fr)_260px]">
        <div className="console-grid relative min-h-[390px] overflow-hidden bg-[#050a12]">
          {showCanvas ? (
            <Canvas
              key={resetKey}
              dpr={effectiveQuality === 'low' ? 1 : [1, 1.5]}
              frameloop={documentVisible && activeScans.length > 0 && !reducedMotion && effectiveQuality !== 'low' ? 'always' : 'demand'}
              camera={{ position: [0, 6.5, 10], fov: 46, near: 0.1, far: 100 }}
              gl={{ antialias: effectiveQuality !== 'low', alpha: true, powerPreference: effectiveQuality === 'low' ? 'low-power' : 'high-performance' }}
              onCreated={({ gl }) => gl.setClearColor('#050a12', 0)}
            >
              <PerformanceMonitor
                onDecline={() => quality === 'auto' && setAutoQuality('low')}
                onIncline={() => quality === 'auto' && setAutoQuality('balanced')}
              >
                <Suspense fallback={null}>
                  <MissionScene
                    nodes={nodes}
                    active={documentVisible && activeScans.length > 0}
                    quality={effectiveQuality}
                    reducedMotion={reducedMotion}
                    selectedId={selected.id}
                    onSelect={setSelectedId}
                    tuning={tuning}
                  />
                </Suspense>
                <AdaptiveDpr pixelated={effectiveQuality === 'low'} />
              </PerformanceMonitor>
            </Canvas>
          ) : (
            <TopologyFallback nodes={nodes} selectedId={selected.id} onSelect={setSelectedId} />
          )}

          {!webGl && (
            <div className="absolute left-4 top-4 flex items-center gap-2 rounded-lg border border-amber-400/15 bg-amber-400/[0.07] px-3 py-2 text-xs text-amber-200"><TriangleAlert className="h-3.5 w-3.5" />WebGL unavailable · accessible topology active</div>
          )}
          {DevSceneControls && sceneControlsEnabled && (
            <Suspense fallback={null}><DevSceneControls onChange={setTuning} /></Suspense>
          )}
        </div>

        <aside className="border-t border-white/[0.07] bg-slate-950/35 p-4 lg:border-l lg:border-t-0" aria-label="Topology details">
          <p className="console-label">Selected module</p>
          <div className="mt-4 rounded-xl border border-white/[0.08] bg-white/[0.025] p-4">
            <span className="mb-3 block h-2 w-2 rounded-full" style={{ background: statusColor[selected.status], boxShadow: `0 0 14px ${statusColor[selected.status]}` }} />
            <h3 className="text-sm font-semibold text-white">{selected.label}</h3>
            <p className="mt-2 text-xs leading-relaxed text-slate-500">{selected.detail}</p>
            <span className="mt-4 inline-flex rounded-full border border-white/10 px-2 py-1 text-[10px] uppercase tracking-wider text-slate-500">{selected.kind}</span>
          </div>
          <div className="mt-4 space-y-1">
            {nodes.map((node) => (
              <button key={node.id} type="button" onClick={() => setSelectedId(node.id)} className={`flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-xs ${node.id === selected.id ? 'bg-cyan-400/[0.08] text-cyan-100' : 'text-slate-500 hover:bg-white/[0.035] hover:text-slate-300'}`}>
                <span className="h-1.5 w-1.5 flex-shrink-0 rounded-full" style={{ background: statusColor[node.status] }} />
                <span className="truncate">{node.label}</span>
              </button>
            ))}
          </div>
        </aside>
      </div>
    </section>
  )
}

const nodePositions: [number, number, number][] = [
  [0, 0.3, 0],
  [-3.6, 0.2, -0.8],
  [3.5, 0.4, -0.9],
  [-2.7, 0.1, 2.4],
  [2.7, 0.35, 2.3],
  [0, 0.15, -3.2],
  [0, 0.3, 3.7],
]

const MissionScene = ({ nodes, active, quality, reducedMotion, selectedId, onSelect, tuning }: {
  nodes: TopologyNode[]
  active: boolean
  quality: Exclude<VisualQuality, 'auto'>
  reducedMotion: boolean
  selectedId: string
  onSelect: (id: string) => void
  tuning: SceneTuning
}) => {
  const interactivePhysics = quality === 'high' && !reducedMotion

  return (
    <>
      <ambientLight intensity={0.72} />
      <directionalLight position={[4, 8, 6]} intensity={quality === 'high' ? 2.2 : 1.5} color="#b6e9ff" castShadow={quality === 'high'} />
      <pointLight position={[-5, 2, -4]} intensity={16} distance={18} color="#7c3aed" />
      <pointLight position={[5, 1, 4]} intensity={12} distance={16} color="#06b6d4" />

      <Grid args={[24, 24]} position={[0, -1.15, 0]} cellColor="#12304b" sectionColor="#1e5675" cellSize={0.55} sectionSize={2.75} fadeDistance={18} fadeStrength={1.4} infiniteGrid />

      {interactivePhysics ? (
        <Suspense fallback={null}>
          <PhysicsTopologyNodes nodes={nodes} positions={nodePositions} selectedId={selectedId} onSelect={onSelect} scale={tuning.nodeScale} />
        </Suspense>
      ) : nodes.map((node, index) => (
        <VisualNode key={node.id} node={node} position={nodePositions[index]} selected={selectedId === node.id} onSelect={onSelect} scale={tuning.nodeScale} />
      ))}

      <CommandCore active={active && !reducedMotion} />
      <OrbitControls makeDefault enablePan={false} minDistance={7.5} maxDistance={15} minPolarAngle={0.58} maxPolarAngle={1.35} target={[0, 0, 0]} />

      {quality !== 'low' && (
        <EffectComposer multisampling={quality === 'high' ? 4 : 0}>
          <Bloom intensity={tuning.bloomIntensity} luminanceThreshold={0.72} luminanceSmoothing={0.75} mipmapBlur />
          <Vignette offset={0.28} darkness={0.72} />
        </EffectComposer>
      )}
    </>
  )
}

const VisualNode = ({ node, position, selected, onSelect, scale }: {
  node: TopologyNode
  position: [number, number, number]
  selected: boolean
  onSelect: (id: string) => void
  scale: number
}) => (
  <group position={position} scale={scale} onClick={(event) => { event.stopPropagation(); onSelect(node.id) }}>
    <mesh scale={selected ? 1.18 : 1}>
      {node.kind === 'host' ? <icosahedronGeometry args={[0.88, 1]} /> : <dodecahedronGeometry args={[0.55, 0]} />}
      <meshStandardMaterial color={statusColor[node.status]} emissive={statusColor[node.status]} emissiveIntensity={selected ? 1.4 : 0.55} roughness={0.32} metalness={0.72} />
    </mesh>
    <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.72, 0]}>
      <ringGeometry args={[0.66, selected ? 0.78 : 0.72, 48]} />
      <meshBasicMaterial color={statusColor[node.status]} transparent opacity={selected ? 0.72 : 0.22} />
    </mesh>
  </group>
)

const CommandCore = ({ active }: { active: boolean }) => {
  const group = useRef<Group>(null)
  useFrame((_, delta) => {
    if (active && group.current) group.current.rotation.y += delta * 0.28
  })
  return (
    <group ref={group} position={[0, 0.3, 0]}>
      <mesh rotation={[Math.PI / 2, 0, 0]} scale={1.9}>
        <torusGeometry args={[1.05, 0.018, 10, 84]} />
        <meshBasicMaterial color="#22d3ee" transparent opacity={0.23} />
      </mesh>
      <mesh rotation={[0, Math.PI / 2, 0]} scale={2.15}>
        <torusGeometry args={[1.05, 0.012, 10, 84]} />
        <meshBasicMaterial color="#8b5cf6" transparent opacity={0.18} />
      </mesh>
    </group>
  )
}

const TopologyFallback = ({ nodes, selectedId, onSelect }: { nodes: TopologyNode[]; selectedId: string; onSelect: (id: string) => void }) => (
  <div className="grid h-full min-h-[390px] place-items-center p-6">
    <div className="grid w-full max-w-2xl grid-cols-2 gap-3 sm:grid-cols-3">
      {nodes.map((node) => (
        <button key={node.id} type="button" onClick={() => onSelect(node.id)} className={`rounded-xl border p-4 text-left ${selectedId === node.id ? 'border-cyan-400/30 bg-cyan-400/[0.08]' : 'border-white/[0.08] bg-white/[0.025] hover:border-white/15'}`}>
          <Sparkles className="h-4 w-4" style={{ color: statusColor[node.status] }} />
          <span className="mt-3 block text-xs font-semibold text-white">{node.label}</span>
          <span className="mt-1 block text-[11px] text-slate-500">{node.kind}</span>
        </button>
      ))}
    </div>
  </div>
)

export default MissionTopology
