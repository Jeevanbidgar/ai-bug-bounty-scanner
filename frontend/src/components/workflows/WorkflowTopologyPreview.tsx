import { Canvas } from '@react-three/fiber'
import { Line, OrbitControls } from '@react-three/drei'
import { Bloom, EffectComposer } from '@react-three/postprocessing'
import type { WorkflowCanvasEdge, WorkflowCanvasNode } from '../../stores/workflowStore'
import { useReducedMotion, useUiStore } from '../../stores/uiStore'

const toPosition = (node: WorkflowCanvasNode): [number, number, number] => [
  (node.position.x - 350) / 115,
  -(node.position.y - 230) / 115,
  node.data.missing ? -0.5 : 0,
]

export const WorkflowTopologyPreview = ({ nodes, edges }: { nodes: WorkflowCanvasNode[]; edges: WorkflowCanvasEdge[] }) => {
  const quality = useUiStore((state) => state.visualQuality)
  const reducedMotion = useReducedMotion()
  const positions = new Map(nodes.map((node) => [node.id, toPosition(node)]))

  return (
    <div className="relative h-[610px] overflow-hidden rounded-2xl border border-white/[0.08] bg-[#050a12] console-grid">
      <Canvas dpr={quality === 'high' ? [1, 1.5] : 1} frameloop="demand" camera={{ position: [0, 1.5, 10], fov: 48 }}>
        <ambientLight intensity={0.8} />
        <directionalLight position={[5, 7, 8]} intensity={2} color="#d9f7ff" />
        <pointLight position={[-5, -2, 2]} intensity={18} distance={18} color="#7c3aed" />

        {edges.map((edge) => {
          const source = positions.get(edge.source)
          const target = positions.get(edge.target)
          if (!source || !target) return null
          return <Line key={edge.id} points={[source, target]} color="#22d3ee" transparent opacity={0.38} lineWidth={1} />
        })}

        {nodes.map((node) => (
          <group key={node.id} position={positions.get(node.id)}>
            <mesh>
              <dodecahedronGeometry args={[0.46, 0]} />
              <meshStandardMaterial
                color={node.data.missing ? '#fbbf24' : '#22d3ee'}
                emissive={node.data.missing ? '#f59e0b' : '#0891b2'}
                emissiveIntensity={0.7}
                roughness={0.35}
                metalness={0.68}
              />
            </mesh>
            <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.58, 0]}>
              <ringGeometry args={[0.46, 0.53, 32]} />
              <meshBasicMaterial color={node.data.missing ? '#fbbf24' : '#8b5cf6'} transparent opacity={0.42} />
            </mesh>
          </group>
        ))}

        <OrbitControls enablePan minDistance={5} maxDistance={18} autoRotate={!reducedMotion && nodes.length > 0} autoRotateSpeed={0.25} />
        {quality !== 'low' && (
          <EffectComposer multisampling={0}>
            <Bloom intensity={0.42} luminanceThreshold={0.72} mipmapBlur />
          </EffectComposer>
        )}
      </Canvas>
      <div className="pointer-events-none absolute bottom-4 left-4 rounded-lg border border-white/10 bg-slate-950/70 px-3 py-2 text-[11px] text-slate-500 backdrop-blur-lg">Read-only spatial preview · edit in Design mode</div>
    </div>
  )
}

export default WorkflowTopologyPreview
