import { useRef } from 'react'
import { CuboidCollider, Physics, RigidBody, type RapierRigidBody } from '@react-three/rapier'
import type { TopologyNode } from '../../types/ui'

const statusColor: Record<TopologyNode['status'], string> = {
  ready: '#22d3ee',
  running: '#a78bfa',
  warning: '#fbbf24',
  offline: '#64748b',
  complete: '#34d399',
}

export const PhysicsTopologyNodes = ({ nodes, positions, selectedId, onSelect, scale }: {
  nodes: TopologyNode[]
  positions: [number, number, number][]
  selectedId: string
  onSelect: (id: string) => void
  scale: number
}) => (
  <Physics gravity={[0, 0, 0]} timeStep="vary" colliders={false}>
    <CuboidCollider position={[0, -1.3, 0]} args={[7, 0.15, 6]} />
    <CuboidCollider position={[-6.4, 1, 0]} args={[0.1, 3, 6]} />
    <CuboidCollider position={[6.4, 1, 0]} args={[0.1, 3, 6]} />
    <CuboidCollider position={[0, 1, -5.2]} args={[7, 3, 0.1]} />
    <CuboidCollider position={[0, 1, 5.2]} args={[7, 3, 0.1]} />
    {nodes.map((node, index) => (
      <PhysicsNode key={node.id} node={node} position={positions[index]} selected={selectedId === node.id} onSelect={onSelect} scale={scale} />
    ))}
  </Physics>
)

const PhysicsNode = ({ node, position, selected, onSelect, scale }: {
  node: TopologyNode
  position: [number, number, number]
  selected: boolean
  onSelect: (id: string) => void
  scale: number
}) => {
  const body = useRef<RapierRigidBody>(null)
  return (
    <RigidBody ref={body} position={position} colliders="ball" linearDamping={5} angularDamping={6} gravityScale={0} canSleep>
      <group
        scale={scale}
        onClick={(event) => {
          event.stopPropagation()
          onSelect(node.id)
          body.current?.applyImpulse({ x: position[0] * 0.018, y: 0.055, z: position[2] * 0.018 }, true)
        }}
      >
        <mesh scale={selected ? 1.18 : 1}>
          {node.kind === 'host' ? <icosahedronGeometry args={[0.88, 1]} /> : <dodecahedronGeometry args={[0.55, 0]} />}
          <meshStandardMaterial color={statusColor[node.status]} emissive={statusColor[node.status]} emissiveIntensity={selected ? 1.4 : 0.55} roughness={0.32} metalness={0.72} />
        </mesh>
        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.72, 0]}>
          <ringGeometry args={[0.66, selected ? 0.78 : 0.72, 48]} />
          <meshBasicMaterial color={statusColor[node.status]} transparent opacity={selected ? 0.72 : 0.22} />
        </mesh>
      </group>
    </RigidBody>
  )
}

export default PhysicsTopologyNodes
