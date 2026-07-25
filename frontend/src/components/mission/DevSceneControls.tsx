import { useControls } from 'leva'
import { useEffect } from 'react'

export interface SceneTuning {
  bloomIntensity: number
  nodeScale: number
  gridOpacity: number
}

export const DevSceneControls = ({ onChange }: { onChange: (tuning: SceneTuning) => void }) => {
  const controls = useControls('Mission topology', {
    bloomIntensity: { value: 0.48, min: 0, max: 1.5, step: 0.01 },
    nodeScale: { value: 1, min: 0.7, max: 1.4, step: 0.01 },
    gridOpacity: { value: 0.2, min: 0, max: 0.65, step: 0.01 },
  })

  useEffect(() => onChange(controls), [controls, onChange])
  return null
}

export default DevSceneControls
