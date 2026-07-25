import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { MotionPreference, UiPreferences, VisualQuality } from '../types/ui'

interface UiState extends UiPreferences {
  vmBaselineMemoryMb: number
  sidebarCollapsed: boolean
  commandPaletteOpen: boolean
  selectedTopologyNode: string | null
  setVisualQuality: (quality: VisualQuality) => void
  setMotion: (motion: MotionPreference) => void
  setImmersiveVisuals: (enabled: boolean) => void
  setHighContrast: (enabled: boolean) => void
  setVmBaselineMemoryMb: (memoryMb: number) => void
  setSidebarCollapsed: (collapsed: boolean) => void
  setCommandPaletteOpen: (open: boolean) => void
  setSelectedTopologyNode: (nodeId: string | null) => void
}

const systemRequestsReducedMotion = () =>
  typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches

export const useUiStore = create<UiState>()(
  persist(
    (set) => ({
      visualQuality: 'auto',
      motion: systemRequestsReducedMotion() ? 'reduced' : 'full',
      immersiveVisuals: true,
      highContrast: false,
      vmBaselineMemoryMb: 4096,
      sidebarCollapsed: false,
      commandPaletteOpen: false,
      selectedTopologyNode: null,
      setVisualQuality: (visualQuality) => set({ visualQuality }),
      setMotion: (motion) => set({ motion }),
      setImmersiveVisuals: (immersiveVisuals) => set({ immersiveVisuals }),
      setHighContrast: (highContrast) => set({ highContrast }),
      setVmBaselineMemoryMb: (vmBaselineMemoryMb) => set({ vmBaselineMemoryMb: Math.min(32768, Math.max(1024, vmBaselineMemoryMb)) }),
      setSidebarCollapsed: (sidebarCollapsed) => set({ sidebarCollapsed }),
      setCommandPaletteOpen: (commandPaletteOpen) => set({ commandPaletteOpen }),
      setSelectedTopologyNode: (selectedTopologyNode) => set({ selectedTopologyNode }),
    }),
    {
      name: 'unihack-ui-preferences',
      partialize: (state) => ({
        visualQuality: state.visualQuality,
        motion: state.motion,
        immersiveVisuals: state.immersiveVisuals,
        highContrast: state.highContrast,
        vmBaselineMemoryMb: state.vmBaselineMemoryMb,
        sidebarCollapsed: state.sidebarCollapsed,
      }),
    },
  ),
)

export const useReducedMotion = () => useUiStore((state) => state.motion === 'reduced')
