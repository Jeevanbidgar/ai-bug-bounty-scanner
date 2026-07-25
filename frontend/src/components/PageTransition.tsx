import { useRef } from 'react'
import { useLocation } from 'react-router-dom'
import { gsap } from 'gsap'
import { useGSAP } from '@gsap/react'
import { useReducedMotion } from '../stores/uiStore'

gsap.registerPlugin(useGSAP)

export const PageTransition = ({ children }: { children: React.ReactNode }) => {
  const container = useRef<HTMLDivElement>(null)
  const location = useLocation()
  const reducedMotion = useReducedMotion()

  useGSAP(() => {
    if (!container.current || reducedMotion) return
    gsap.fromTo(
      container.current,
      { autoAlpha: 0, y: 10 },
      { autoAlpha: 1, y: 0, duration: 0.34, ease: 'power2.out', clearProps: 'transform' },
    )
  }, { dependencies: [location.pathname, reducedMotion], scope: container })

  return <div ref={container} key={location.pathname}>{children}</div>
}
