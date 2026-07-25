import { ArrowLeft, Compass } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Button } from '../components/ui/Button'

const NotFoundPage = () => {
  const navigate = useNavigate()
  return (
    <div className="surface-panel grid min-h-[62vh] place-items-center rounded-3xl p-8 text-center">
      <div>
        <Compass className="mx-auto h-10 w-10 text-slate-700" />
        <p className="console-label mt-5 text-cyan-200">Route unavailable</p>
        <h1 className="console-heading mt-3 text-3xl">Operation module not found</h1>
        <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-slate-500">This address does not map to a UniHack workspace module. Return to the mission console without losing local scan history.</p>
        <Button className="mt-6" onClick={() => navigate('/')}><ArrowLeft className="mr-2 h-4 w-4" />Return to Mission</Button>
      </div>
    </div>
  )
}

export default NotFoundPage
