import { Cable, Wrench } from 'lucide-react'
import AdapterExplorer from '../components/AdapterExplorer'

const AdaptersPage = () => {
  return (
    <div className="space-y-5">
      <header className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <div className="mb-3 flex items-center gap-2"><Cable className="h-4 w-4 text-cyan-300" /><span className="console-label text-cyan-200">Execution contracts</span></div>
          <h1 className="console-heading text-3xl sm:text-4xl">Adaptive Tool Contracts</h1>
          <p className="mt-3 max-w-2xl text-sm text-slate-400">See how many installed tools UniHack supports. New catalog tools are analyzed locally and receive a safe generated profile when their CLI contract is unambiguous.</p>
        </div>
        <div className="hidden items-center gap-2 rounded-xl border border-white/[0.07] bg-white/[0.025] px-3 py-2 text-xs text-slate-500 md:flex"><Wrench className="h-3.5 w-3.5 text-violet-300" />Preview does not execute tools</div>
      </header>
      <AdapterExplorer />
    </div>
  )
}

export default AdaptersPage
