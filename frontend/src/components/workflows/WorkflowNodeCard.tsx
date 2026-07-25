import { Handle, Position, type NodeProps } from '@xyflow/react'
import { CircleAlert, Clock3, Terminal } from 'lucide-react'
import type { WorkflowCanvasNode } from '../../stores/workflowStore'

export const WorkflowNodeCard = ({ data, selected }: NodeProps<WorkflowCanvasNode>) => (
  <article className={`w-[238px] rounded-2xl border bg-[#0b1421]/95 shadow-xl shadow-black/25 backdrop-blur-xl transition-all ${selected ? 'border-cyan-300/50 shadow-cyan-500/10' : data.missing ? 'border-amber-400/35' : 'border-white/10'}`}>
    <Handle type="target" position={Position.Left} className="!h-2.5 !w-2.5 !border-2 !border-[#0b1421] !bg-cyan-300" />
    <div className="flex items-start gap-3 p-4">
      <span className={`grid h-9 w-9 flex-shrink-0 place-items-center rounded-xl border ${data.missing ? 'border-amber-400/20 bg-amber-400/10 text-amber-300' : 'border-cyan-400/20 bg-cyan-400/10 text-cyan-300'}`}>
        {data.missing ? <CircleAlert className="h-4 w-4" /> : <Terminal className="h-4 w-4" />}
      </span>
      <div className="min-w-0">
        <p className="truncate text-sm font-semibold text-white">{data.label}</p>
        <p className="mt-1 truncate font-mono text-[10px] uppercase tracking-wider text-cyan-300/80">{data.tool}</p>
      </div>
    </div>
    <p className="line-clamp-2 min-h-[38px] border-t border-white/[0.07] px-4 py-3 text-[11px] leading-relaxed text-slate-500">{data.description}</p>
    <footer className="flex items-center justify-between border-t border-white/[0.07] px-4 py-2 text-[10px] text-slate-600">
      <span className="flex items-center gap-1"><Clock3 className="h-3 w-3" />{data.timeout ? `${data.timeout}s` : 'default'}</span>
      <span>{data.missing ? 'tool missing' : 'host ready'}</span>
    </footer>
    <Handle type="source" position={Position.Right} className="!h-2.5 !w-2.5 !border-2 !border-[#0b1421] !bg-violet-300" />
  </article>
)

export default WorkflowNodeCard
