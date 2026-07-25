// React is not needed for this component

interface ProgressProps {
  value: number
  max?: number
  className?: string
}

export const Progress = ({
  value,
  max = 100,
  className = ''
}: ProgressProps) => {
  const percentage = Math.min(Math.max((value / max) * 100, 0), 100)

  return (
    <div className={`h-1.5 w-full overflow-hidden rounded-full bg-slate-800 ${className}`}>
      <div
        className="h-full rounded-full bg-gradient-to-r from-cyan-400 via-blue-500 to-violet-500 shadow-[0_0_14px_rgba(34,211,238,0.45)] transition-all duration-300 ease-out"
        style={{ width: `${percentage}%` }}
      />
    </div>
  )
}
