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
    <div className={`w-full bg-gray-700 rounded-full h-2 ${className}`}>
      <div
        className="bg-blue-600 h-2 rounded-full transition-all duration-300 ease-out"
        style={{ width: `${percentage}%` }}
      />
    </div>
  )
}
