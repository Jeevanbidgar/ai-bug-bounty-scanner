import React from 'react'

interface BadgeProps {
  variant?: 'default' | 'secondary' | 'destructive' | 'outline'
  children: React.ReactNode
  className?: string
}

export const Badge = ({
  variant = 'default',
  className = '',
  children
}: BadgeProps) => {
  const baseClasses = 'inline-flex items-center rounded-full px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.08em]'

  const variantClasses = {
    default: 'border border-cyan-400/20 bg-cyan-400/10 text-cyan-200',
    secondary: 'border border-white/10 bg-white/[0.05] text-slate-300',
    destructive: 'border border-red-400/20 bg-red-400/10 text-red-300',
    outline: 'border border-white/15 bg-transparent text-slate-300'
  }

  const classes = `${baseClasses} ${variantClasses[variant]} ${className}`

  return (
    <span className={classes}>
      {children}
    </span>
  )
}
