import React from 'react'

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'outline' | 'ghost'
  size?: 'sm' | 'md' | 'lg'
  children: React.ReactNode
}

export const Button = ({
  variant = 'default',
  size = 'md',
  className = '',
  children,
  type = 'button',
  ...props
}: ButtonProps) => {
  const baseClasses = 'inline-flex items-center justify-center rounded-xl font-medium transition-[color,background-color,border-color,box-shadow,transform] duration-200 focus:outline-none focus:ring-2 focus:ring-cyan-400/70 focus:ring-offset-2 focus:ring-offset-slate-950 disabled:opacity-50 disabled:pointer-events-none active:translate-y-px'

  const variantClasses = {
    default: 'border border-cyan-300/20 bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 shadow-[0_8px_24px_rgba(6,182,212,0.18)] hover:from-cyan-400 hover:to-blue-500',
    outline: 'border border-white/10 bg-white/[0.035] text-slate-200 hover:border-cyan-400/30 hover:bg-cyan-400/[0.08]',
    ghost: 'text-slate-300 hover:bg-white/[0.06] hover:text-white'
  }

  const sizeClasses = {
    sm: 'h-8 px-3 text-sm',
    md: 'h-10 px-4 py-2',
    lg: 'h-12 px-8 text-lg'
  }

  const classes = `${baseClasses} ${variantClasses[variant]} ${sizeClasses[size]} ${className}`

  return (
    <button type={type} className={classes} {...props}>
      {children}
    </button>
  )
}
