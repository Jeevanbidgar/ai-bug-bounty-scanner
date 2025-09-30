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
  const baseClasses = 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium'

  const variantClasses = {
    default: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300',
    secondary: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300',
    destructive: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300',
    outline: 'border border-gray-300 text-gray-700 dark:border-gray-600 dark:text-gray-300'
  }

  const classes = `${baseClasses} ${variantClasses[variant]} ${className}`

  return (
    <span className={classes}>
      {children}
    </span>
  )
}
