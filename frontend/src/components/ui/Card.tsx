import React from 'react'

interface CardProps {
  children: React.ReactNode
  className?: string
}

interface CardHeaderProps {
  children: React.ReactNode
  className?: string
}

interface CardTitleProps {
  children: React.ReactNode
  className?: string
}

interface CardDescriptionProps {
  children: React.ReactNode
  className?: string
}

interface CardContentProps {
  children: React.ReactNode
  className?: string
}

export const Card = ({ children, className = '' }: CardProps) => (
  <div className={`bg-gray-800 rounded-lg border border-gray-700 ${className}`}>
    {children}
  </div>
)

export const CardHeader = ({ children, className = '' }: CardHeaderProps) => (
  <div className={`p-6 pb-0 ${className}`}>
    {children}
  </div>
)

export const CardTitle = ({ children, className = '' }: CardTitleProps) => (
  <h3 className={`text-lg font-semibold text-white ${className}`}>
    {children}
  </h3>
)

export const CardDescription = ({ children, className = '' }: CardDescriptionProps) => (
  <p className={`text-sm text-gray-400 mt-1 ${className}`}>
    {children}
  </p>
)

export const CardContent = ({ children, className = '' }: CardContentProps) => (
  <div className={`p-6 pt-0 ${className}`}>
    {children}
  </div>
)
