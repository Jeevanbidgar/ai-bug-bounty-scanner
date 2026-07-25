import React from 'react'

interface CardProps {
  children: React.ReactNode
  className?: string
}

interface CardHeaderProps {
  children: React.ReactNode
  className?: string
}

interface CardTitleProps extends React.HTMLAttributes<HTMLHeadingElement> {
  children: React.ReactNode
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
  <div className={`surface-panel rounded-2xl ${className}`}>
    {children}
  </div>
)

export const CardHeader = ({ children, className = '' }: CardHeaderProps) => (
  <div className={`p-5 pb-0 sm:p-6 sm:pb-0 ${className}`}>
    {children}
  </div>
)

export const CardTitle = ({ children, className = '', ...props }: CardTitleProps) => (
  <h3 className={`text-lg font-semibold tracking-tight text-white ${className}`} {...props}>
    {children}
  </h3>
)

export const CardDescription = ({ children, className = '' }: CardDescriptionProps) => (
  <p className={`mt-1 text-sm leading-relaxed text-slate-400 ${className}`}>
    {children}
  </p>
)

export const CardContent = ({ children, className = '' }: CardContentProps) => (
  <div className={`p-5 pt-0 sm:p-6 sm:pt-0 ${className}`}>
    {children}
  </div>
)
