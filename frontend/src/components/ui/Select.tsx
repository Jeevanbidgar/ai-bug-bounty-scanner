import React, { useState } from 'react'
import { ChevronDown } from 'lucide-react'

interface SelectProps {
  children: React.ReactNode
  value?: string
  onValueChange?: (value: string) => void
}

interface SelectTriggerProps {
  children: React.ReactNode
  className?: string
}

interface SelectContentProps {
  children: React.ReactNode
  className?: string
}

interface SelectItemProps {
  value: string
  children: React.ReactNode
  className?: string
}

export const Select = ({ children, value, onValueChange }: SelectProps) => {
  const [isOpen, setIsOpen] = useState(false)

  return (
    <div className="relative">
      {React.Children.map(children, (child) => {
        if (React.isValidElement(child)) {
          return React.cloneElement(child, {
            isOpen,
            setIsOpen,
            value,
            onValueChange
          } as any)
        }
        return child
      })}
    </div>
  )
}

export const SelectTrigger = ({ children, className = '', isOpen, setIsOpen }: SelectTriggerProps & any) => {
  return (
    <button
      type="button"
      onClick={() => setIsOpen(!isOpen)}
      className={`flex h-10 w-full items-center justify-between rounded-md border border-gray-600 bg-gray-700 px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 ${className}`}
    >
      {children}
      <ChevronDown className={`h-4 w-4 opacity-50 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
    </button>
  )
}

export const SelectValue = ({ placeholder }: { placeholder?: string }) => {
  return <span className="text-gray-400">{placeholder}</span>
}

export const SelectContent = ({ children, className = '', isOpen }: SelectContentProps & any) => {
  if (!isOpen) return null

  return (
    <div className={`absolute top-full left-0 right-0 z-50 mt-1 rounded-md border border-gray-600 bg-gray-700 shadow-lg ${className}`}>
      {children}
    </div>
  )
}

export const SelectItem = ({ value, children, className = '', onValueChange, setIsOpen }: SelectItemProps & any) => {
  return (
    <div
      className={`cursor-pointer px-3 py-2 text-sm text-white hover:bg-gray-600 ${className}`}
      onClick={() => {
        onValueChange(value)
        setIsOpen(false)
      }}
    >
      {children}
    </div>
  )
}
