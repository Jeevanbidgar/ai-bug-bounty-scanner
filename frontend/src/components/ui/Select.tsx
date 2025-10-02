import React, { useState, useEffect, useRef } from 'react';
import { ChevronDown } from 'lucide-react';

interface SelectProps {
  children: React.ReactNode;
  value?: string;
  onValueChange?: (value: string) => void;
}

interface SelectContextType {
  isOpen: boolean;
  setIsOpen: (open: boolean) => void;
  selectedValue: string;
  selectedLabel: string;
  onSelect: (value: string, label: string) => void;
}

const SelectContext = React.createContext<SelectContextType | undefined>(undefined);

export const Select = ({ children, value, onValueChange }: SelectProps) => {
  const [isOpen, setIsOpen] = useState(false);
  const [selectedValue, setSelectedValue] = useState(value || '');
  const [selectedLabel, setSelectedLabel] = useState('');
  const selectRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (value !== undefined) {
      setSelectedValue(value);
    }
  }, [value]);

  useEffect(() => {
    let foundLabel = '';
    React.Children.forEach(children, (child) => {
      if (React.isValidElement(child) && child.type === SelectContent) {
        React.Children.forEach(child.props.children, (item: any) => {
          if (React.isValidElement(item)) {
            const itemProps = item.props as { value?: string; children?: React.ReactNode };
            if (itemProps.value === selectedValue) {
              foundLabel = String(itemProps.children || '');
            }
          }
        });
      }
    });
    setSelectedLabel(foundLabel);
  }, [selectedValue, children]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (selectRef.current && !selectRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [isOpen]);

  const handleSelect = (value: string, label: string) => {
    console.log('Select handleSelect:', { value, label });
    setSelectedValue(value);
    setSelectedLabel(label);
    setIsOpen(false);
    if (onValueChange) {
      console.log('Calling onValueChange:', value);
      onValueChange(value);
    }
  };

  const contextValue: SelectContextType = {
    isOpen,
    setIsOpen,
    selectedValue,
    selectedLabel,
    onSelect: handleSelect
  };

  return (
    <SelectContext.Provider value={contextValue}>
      <div ref={selectRef} className="relative">
        {children}
      </div>
    </SelectContext.Provider>
  );
};

export const SelectTrigger = ({ children, className = '' }: { children: React.ReactNode; className?: string }) => {
  const context = React.useContext(SelectContext);
  if (!context) throw new Error('SelectTrigger must be used within Select');
  return (
    <button
      type="button"
      onClick={() => context.setIsOpen(!context.isOpen)}
      className={`flex h-10 w-full items-center justify-between rounded-md border border-gray-600 bg-gray-700 px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 ${className}`}
    >
      {children}
      <ChevronDown className={`h-4 w-4 opacity-50 transition-transform ${context.isOpen ? 'rotate-180' : ''}`} />
    </button>
  );
};

export const SelectValue = ({ placeholder }: { placeholder?: string }) => {
  const context = React.useContext(SelectContext);
  if (!context) throw new Error('SelectValue must be used within Select');
  return (
    <span className={context.selectedLabel ? "text-white" : "text-gray-400"}>
      {context.selectedLabel || placeholder}
    </span>
  );
};

export const SelectContent = ({ children, className = '' }: { children: React.ReactNode; className?: string }) => {
  const context = React.useContext(SelectContext);
  if (!context) throw new Error('SelectContent must be used within Select');
  if (!context.isOpen) return null;
  return (
    <div className={`absolute top-full left-0 right-0 z-50 mt-1 max-h-60 overflow-auto rounded-md border border-gray-600 bg-gray-700 shadow-lg ${className}`}>
      {children}
    </div>
  );
};

export const SelectItem = ({ value, children, className = '', disabled = false }: { value: string; children: React.ReactNode; className?: string; disabled?: boolean }) => {
  const context = React.useContext(SelectContext);
  if (!context) throw new Error('SelectItem must be used within Select');
  const handleClick = () => {
    if (disabled) return;
    const label = typeof children === 'string' ? children : String(children);
    context.onSelect(value, label);
  };
  const isSelected = context.selectedValue === value;
  return (
    <div
      className={`px-3 py-2 text-sm transition-colors ${
        disabled 
          ? 'text-gray-500 cursor-not-allowed opacity-50' 
          : 'text-white cursor-pointer hover:bg-gray-600'
      } ${isSelected && !disabled ? 'bg-gray-600' : ''} ${className}`}
      onClick={handleClick}
    >
      {children}
    </div>
  );
};
