import React, { useState, useEffect, useRef } from 'react';
import { ChevronDown } from 'lucide-react';

const textContent = (node: React.ReactNode): string => {
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (Array.isArray(node)) return node.map(textContent).join(' ').replace(/\s+/g, ' ').trim();
  if (React.isValidElement<{ children?: React.ReactNode }>(node)) return textContent(node.props.children);
  return '';
};

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
      if (React.isValidElement<{ children?: React.ReactNode }>(child) && child.type === SelectContent) {
        React.Children.forEach(child.props.children, (item) => {
          if (React.isValidElement(item)) {
            const itemProps = item.props as { value?: string; children?: React.ReactNode };
            if (itemProps.value === selectedValue) {
              foundLabel = textContent(itemProps.children);
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
    setSelectedValue(value);
    setSelectedLabel(label);
    setIsOpen(false);
    if (onValueChange) {
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

interface SelectTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
}

export const SelectTrigger = ({ children, className = '', ...props }: SelectTriggerProps) => {
  const context = React.useContext(SelectContext);
  if (!context) throw new Error('SelectTrigger must be used within Select');
  return (
    <button
      type="button"
      {...props}
      onClick={() => context.setIsOpen(!context.isOpen)}
      aria-haspopup="listbox"
      aria-expanded={context.isOpen}
      className={`flex h-11 w-full items-center justify-between rounded-xl border border-white/10 bg-slate-950/60 px-3 py-2 text-sm text-white focus:border-cyan-400/50 focus:outline-none focus:ring-2 focus:ring-cyan-400/20 ${className}`}
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
    <span className={context.selectedLabel ? "text-white" : "text-slate-500"}>
      {context.selectedLabel || placeholder}
    </span>
  );
};

export const SelectContent = ({ children, className = '' }: { children: React.ReactNode; className?: string }) => {
  const context = React.useContext(SelectContext);
  if (!context) throw new Error('SelectContent must be used within Select');
  if (!context.isOpen) return null;
  return (
    <div role="listbox" className={`absolute left-0 right-0 top-full z-50 mt-2 max-h-60 overflow-auto rounded-xl border border-white/10 bg-slate-900/95 p-1 shadow-2xl shadow-black/40 backdrop-blur-xl ${className}`}>
      {children}
    </div>
  );
};

export const SelectItem = ({ value, children, className = '', disabled = false }: { value: string; children: React.ReactNode; className?: string; disabled?: boolean }) => {
  const context = React.useContext(SelectContext);
  if (!context) throw new Error('SelectItem must be used within Select');
  const handleClick = () => {
    if (disabled) return;
    const label = textContent(children) || value;
    context.onSelect(value, label);
  };
  const isSelected = context.selectedValue === value;
  return (
    <div
      role="option"
      aria-selected={isSelected}
      aria-disabled={disabled}
      tabIndex={disabled ? -1 : 0}
      className={`px-3 py-2 text-sm transition-colors ${
        disabled 
          ? 'cursor-not-allowed text-slate-600 opacity-50'
          : 'cursor-pointer text-slate-200 hover:bg-cyan-400/10 hover:text-white'
      } ${isSelected && !disabled ? 'bg-cyan-400/10 text-cyan-100' : ''} rounded-lg ${className}`}
      onClick={handleClick}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          handleClick();
        }
      }}
    >
      {children}
    </div>
  );
};
