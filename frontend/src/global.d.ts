/// <reference types="vite/client" />

// Global type declarations for VS Code TypeScript

// Allow importing CSS files
declare module '*.css' {
  const content: Record<string, string>
  export default content
}

// Allow importing other asset types
declare module '*.png' {
  const value: string
  export default value
}

declare module '*.jpg' {
  const value: string
  export default value
}

declare module '*.svg' {
  const value: string
  export default value
}

declare module '*.gif' {
  const value: string
  export default value
}

declare module '*.webp' {
  const value: string
  export default value
}
