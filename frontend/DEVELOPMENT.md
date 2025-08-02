# Frontend Development Setup

## Auto-Adapting Development Environment

This frontend is configured to automatically adapt to changes while running, providing an enhanced development experience.

## Features

### 🔥 Hot Module Replacement (HMR)
- **Instant Updates**: Changes to Vue components, styles, and JavaScript files are reflected immediately
- **State Preservation**: Component state is preserved during updates when possible
- **Error Overlay**: Compilation errors are displayed as overlays in the browser

### 📁 Enhanced File Watching
- **Aggressive Polling**: Uses polling with 100ms intervals for better change detection
- **Multiple File Types**: Watches `.vue`, `.js`, `.css`, `.env`, and config files
- **Config Auto-Reload**: Automatically restarts when configuration files change

### 🔧 Environment-Aware Configuration
- **Dynamic API URLs**: Automatically switches between development and production endpoints
- **Debug Logging**: Enhanced logging in development mode
- **Performance Monitoring**: Optional performance overlays and monitoring

## Quick Start

### Option 1: Windows Batch File (Recommended for Windows)
```bash
# Double-click or run from command prompt
start-dev.bat
```

### Option 2: NPM Scripts
```bash
# Basic development server
npm run dev

# Development with debug logging
npm run dev-debug

# Force clean restart
npm run dev-force

# Development with external access
npm run dev -- --host 0.0.0.0
```

### Option 3: Enhanced Development Server
```bash
# Advanced server with config monitoring
node dev-server.mjs
```

## Environment Configuration

### Environment Files
- `.env.development` - Development-specific variables
- `.env.local` - Local overrides (not committed)
- `.env` - Global environment variables

### Key Environment Variables
```bash
# API Configuration
VITE_API_BASE_URL=http://localhost:5000/api
VITE_SOCKET_URL=http://localhost:5000

# Development Features
VITE_HOT_RELOAD=true
VITE_DEBUG_MODE=true
VITE_ENABLE_DEVTOOLS=true

# Performance
VITE_ENABLE_POLLING=true
VITE_POLLING_INTERVAL=100
```

## Development Features

### 🎯 Automatic Backend Connection
- **Health Checks**: Automatically tests backend connectivity
- **Retry Logic**: Retries failed connections with exponential backoff
- **Connection Status**: Visual indicators for backend connection status

### 📊 Development Debugging
- **API Request/Response Logging**: All API calls are logged in the console
- **Socket Connection Monitoring**: Real-time socket connection status
- **Performance Metrics**: Optional performance monitoring overlay

### 🔄 Configuration Hot Reloading
- **Vite Config**: Changes to `vite.config.js` trigger server restart
- **Environment Variables**: Changes to `.env*` files are detected
- **Package Dependencies**: `package.json` changes trigger reinstall

## Advanced Configuration

### Custom Vite Configuration
Use `vite.config.dev.js` for development-specific settings:
```javascript
// Enhanced polling and HMR settings
export default defineConfig({
  server: {
    watch: {
      usePolling: true,
      interval: 50, // Ultra-fast polling
    },
    hmr: {
      overlay: true,
      port: 3001,
    }
  }
});
```

### Development Scripts

#### Watch Mode for Different Tasks
```bash
# Watch and lint files
npm run lint-watch

# Build in watch mode
npm run build-watch

# Preview production build
npm run preview
```

#### Clean and Restart
```bash
# Clean cache and restart
npm run restart

# Force clean dependencies
npm run clean
```

## Troubleshooting

### Common Issues

1. **Changes Not Detected**
   - Increase polling interval in `vite.config.js`
   - Check file permissions
   - Disable antivirus real-time scanning for project folder

2. **Backend Connection Issues**
   - Verify backend is running on `http://localhost:5000`
   - Check CORS configuration
   - Update `VITE_API_BASE_URL` in `.env.local`

3. **Port Conflicts**
   - Change port in `vite.config.js`
   - Use `--port` flag: `npm run dev -- --port 3001`

4. **Memory Issues with Large Projects**
   - Reduce polling frequency
   - Exclude unnecessary directories from watching
   - Increase Node.js memory: `node --max-old-space-size=4096`

### Performance Optimization

#### For Better Hot Reload Performance
```javascript
// In vite.config.js
export default defineConfig({
  server: {
    watch: {
      usePolling: true,
      interval: 100, // Balance between speed and CPU usage
      ignored: ['**/node_modules/**', '**/.git/**'] // Exclude heavy directories
    }
  }
});
```

#### For Faster Build Times
```javascript
// Optimize dependencies
export default defineConfig({
  optimizeDeps: {
    include: ['vue', 'vue-router', 'pinia'], // Pre-bundle heavy dependencies
    force: false // Only force when needed
  }
});
```

## IDE Integration

### VS Code Settings
Add to `.vscode/settings.json`:
```json
{
  "typescript.preferences.importModuleSpecifier": "relative",
  "vue.codeActions.enabled": true,
  "vue.complete.casing.tags": "pascal",
  "files.watcherExclude": {
    "**/node_modules/**": true,
    "**/dist/**": true
  }
}
```

### VS Code Extensions
- Vue Language Features (Volar)
- TypeScript Vue Plugin (Volar)
- Tailwind CSS IntelliSense
- ESLint
- Prettier

## Network Access

### External Device Access
The development server is configured to accept connections from external devices:
```bash
# Server will be available at:
http://localhost:3000      # Local access
http://your-ip:3000        # Network access
```

### Mobile Testing
1. Find your computer's IP address
2. Ensure firewall allows port 3000
3. Access `http://YOUR_IP:3000` from mobile device

## Monitoring and Logs

### Console Logging
Development mode provides enhanced logging:
- 📤 API requests with full details
- 📥 API responses with status codes
- 🔌 Socket connection events
- 🔄 Hot reload events
- ⚠️ Configuration changes

### Performance Monitoring
Enable performance overlay:
```bash
# Set environment variable
VITE_SHOW_PERFORMANCE_OVERLAY=true
```

## Production Deployment

### Build for Production
```bash
# Standard production build
npm run build

# Build with source maps for debugging
npm run build -- --sourcemap

# Preview production build locally
npm run preview
```

### Environment Switching
The application automatically detects the environment and adjusts:
- **Development**: Full debugging, hot reload, verbose logging
- **Production**: Optimized bundles, minimal logging, error reporting
