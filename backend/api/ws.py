"""
WebSocket manager removed - using Tauri events only for desktop-native architecture

All real-time communication now uses Tauri's event system (emit/listen) instead of WebSockets.
This ensures desktop-only operation without web server dependencies.

See src-tauri/src/main.rs for Tauri event-based workflow execution.
"""

import logging

logger = logging.getLogger(__name__)

# WebSocket functionality removed - replaced with Tauri events
# Real-time updates are handled via Tauri emit/listen in the desktop app
