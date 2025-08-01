# Real-time Collaboration Module
"""
Real-time collaboration features for teams using Socket.IO
"""

try:
    from flask_socketio import SocketIO, emit, join_room, leave_room, rooms, request
except ImportError:
    # Fallback for when flask-socketio is not installed
    class MockSocketIO:
        def on(self, event): return lambda f: f
        def emit(self, *args, **kwargs): pass
    SocketIO = MockSocketIO
    emit = join_room = leave_room = rooms = request = lambda *args, **kwargs: None

from datetime import datetime
import json
import uuid
from typing import Dict, List, Any, Optional
import logging

class CollaborationManager:
    """Manage real-time collaboration features"""
    
    def __init__(self, socketio: SocketIO):
        self.socketio = socketio
        self.active_users = {}  # user_id -> user_info
        self.scan_rooms = {}    # scan_id -> list of user_ids
        self.chat_history = {}  # room_id -> list of messages
        self.shared_cursors = {}  # room_id -> {user_id: cursor_position}
        self.annotations = {}   # vulnerability_id -> list of annotations
        
        # Register Socket.IO event handlers
        self._register_events()
    
    def _register_events(self):
        """Register Socket.IO event handlers for collaboration"""
        
        @self.socketio.on('user_join')
        def handle_user_join(data):
            """Handle user joining the application"""
            user_id = data.get('user_id', str(uuid.uuid4()))
            user_info = {
                'id': user_id,
                'name': data.get('name', 'Anonymous'),
                'role': data.get('role', 'viewer'),
                'avatar': data.get('avatar', ''),
                'joined_at': datetime.now().isoformat(),
                'session_id': request.sid
            }
            
            self.active_users[user_id] = user_info
            
            # Broadcast user joined
            emit('user_joined', {
                'user': user_info,
                'total_users': len(self.active_users)
            }, broadcast=True)
            
            # Send current active users to new user
            emit('active_users_update', {
                'users': list(self.active_users.values())
            })
            
            logging.info(f"User {user_info['name']} joined")
        
        @self.socketio.on('user_leave')
        def handle_user_leave(data):
            """Handle user leaving the application"""
            user_id = data.get('user_id')
            
            if user_id in self.active_users:
                user_info = self.active_users.pop(user_id)
                
                # Remove user from all scan rooms
                for scan_id, users in self.scan_rooms.items():
                    if user_id in users:
                        users.remove(user_id)
                        emit('user_left_scan', {
                            'user_id': user_id,
                            'scan_id': scan_id
                        }, room=f'scan_{scan_id}')
                
                # Broadcast user left
                emit('user_left', {
                    'user_id': user_id,
                    'total_users': len(self.active_users)
                }, broadcast=True)
                
                logging.info(f"User {user_info['name']} left")
        
        @self.socketio.on('join_scan_room')
        def handle_join_scan_room(data):
            """Handle user joining a scan room for collaboration"""
            user_id = data.get('user_id')
            scan_id = data.get('scan_id')
            
            if not user_id or not scan_id:
                return
            
            room_name = f'scan_{scan_id}'
            join_room(room_name)
            
            # Add user to scan room
            if scan_id not in self.scan_rooms:
                self.scan_rooms[scan_id] = []
            
            if user_id not in self.scan_rooms[scan_id]:
                self.scan_rooms[scan_id].append(user_id)
            
            user_info = self.active_users.get(user_id, {'name': 'Unknown'})
            
            # Notify others in the room
            emit('user_joined_scan', {
                'user': user_info,
                'scan_id': scan_id,
                'users_in_scan': len(self.scan_rooms[scan_id])
            }, room=room_name, include_self=False)
            
            # Send scan room info to the user
            emit('scan_room_joined', {
                'scan_id': scan_id,
                'users': [self.active_users.get(uid, {'id': uid}) for uid in self.scan_rooms[scan_id]],
                'chat_history': self.chat_history.get(room_name, [])
            })
        
        @self.socketio.on('leave_scan_room')
        def handle_leave_scan_room(data):
            """Handle user leaving a scan room"""
            user_id = data.get('user_id')
            scan_id = data.get('scan_id')
            
            room_name = f'scan_{scan_id}'
            leave_room(room_name)
            
            # Remove user from scan room
            if scan_id in self.scan_rooms and user_id in self.scan_rooms[scan_id]:
                self.scan_rooms[scan_id].remove(user_id)
                
                user_info = self.active_users.get(user_id, {'name': 'Unknown'})
                
                # Notify others in the room
                emit('user_left_scan', {
                    'user': user_info,
                    'scan_id': scan_id,
                    'users_in_scan': len(self.scan_rooms[scan_id])
                }, room=room_name)
        
        @self.socketio.on('send_chat_message')
        def handle_chat_message(data):
            """Handle chat messages in scan rooms"""
            user_id = data.get('user_id')
            scan_id = data.get('scan_id')
            message = data.get('message', '').strip()
            
            if not message or len(message) > 1000:  # Message length limit
                return
            
            user_info = self.active_users.get(user_id, {'name': 'Unknown'})
            room_name = f'scan_{scan_id}'
            
            chat_message = {
                'id': str(uuid.uuid4()),
                'user_id': user_id,
                'user_name': user_info.get('name', 'Unknown'),
                'user_avatar': user_info.get('avatar', ''),
                'message': message,
                'timestamp': datetime.now().isoformat(),
                'type': 'message'
            }
            
            # Store in chat history
            if room_name not in self.chat_history:
                self.chat_history[room_name] = []
            
            self.chat_history[room_name].append(chat_message)
            
            # Keep only last 100 messages
            if len(self.chat_history[room_name]) > 100:
                self.chat_history[room_name] = self.chat_history[room_name][-100:]
            
            # Broadcast to room
            emit('chat_message_received', chat_message, room=room_name)
        
        @self.socketio.on('vulnerability_annotation')
        def handle_vulnerability_annotation(data):
            """Handle vulnerability annotations and comments"""
            user_id = data.get('user_id')
            vulnerability_id = data.get('vulnerability_id')
            annotation_type = data.get('type', 'comment')  # comment, highlight, note
            content = data.get('content', '')
            position = data.get('position', {})  # For highlighting specific parts
            
            user_info = self.active_users.get(user_id, {'name': 'Unknown'})
            
            annotation = {
                'id': str(uuid.uuid4()),
                'user_id': user_id,
                'user_name': user_info.get('name'),
                'vulnerability_id': vulnerability_id,
                'type': annotation_type,
                'content': content,
                'position': position,
                'timestamp': datetime.now().isoformat(),
                'resolved': False
            }
            
            # Store annotation
            if vulnerability_id not in self.annotations:
                self.annotations[vulnerability_id] = []
            
            self.annotations[vulnerability_id].append(annotation)
            
            # Broadcast to all users viewing this vulnerability
            emit('annotation_added', annotation, broadcast=True)
        
        @self.socketio.on('cursor_position_update')
        def handle_cursor_position(data):
            """Handle real-time cursor position sharing"""
            user_id = data.get('user_id')
            scan_id = data.get('scan_id')
            position = data.get('position', {})
            
            room_name = f'scan_{scan_id}'
            
            if room_name not in self.shared_cursors:
                self.shared_cursors[room_name] = {}
            
            self.shared_cursors[room_name][user_id] = {
                'position': position,
                'user': self.active_users.get(user_id, {'name': 'Unknown'}),
                'timestamp': datetime.now().isoformat()
            }
            
            # Broadcast cursor position to others in room
            emit('cursor_position_updated', {
                'user_id': user_id,
                'position': position,
                'user': self.active_users.get(user_id, {'name': 'Unknown'})
            }, room=room_name, include_self=False)
        
        @self.socketio.on('scan_highlight')
        def handle_scan_highlight(data):
            """Handle highlighting elements during collaborative scanning"""
            user_id = data.get('user_id')
            scan_id = data.get('scan_id')
            element_id = data.get('element_id')
            highlight_type = data.get('type', 'focus')  # focus, vulnerability, note
            
            room_name = f'scan_{scan_id}'
            user_info = self.active_users.get(user_id, {'name': 'Unknown'})
            
            # Broadcast highlight to others in room
            emit('element_highlighted', {
                'user_id': user_id,
                'user_name': user_info.get('name'),
                'element_id': element_id,
                'type': highlight_type,
                'timestamp': datetime.now().isoformat()
            }, room=room_name, include_self=False)
        
        @self.socketio.on('request_assistance')
        def handle_assistance_request(data):
            """Handle requests for assistance from team members"""
            user_id = data.get('user_id')
            scan_id = data.get('scan_id')
            assistance_type = data.get('type', 'general')  # general, vulnerability, technical
            message = data.get('message', '')
            
            user_info = self.active_users.get(user_id, {'name': 'Unknown'})
            room_name = f'scan_{scan_id}'
            
            assistance_request = {
                'id': str(uuid.uuid4()),
                'user_id': user_id,
                'user_name': user_info.get('name'),
                'type': assistance_type,
                'message': message,
                'scan_id': scan_id,
                'timestamp': datetime.now().isoformat(),
                'status': 'open'
            }
            
            # Broadcast assistance request
            emit('assistance_requested', assistance_request, room=room_name, include_self=False)
            
            # Also broadcast to admin/senior users globally
            emit('global_assistance_request', assistance_request, broadcast=True)
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle user disconnection"""
            # Find and remove user from active users
            session_id = request.sid
            user_to_remove = None
            
            for user_id, user_info in self.active_users.items():
                if user_info.get('session_id') == session_id:
                    user_to_remove = user_id
                    break
            
            if user_to_remove:
                user_info = self.active_users.pop(user_to_remove)
                
                # Remove from all scan rooms
                for scan_id, users in self.scan_rooms.items():
                    if user_to_remove in users:
                        users.remove(user_to_remove)
                        emit('user_left_scan', {
                            'user_id': user_to_remove,
                            'scan_id': scan_id
                        }, room=f'scan_{scan_id}')
                
                # Broadcast user disconnected
                emit('user_disconnected', {
                    'user_id': user_to_remove,
                    'total_users': len(self.active_users)
                }, broadcast=True)
    
    def send_scan_progress_to_room(self, scan_id: str, progress_data: Dict):
        """Send scan progress updates to all users in the scan room"""
        room_name = f'scan_{scan_id}'
        
        self.socketio.emit('scan_progress_update', {
            'scan_id': scan_id,
            **progress_data,
            'timestamp': datetime.now().isoformat()
        }, room=room_name)
    
    def send_vulnerability_found_to_room(self, scan_id: str, vulnerability: Dict):
        """Send new vulnerability alerts to scan room"""
        room_name = f'scan_{scan_id}'
        
        self.socketio.emit('vulnerability_found', {
            'scan_id': scan_id,
            'vulnerability': vulnerability,
            'timestamp': datetime.now().isoformat()
        }, room=room_name)
    
    def send_system_notification(self, message: str, notification_type: str = 'info'):
        """Send system-wide notifications"""
        
        notification = {
            'id': str(uuid.uuid4()),
            'type': notification_type,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        
        self.socketio.emit('system_notification', notification, broadcast=True)
    
    def get_room_statistics(self, scan_id: str) -> Dict:
        """Get statistics for a scan room"""
        room_name = f'scan_{scan_id}'
        
        return {
            'scan_id': scan_id,
            'active_users': len(self.scan_rooms.get(scan_id, [])),
            'chat_messages': len(self.chat_history.get(room_name, [])),
            'annotations': sum(1 for vuln_id, annotations in self.annotations.items() 
                             if any(ann.get('scan_id') == scan_id for ann in annotations)),
            'last_activity': max([
                msg.get('timestamp', '') for msg in self.chat_history.get(room_name, [])
            ] + [datetime.now().isoformat()]) if self.chat_history.get(room_name) else None
        }
    
    def get_user_activity(self, user_id: str) -> Dict:
        """Get activity summary for a user"""
        user_info = self.active_users.get(user_id, {})
        
        # Count user's contributions
        chat_count = sum(
            len([msg for msg in messages if msg.get('user_id') == user_id])
            for messages in self.chat_history.values()
        )
        
        annotation_count = sum(
            len([ann for ann in annotations if ann.get('user_id') == user_id])
            for annotations in self.annotations.values()
        )
        
        # Get active scan rooms for user
        active_rooms = [
            scan_id for scan_id, users in self.scan_rooms.items()
            if user_id in users
        ]
        
        return {
            'user_id': user_id,
            'user_info': user_info,
            'chat_messages_sent': chat_count,
            'annotations_made': annotation_count,
            'active_scan_rooms': active_rooms,
            'session_duration': self._calculate_session_duration(user_info)
        }
    
    def _calculate_session_duration(self, user_info: Dict) -> str:
        """Calculate how long a user has been active"""
        joined_at = user_info.get('joined_at')
        if not joined_at:
            return '0 minutes'
        
        try:
            join_time = datetime.fromisoformat(joined_at)
            duration = datetime.now() - join_time
            
            hours = duration.seconds // 3600
            minutes = (duration.seconds % 3600) // 60
            
            if hours > 0:
                return f'{hours}h {minutes}m'
            else:
                return f'{minutes}m'
        except:
            return 'Unknown'
    
    def export_collaboration_data(self, scan_id: str) -> Dict:
        """Export collaboration data for a scan"""
        room_name = f'scan_{scan_id}'
        
        return {
            'scan_id': scan_id,
            'participants': [
                self.active_users.get(user_id, {'id': user_id})
                for user_id in self.scan_rooms.get(scan_id, [])
            ],
            'chat_history': self.chat_history.get(room_name, []),
            'annotations': [
                ann for vuln_annotations in self.annotations.values()
                for ann in vuln_annotations
                if ann.get('scan_id') == scan_id
            ],
            'statistics': self.get_room_statistics(scan_id),
            'exported_at': datetime.now().isoformat()
        }
    
    def cleanup_inactive_sessions(self):
        """Clean up inactive sessions and old data"""
        current_time = datetime.now()
        
        # Remove users inactive for more than 1 hour
        inactive_users = []
        for user_id, user_info in self.active_users.items():
            try:
                joined_at = datetime.fromisoformat(user_info.get('joined_at', ''))
                if (current_time - joined_at).seconds > 3600:  # 1 hour
                    inactive_users.append(user_id)
            except:
                continue
        
        for user_id in inactive_users:
            self.active_users.pop(user_id, None)
        
        # Clean up empty scan rooms
        empty_rooms = [
            scan_id for scan_id, users in self.scan_rooms.items()
            if not users
        ]
        
        for scan_id in empty_rooms:
            self.scan_rooms.pop(scan_id, None)
        
        # Clean up old chat history (keep last 24 hours)
        for room_name, messages in self.chat_history.items():
            recent_messages = []
            for msg in messages:
                try:
                    msg_time = datetime.fromisoformat(msg.get('timestamp', ''))
                    if (current_time - msg_time).seconds < 86400:  # 24 hours
                        recent_messages.append(msg)
                except:
                    continue
            
            self.chat_history[room_name] = recent_messages
    
    def get_collaboration_status(self) -> Dict:
        """Get overall collaboration system status"""
        return {
            'active_users': len(self.active_users),
            'active_scan_rooms': len(self.scan_rooms),
            'total_chat_messages': sum(len(messages) for messages in self.chat_history.values()),
            'total_annotations': sum(len(annotations) for annotations in self.annotations.values()),
            'system_status': 'active',
            'features_enabled': [
                'Real-time Chat',
                'Vulnerability Annotations',
                'Cursor Sharing',
                'Collaborative Highlighting',
                'Assistance Requests',
                'Live Progress Updates'
            ]
        }
