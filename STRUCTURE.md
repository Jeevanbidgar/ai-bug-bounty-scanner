# AI Bug Bounty Scanner - Project Structure

## Clean, Modular Architecture

```
ai-bug-bounty-scanner/
├── 📁 core/                    # Core application components
│   ├── config.py              # Environment configuration management
│   ├── celery_app.py          # Celery application factory
│   └── __init__.py            # Core module initialization
│
├── 📁 database/               # Database layer
│   ├── models.py              # SQLAlchemy models
│   ├── database.py            # Database connection and utilities
│   └── __init__.py
│
├── 📁 auth/                   # Authentication and authorization
│   ├── auth_manager.py        # Authentication management
│   ├── decorators.py          # Auth decorators
│   └── __init__.py
│
├── 📁 api/                    # API endpoints (blueprints)
│   ├── auth_routes.py         # Authentication routes
│   ├── scan_routes.py         # Scanning endpoints
│   ├── report_routes.py       # Report management
│   ├── user_routes.py         # User management
│   ├── admin_routes.py        # Admin endpoints
│   ├── dashboard_routes.py    # Dashboard data
│   └── __init__.py
│
├── 📁 agents/                 # Security scanning agents
│   ├── recon_agent.py         # Reconnaissance agent
│   ├── webapp_agent.py        # Web application scanner
│   ├── network_agent.py       # Network scanner
│   ├── api_agent.py           # API security scanner
│   ├── report_agent.py        # Report generation
│   ├── security_validator.py  # Security validation
│   └── __init__.py
│
├── 📁 enhancements/           # Advanced features
│   ├── threat_intelligence.py # Threat intel integration
│   ├── enhanced_security_agent.py # ML-powered scanning
│   └── __init__.py
│
├── 📁 tasks/                  # Celery tasks
│   ├── scanning_tasks.py      # Async scanning tasks
│   ├── report_tasks.py        # Report generation tasks
│   └── __init__.py
│
├── 📁 utils/                  # Utility functions
│   ├── validate_env.py        # Environment validation
│   └── __init__.py
│
├── 📁 frontend/               # Vue.js frontend application
│   ├── src/                   # Source code
│   ├── public/                # Static assets
│   ├── package.json           # NPM dependencies
│   └── vite.config.js         # Vite configuration
│
├── 📁 logs/                   # Application logs
├── 📁 uploads/                # File uploads
├── 📁 backups/                # Database backups
├── 📁 instance/               # SQLite database (development)
│
├── 📁 archive/                # Archived/old files
│   ├── tests/                 # Moved test files
│   ├── old_files/             # Deprecated files
│   └── documentation/         # Old documentation
│
├── 📄 app.py                  # Main Flask application
├── 📄 requirements.txt        # Python dependencies
├── 📄 .env                    # Environment variables
├── 📄 .env.example            # Environment template
├── 📄 .env.production         # Production environment
├── 📄 setup.bat               # Windows setup script
├── 📄 README.md               # Project documentation
├── 📄 Dockerfile              # Docker configuration
├── 📄 docker-compose.yml      # Docker services
└── 📄 .gitignore              # Git ignore rules
```

## Key Components

### Core Module (`/core/`)
- **config.py**: Centralized configuration management with environment variable support
- **celery_app.py**: Celery application factory for async task processing

### Database Layer (`/database/`)
- **models.py**: SQLAlchemy ORM models
- **database.py**: Database connection management and utilities

### API Layer (`/api/`)
- Modular Flask blueprints for different functionality areas
- RESTful API design with proper error handling
- JWT authentication integration

### Agents (`/agents/`)
- Specialized security scanning agents
- Each agent handles specific vulnerability types
- Modular and extensible design

### Tasks (`/tasks/`)
- Asynchronous Celery tasks for heavy operations
- Background scanning and report generation
- Queue-based task distribution

### Frontend (`/frontend/`)
- Modern Vue.js 3 application
- Vite build system with hot reload
- Responsive design with Tailwind CSS

## Benefits of This Structure

1. **Modularity**: Each component has a clear responsibility
2. **Scalability**: Easy to add new features and agents
3. **Maintainability**: Clean separation of concerns
4. **Testability**: Isolated components for unit testing
5. **Development**: Clear development workflow
6. **Deployment**: Organized for containerization

## Quick Start

1. **Environment Setup**: Copy `.env.example` to `.env` and configure
2. **Dependencies**: Run `pip install -r requirements.txt`
3. **Validation**: Run `python utils/validate_env.py`
4. **Backend**: Run `python app.py`
5. **Frontend**: Run `cd frontend && npm run dev`

## Development Workflow

1. Backend changes: Modify `/core/`, `/api/`, `/agents/`, or `/tasks/`
2. Frontend changes: Work in `/frontend/src/`
3. Configuration: Update `.env` files as needed
4. New features: Add to appropriate modules with proper imports
5. Testing: Use archived test structure as reference

This clean, modular structure makes the application easier to develop, maintain, and scale.
