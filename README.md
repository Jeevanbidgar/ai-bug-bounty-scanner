# 🛡️ AI Bug Bounty Scanner

**Professional Security Tool Orchestration Platform** - Desktop Application

A cross-platform desktop application for orchestrating reconnaissance and penetration testing tools like subfinder, amass, nuclei, nmap, and sqlmap.

---

## 🚀 Quick Start

### **Windows**

1. **Start Application**

   ```
   Double-click: start.bat
   ```

2. **Stop Application**
   ```
   Double-click: stop.bat
   ```

That's it! The desktop window will open automatically.

---

## 📋 Requirements

- **Python 3.11+**
- **Node.js 18+**
- **Rust** (for building)
- **Windows 10/11** (Linux/Mac support planned)

---

## 🎯 Features

- ✅ **Native Desktop App** - Built with Tauri + Rust
- ✅ **Modern UI** - React + TypeScript + Tailwind CSS
- ✅ **Tool Orchestration** - Manage security tools from one place
- ✅ **Real-time Monitoring** - Live scan progress and results
- ✅ **Production Ready** - Error handling, logging, metrics
- ✅ **Secure** - Rate limiting, input validation, resource limits
- ✅ **Cross-platform** - Windows, Linux, macOS (planned)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────┐
│     Desktop App (Tauri/Rust)        │
│  ┌───────────────────────────────┐  │
│  │   React Frontend (UI)         │  │
│  │   - Dashboard                 │  │
│  │   - Tool Management           │  │
│  │   - Scan Orchestration        │  │
│  └───────────────────────────────┘  │
└─────────────────┬───────────────────┘
                  │ HTTP
     ┌────────────▼──────────────┐
     │  Python FastAPI Backend   │
     │  - Security Tools         │
     │  - Scan Engine            │
     │  - SQLite Database        │
     └───────────────────────────┘
```

---

## 🛠️ Supported Tools

- **Subdomain Discovery**: subfinder, amass
- **URL Discovery**: waybackurls, gau
- **Port Scanning**: naabu, nmap
- **Vulnerability Scanning**: nuclei
- **Web Fuzzing**: ffuf, gobuster
- **SQL Injection**: sqlmap

---

## 📖 Usage

### **First Launch**

1. Double-click `start.bat`
2. Wait 2-3 minutes (compiling Rust)
3. Desktop window opens automatically

### **Subsequent Launches**

1. Double-click `start.bat`
2. Desktop window opens in 5-10 seconds

### **Dashboard**

- View system health
- See available tools
- Quick scan functionality

### **Tools Page**

- View all security tools
- Check installation status
- Tool descriptions and usage

### **Scans Page**

- Create new scans
- View scan history
- Monitor progress

### **Reports Page**

- Generate reports
- Export as PDF/HTML/JSON
- Download results

---

## 🔧 Development

### **Setup**

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Node dependencies
cd frontend
npm install

# First time setup
cd ..
start.bat
```

### **Development Mode**

```bash
# Runs with hot reload
start.bat
```

### **Production Build**

```bash
# Creates installer (.msi)
cd frontend
npm run tauri build
```

**Output**: `src-tauri/target/release/bundle/msi/AI Bug Bounty Scanner_2.0.0_x64.msi`

---

## 📊 Tech Stack

### **Frontend**

- React 18 + TypeScript
- Vite (build tool)
- Tailwind CSS
- React Query (data fetching)
- Tauri (desktop framework)

### **Backend**

- FastAPI (Python async)
- SQLAlchemy + SQLite
- Pydantic (validation)
- Structlog (logging)
- Prometheus (metrics)

### **Desktop**

- Tauri 1.x (Rust)
- Native window
- System integration

---

## 🔒 Security Features

- ✅ **Input Validation** - Pydantic schemas with regex validation
- ✅ **Rate Limiting** - SlowAPI with configurable limits
- ✅ **Resource Limits** - CPU, memory, execution time monitoring
- ✅ **Error Handling** - Comprehensive error catching and logging
- ✅ **CORS Protection** - Configured for desktop app only
- ✅ **Structured Logging** - JSON logs for audit trails

---

## 📈 Monitoring

### **Metrics Endpoint**

```
http://localhost:8000/metrics
```

View Prometheus metrics:

- HTTP requests (count, duration)
- Tool executions (count, failures)
- Resource usage (CPU, memory)
- Error rates

### **Health Check**

```
http://localhost:8000/api/health/
```

---

## 🐛 Troubleshooting

### **App won't start?**

1. Check Python is installed: `python --version`
2. Check Node is installed: `node --version`
3. Check Rust is installed: `cargo --version`
4. Run `stop.bat` then `start.bat`

### **Backend errors?**

```bash
# Check logs in backend PowerShell window
# or manually test:
cd backend
python run.py
```

### **Frontend errors?**

```bash
# Rebuild frontend
cd frontend
npm install
npm run dev
```

### **Port conflicts?**

- Backend uses port **8000**
- Frontend uses port **5173**
- Run `stop.bat` to free ports

---

## 📁 Project Structure

```
ai-bug-bounty-scanner/
├── assets/              # Images and icons
│   ├── app-icon.png     # Main application icon
│   └── *.png            # Generated icon sizes
├── backend/             # Python FastAPI backend
│   ├── api/             # API endpoints
│   ├── services/        # Business logic
│   ├── models.py        # Database models
│   └── main.py          # FastAPI app
├── frontend/            # React frontend
│   ├── src/
│   │   ├── pages/       # UI pages
│   │   ├── components/  # React components
│   │   └── services/    # API client
│   └── package.json
├── src-tauri/           # Rust desktop wrapper
│   ├── icons/           # Desktop app icons
│   ├── src/main.rs      # Tauri commands
│   └── tauri.conf.json  # App config
├── data/                # SQLite database
├── start.bat            # ▶️ START HERE!
├── stop.bat             # ⏹️ Stop application
└── README.md            # 📖 This file
```

---

## 🎨 Icon

The application uses a custom cyberpunk-themed icon located in `assets/app-icon.png`.

To replace:

1. Add your PNG (1024x1024) as `assets/app-icon.png`
2. Rebuild: `npm run tauri build`

---

## 📝 Configuration

Edit `.env` file:

```env
# Application
ENVIRONMENT=development
DEBUG=True

# Server
HOST=127.0.0.1
PORT=8000

# Security
SECRET_KEY=your-secret-key-here

# Resource Limits
MAX_MEMORY_MB=1024
MAX_CPU_PERCENT=80
MAX_EXECUTION_TIME=600
```

---

## 🚢 Deployment

### **For End Users**

1. Build installer: `cd frontend && npm run tauri build`
2. Share the `.msi` file from `src-tauri/target/release/bundle/msi/`
3. User double-clicks to install
4. App appears in Start Menu

### **For Developers**

- Use `start.bat` for development
- Backend auto-reloads on code changes
- Frontend hot-reloads via Vite

---

## 🤝 Contributing

This is a professional security tool. Contributions welcome!

### **Before contributing:**

1. Test with `start.bat`
2. Ensure no errors in console
3. Run linters
4. Test on Windows

---

## ⚖️ License

MIT License - Use responsibly and ethically.

**Important**: This tool is for authorized security testing only. Always get permission before scanning targets.

---

## 📞 Support

For issues:

1. Check this README
2. Review PowerShell window errors
3. Check `backend/logs/` directory

---

## 🎯 Roadmap

- [ ] Linux support
- [ ] macOS support
- [ ] Docker integration
- [ ] CI/CD pipeline
- [ ] Plugin system
- [ ] Report templates
- [ ] Dark/Light theme toggle
- [ ] Multi-language support

---

**Made with ❤️ for security professionals**

**Version**: 2.0.0  
**Last Updated**: 2025-09-30

---

## 🚀 TL;DR

```bash
# Just do this:
start.bat

# When done:
stop.bat
```

**That's it!** 🎉
