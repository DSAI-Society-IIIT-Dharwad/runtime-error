# Home Net Guardian 🛡️

> A privacy-focused, real-time home network security monitoring system with ML-powered anomaly detection and IoT device fingerprinting.

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18+-61DAFB.svg)](https://reactjs.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Directory Structure](#directory-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## 🔍 Overview

**Home Net Guardian** is a comprehensive network security monitoring solution designed for home and small business networks. It provides real-time packet capture, intelligent anomaly detection, and detailed device fingerprinting—all running locally to protect your privacy.

### Key Capabilities

- **Dual Operation Modes**: Real-time live capture or offline PCAP file analysis
- **ML-Powered Detection**: Uses Isolation Forest and heuristic rules to identify threats
- **Device Fingerprinting**: Automatically identifies devices using MAC vendor lookup and behavioral analysis
- **Docker Container Monitoring**: Tracks network activity of containerized applications
- **Real-time Dashboard**: Beautiful WebSocket-powered interface with live updates
- **Privacy-First**: All data stays on your local network—no cloud dependencies

## ✨ Features

### Network Monitoring
- ✅ Live packet capture from network interfaces
- ✅ PCAP file upload and analysis
- ✅ Network flow aggregation and tracking
- ✅ Protocol analysis (TCP, UDP, ICMP, DNS, HTTP, TLS)
- ✅ SNI extraction for HTTPS traffic

### Security & Detection
- ✅ ML-based anomaly detection using Isolation Forest
- ✅ Heuristic-based threat detection rules
- ✅ Port scanning detection
- ✅ DGA domain detection
- ✅ High-risk port monitoring
- ✅ Suspicious traffic pattern identification

### Device Management
- ✅ Automatic device discovery
- ✅ MAC vendor identification (OUI lookup)
- ✅ Device role classification
- ✅ Risk scoring for each device
- ✅ Docker container tracking

### Dashboard & UI
- ✅ Real-time statistics and graphs
- ✅ Alert management with severity levels
- ✅ Device activity timeline
- ✅ Network flow visualization
- ✅ Mode switching (Live ↔ PCAP)
- ✅ Dark mode support

## 🏗️ Architecture

```
┌──────────────┐
│   Frontend   │  React + TypeScript + Vite
│  (Port 5173) │  ← WebSocket + REST API
└──────┬───────┘
       │
┌──────▼────────────────────────────────────────┐
│            FastAPI Backend                     │
│              (Port 8000)                       │
├────────────────────────────────────────────────┤
│  ┌──────────────┐      ┌─────────────────┐   │
│  │ Live Sniffer │      │  PCAP Reader    │   │
│  │  (Scapy)     │      │   (Scapy)       │   │
│  └──────┬───────┘      └────────┬────────┘   │
│         │                       │             │
│         └───────────┬───────────┘             │
│                     ▼                         │
│         ┌───────────────────────┐             │
│         │  Packet Processor     │             │
│         │  - Flow Aggregation   │             │
│         │  - Device Fingerprint │             │
│         └───────────┬───────────┘             │
│                     ▼                         │
│         ┌───────────────────────┐             │
│         │  Anomaly Detector     │             │
│         │  - Isolation Forest   │             │
│         │  - Heuristic Rules    │             │
│         └───────────┬───────────┘             │
│                     ▼                         │
│         ┌───────────────────────┐             │
│         │   SQLite Database     │             │
│         │  - Devices            │             │
│         │  - Flows              │             │
│         │  - Alerts             │             │
│         └───────────────────────┘             │
└────────────────────────────────────────────────┘
```

### Technology Stack

**Backend:**
- **FastAPI**: Modern Python web framework
- **Scapy**: Packet capture and manipulation
- **SQLModel**: Database ORM (SQLite)
- **scikit-learn**: Machine learning (Isolation Forest)
- **Docker SDK**: Container monitoring

**Frontend:**
- **React 18**: UI framework
- **TypeScript**: Type-safe JavaScript
- **Vite**: Build tool and dev server
- **TanStack Query**: Data fetching and caching
- **Recharts**: Data visualization
- **Tailwind CSS**: Utility-first styling

## 📁 Directory Structure

```
home-net-guardian/
├── backend/                    # Python FastAPI backend
│   ├── app.py                 # Main application entry point
│   ├── capture/               # Packet capture modules
│   │   ├── live_sniffer.py   # Real-time packet capture
│   │   ├── pcap_reader.py    # PCAP file analysis
│   │   ├── device_fingerprint.py  # Device identification
│   │   └── docker_monitor.py # Container monitoring
│   ├── core/                  # Core utilities
│   │   ├── config.py         # Configuration management
│   │   └── security.py       # Security utilities
│   ├── db/                    # Database layer
│   │   ├── models.py         # SQLModel database models
│   │   └── repo.py           # Repository pattern
│   ├── detection/             # Threat detection
│   │   ├── model.py          # ML anomaly detector
│   │   ├── features.py       # Feature engineering
│   │   └── heuristics.py     # Rule-based detection
│   ├── schemas/               # Pydantic schemas
│   │   ├── devices.py
│   │   ├── traffic.py
│   │   └── alerts.py
│   ├── uploads/               # Uploaded PCAP files
│   ├── logs/                  # Application logs
│   ├── guardian.db            # SQLite database
│   ├── pyproject.toml         # Python dependencies
│   └── Dockerfile             # Backend container
│
├── frontend/                  # React TypeScript frontend
│   ├── src/
│   │   ├── components/       # React components
│   │   │   ├── Dashboard.tsx # Main dashboard
│   │   │   ├── DeviceTable.tsx
│   │   │   ├── AlertList.tsx
│   │   │   ├── FlowGraph.tsx
│   │   │   ├── Settings.tsx
│   │   │   ├── PcapAnalysis.tsx
│   │   │   ├── DockerStatus.tsx
│   │   │   └── ModeIndicator.tsx
│   │   ├── lib/              # Utilities
│   │   │   ├── api.ts       # API client
│   │   │   ├── store.ts     # Zustand state management
│   │   │   └── ws.ts        # WebSocket client
│   │   ├── App.tsx          # Root component
│   │   └── main.tsx         # Entry point
│   ├── package.json          # Node dependencies
│   ├── vite.config.ts        # Vite configuration
│   └── Dockerfile            # Frontend container
│
├── data/                      # Sample data
│   ├── sample.pcap           # Sample PCAP file
│   ├── oui_sample.csv        # MAC vendor database
│   └── suspicious_domains.txt
│
├── docs/                      # Documentation
│   └── architecture.svg
│
├── compose.yaml               # Docker Compose config
├── Makefile                   # Build automation
├── PCAP-UPLOAD-GUIDE.md      # PCAP upload guide
├── PCAP-FIX-SUMMARY.md       # Recent fixes
└── README.md                  # This file
```

## 📋 Prerequisites

### Required Software

- **Docker** (v20.10+) & **Docker Compose** (v2.0+)
- **Git** for cloning the repository

### For Local Development (Optional)

- **Python 3.11+** with pip
- **Node.js 18+** with pnpm
- **libpcap-dev** (Linux) or **Npcap** (Windows)

### System Requirements

- **RAM**: 2GB minimum, 4GB recommended
- **Disk**: 500MB for application + space for PCAP files
- **Network**: Access to the network interface you want to monitor

### Operating System Notes

- **Linux**: Full support for live capture (requires root or capabilities)
- **macOS**: PCAP mode recommended (live capture may require admin privileges)
- **Windows**: PCAP mode recommended (requires Npcap for live capture)

## 🚀 Installation

### Method 1: Docker (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/home-net-guardian.git
cd home-net-guardian

# 2. Start the application
docker-compose up -d

# 3. Access the dashboard
# Open http://localhost:5173 in your browser

# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

### Method 2: Local Development

**Backend:**
```bash
cd backend

# Install dependencies
pip install -r requirements.txt
# OR
poetry install

# Run the backend
python app.py
```

**Frontend:**
```bash
cd frontend

# Install dependencies
pnpm install

# Run the dev server
pnpm dev
```

## 📖 Usage

### Starting the Application

**Using Docker:**
```bash
# Start in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

**Using Makefile:**
```bash
make dev      # Start development environment
make stop     # Stop all services
make clean    # Clean up containers and volumes
```

### Operation Modes

The system operates in two distinct modes:

#### 1. **PCAP Mode** (Default - Safe)

Analyze pre-captured network traffic files.

**Steps:**
1. Go to **Settings** page
2. Select **PCAP Mode**
3. Click **Upload** and choose a `.pcap` file
4. Wait for analysis to complete
5. View results on **Dashboard** and **Devices** pages

**Benefits:**
- No special permissions required
- Safe for testing and learning
- Analyze historical traffic
- Great for demos and development

#### 2. **Live Capture Mode** (Requires Privileges)

Monitor real-time network traffic.

**Steps:**
1. Grant necessary permissions (see below)
2. Go to **Settings** page
3. Select **Live Mode**
4. Choose network interface (e.g., `eth0`, `wlan0`)
5. Click **Switch Mode**
6. Monitor live traffic on dashboard

**Requirements:**
```bash
# Linux: Grant capabilities
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Or run with Docker in privileged mode
docker-compose -f compose.yaml up -d
```

### Using Sample Data

```bash
# The project includes sample PCAP files
cd data/

# Upload via UI:
# Settings → PCAP Mode → Upload → Select sample.pcap

# Or set environment variable:
export PCAP_PATH=./data/sample.pcap
docker-compose up -d
```

### Uploading PCAP Files

1. **Supported formats**: `.pcap`, `.pcapng`
2. **Location**: Files are saved to `backend/uploads/`
3. **Analysis**: Automatic extraction of:
   - Devices (MAC addresses, IPs, vendors)
   - Network flows (connections, protocols, bytes)
   - Alerts (anomalies, suspicious patterns)

See [PCAP-UPLOAD-GUIDE.md](PCAP-UPLOAD-GUIDE.md) for detailed instructions.

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Backend Configuration
API_HOST=0.0.0.0
API_PORT=8000
LOG_LEVEL=INFO

# Capture Mode: 'live' or 'pcap'
CAPTURE_MODE=pcap

# Live Capture Settings
IFACE=eth0                    # Network interface

# PCAP Mode Settings
PCAP_PATH=./data/sample.pcap  # Path to PCAP file

# Database
DB_URL=sqlite:///guardian.db

# Security
HIGH_RISK_PORTS=22,23,3389,445,1433,3306,5432
FLOW_WINDOW_SECONDS=60

# ML Model
ANOMALY_CONTAMINATION=0.02    # Expected % of anomalies
MODEL_RETRAIN_HOURS=24        # Retrain interval

# WebSocket
WS_UPDATE_INTERVAL=2          # Seconds between updates
WS_ORIGIN=http://localhost:5173

# CORS
CORS_ORIGINS=["http://localhost:5173"]
```

### Adjusting Detection Sensitivity

Edit `backend/core/config.py`:

```python
# Lower = more sensitive (more alerts)
anomaly_contamination: float = 0.01

# Higher = more aggressive detection
high_risk_ports = [22, 23, 445, 3389, ...]
```

## 📚 API Documentation

### REST API

Once running, visit: **http://localhost:8000/docs**

Key endpoints:

**Devices:**
- `GET /api/devices` - List all devices
- `GET /api/devices/{mac}` - Get device details
- `GET /api/devices/{mac}/activity` - Device activity summary

**Flows:**
- `GET /api/flows` - List network flows
- `GET /api/flows/statistics` - Flow statistics
- `GET /api/flows/top-talkers` - Top bandwidth consumers

**Alerts:**
- `GET /api/alerts` - List security alerts
- `POST /api/alerts` - Create alert
- `PATCH /api/alerts/{id}` - Update alert status

**Capture:**
- `GET /api/capture/status` - Capture status
- `POST /api/capture/mode` - Switch capture mode
- `POST /api/capture/pcap` - Upload PCAP file

**Detection:**
- `POST /api/detect/anomaly` - Run anomaly detection
- `POST /api/model/train` - Train ML model
- `GET /api/model/info` - Model information

### WebSocket

Connect to: `ws://localhost:8000/ws/stream`

**Message format:**
```json
{
  "type": "update",
  "timestamp": "2025-10-29T10:30:00Z",
  "data": {
    "devices": [...],
    "flows": [...],
    "alerts": [...]
  }
}
```

## 🐛 Troubleshooting

### PCAP Upload Issues

**Problem**: File uploads but shows 0 devices/flows

**Solution**: 
- Check `backend/logs/guardian.log` for errors
- Ensure PCAP file is valid (test with Wireshark)
- Verify file is in `backend/uploads/`
- See [PCAP-FIX-SUMMARY.md](PCAP-FIX-SUMMARY.md)

### Permission Errors (Live Mode)

**Linux:**
```bash
# Grant capabilities
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Or run with sudo (not recommended)
sudo python backend/app.py
```

**Docker:**
```bash
# Run in privileged mode
docker-compose -f compose.host.yaml up -d
```

### No Network Interfaces Found

```bash
# List available interfaces
ip link show       # Linux
ifconfig          # macOS/BSD
ipconfig          # Windows

# Update IFACE environment variable
export IFACE=your_interface_name
```

### Database Locked Errors

```bash
# Stop all services
docker-compose down

# Remove database (WARNING: loses data)
rm backend/guardian.db

# Restart
docker-compose up -d
```

### Frontend Not Loading

```bash
# Check if services are running
docker-compose ps

# Rebuild frontend
cd frontend
pnpm install
pnpm build

# Or rebuild containers
docker-compose up -d --build
```

## 🧪 Testing

```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
pnpm test

# Linting
cd backend && ruff check . && black --check .
cd frontend && pnpm lint
```

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup

```bash
# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Run tests before committing
make test
```

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## ⚠️ Legal & Ethical Notice

**IMPORTANT**: This tool is designed for **legitimate security monitoring** of networks you own or have explicit permission to monitor.

- ✅ **Legal Uses**: Monitoring your home network, analyzing your own traffic
- ❌ **Illegal Uses**: Unauthorized network monitoring, intercepting others' traffic

**The authors assume no liability for misuse of this software.** Always comply with local laws and regulations regarding network monitoring and data privacy.

## 🙏 Acknowledgments

- **[Scapy](https://scapy.net/)** - Powerful packet manipulation library
- **[FastAPI](https://fastapi.tiangolo.com/)** - Modern Python web framework
- **[React](https://reactjs.org/)** - Frontend UI library
- **[scikit-learn](https://scikit-learn.org/)** - Machine learning library
- **[Recharts](https://recharts.org/)** - React charting library

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/home-net-guardian/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/home-net-guardian/discussions)
- **Documentation**: [Wiki](https://github.com/yourusername/home-net-guardian/wiki)

## 🗺️ Roadmap

- [ ] Multi-interface capture support
- [ ] Advanced protocol dissectors
- [ ] Machine learning model improvements
- [ ] Mobile app for monitoring
- [ ] Cloud sync (optional, encrypted)
- [ ] Exportable reports (PDF)
- [ ] Integration with SIEM systems

---

**Made with ❤️ for network security enthusiasts**

*Star ⭐ this repository if you find it helpful!*
