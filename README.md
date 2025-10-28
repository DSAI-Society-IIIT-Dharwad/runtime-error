# Home Net Guardian 🛡️

A privacy-focused, local-first home network monitoring system with real-time anomaly detection and IoT device fingerprinting.

![Dashboard](docs/screenshots/dashboard.png)

## 🚀 Features

### Guardian Network Monitor
- **Real-time packet capture** and offline PCAP analysis
- **ML-powered anomaly detection** using Isolation Forest
- **IoT device fingerprinting** with vendor identification
- **Real-time alerts** for suspicious network activity
- **Privacy-first**: All data stays local
- **Beautiful dashboard** with live updates via WebSocket

### 🆕 Enterprise Security Scanner
- **Multi-engine scanning**: ZAP (DAST), Nuclei, Nmap, Trivy
- **CVE enrichment**: EPSS scores + CISA KEV catalog integration
- **Professional reporting**: HTML/PDF/JSON with executive summaries
- **CI/CD ready**: GitHub Actions workflow included
- **Interactive UI**: Streamlit-based demo interface

> **See [SECURITY_SCANNER_README.md](SECURITY_SCANNER_README.md) for the complete security scanner documentation**

## ⚠️ Legal & Ethical Notice

**IMPORTANT**: Only use this tool on networks you own or have explicit permission to monitor. Unauthorized network monitoring may violate laws and regulations. The authors assume no liability for misuse.

## 🏗️ Architecture

See [docs/architecture.svg](docs/architecture.svg) for the full system design.

```
Guardian Network Monitor:
Packet Capture → Feature Extraction → ML/Heuristics → Database
                                                         ↓
Frontend ← WebSocket ← FastAPI Backend ←──────────────┘

Enterprise Security Scanner (NEW):
Orchestrator → [ZAP | Nuclei | Nmap | Trivy] → Normalize → Enrich (EPSS/KEV) → Report
```

## 📦 Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+ (for local development)
- Node.js 18+ (for local development)
- Linux: libpcap-dev
- macOS: Recommend using PCAP mode
- Windows: Recommend using PCAP mode or Npcap

### Guardian Network Monitor (Using Docker)

```bash
# Clone the repository
git clone https://github.com/yourusername/home-net-guardian.git
cd home-net-guardian

# Start the application
make dev

# Open http://localhost:5173 in your browser
```

### Enterprise Security Scanner

```bash
# Quick start (5 minutes)
pip install -r scanner/requirements.txt

# Install tools: ZAP, Nuclei, Nmap, Trivy
# See scanner/INSTALLATION.md for details

# Run first scan
python -m scanner.orchestrator --targets https://example.com --passive-only

# Or use interactive UI
streamlit run streamlit_app.py
```

**📚 Full documentation**: [SCANNER_QUICKSTART.md](SCANNER_QUICKSTART.md) | [SECURITY_SCANNER_README.md](SECURITY_SCANNER_README.md)

### Test with Sample Data

```bash
# Generate synthetic PCAP and run in offline mode
make pcap

# Or manually upload data/sample.pcap via the UI
```

## 🔧 Configuration

The system can operate in two modes:

1. **Live Capture Mode** (requires privileges)
   ```bash
   CAPTURE_MODE=live IFACE=eth0 make dev
   ```

2. **PCAP Mode** (default, safer)
   ```bash
   CAPTURE_MODE=pcap PCAP_PATH=data/sample.pcap make dev
   ```

### Non-root Packet Capture (Linux)

```bash
# Grant capabilities to Python
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Or run backend with sudo (not recommended for production)
```

## 📊 Dashboard Components

- **KPI Cards**: Active devices, recent alerts, suspicious destinations
- **Device Table**: All discovered devices with vendor info and risk scores
- **Flow Graph**: Interactive visualization of network communications
- **Alert List**: Real-time security alerts with severity levels
- **Settings**: Configure thresholds and capture modes

## 🧪 Testing

```bash
# Run backend tests
make test

# Lint checks
cd backend && ruff check . && black --check .
cd frontend && pnpm lint
```

## 🐳 Production Deployment

1. Update `.env` with production values
2. Use proper TLS termination (nginx/traefik)
3. Implement authentication if exposed beyond localhost
4. Consider log aggregation and monitoring
5. Regular model retraining based on your network

## 📝 Environment Variables

See `backend/.env.example` for all configuration options:

- `CAPTURE_MODE`: live or pcap
- `IFACE`: Network interface for live capture
- `PCAP_PATH`: Path to PCAP file for offline analysis
- `ANOMALY_CONTAMINATION`: Expected proportion of anomalies (default: 0.02)
- `WS_ORIGIN`: Allowed WebSocket origin

## 🤝 Contributing

Contributions are welcome! Please ensure:
- Tests pass
- Code is linted
- Documentation is updated

## 📄 License

MIT License - see LICENSE file

## 🙏 Acknowledgments

- Scapy for packet manipulation
- FastAPI for the backend framework
- React & Vite for the frontend
- Scikit-learn for anomaly detection

## 📸 Screenshots

### Dashboard
![Dashboard](docs/screenshots/dashboard.png)

### Alerts
![Alerts](docs/screenshots/alerts.png)

### Flow Graph
![Flow Graph](docs/screenshots/flow-graph.png)

---

**Security Notice**: This tool is designed for legitimate security monitoring of your own networks. Always comply with local laws and regulations.
