# Home Net Guardian - Backend

FastAPI-based backend for home network security monitoring.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Capture   │────▶│   Detection  │────▶│     API     │
│  (Scapy)    │     │  (ML/Rules)  │     │  (FastAPI)  │
└─────────────┘     └──────────────┘     └─────────────┘
       │                    │                     │
       ▼                    ▼                     ▼
┌─────────────────────────────────────────────────────┐
│                   SQLite Database                    │
└─────────────────────────────────────────────────────┘
```

## Setup

### Prerequisites

- Python 3.11+
- Poetry for dependency management
- libpcap-dev (Linux) or Npcap (Windows)

### Installation

```bash
# Install dependencies
poetry install

# Copy environment file
cp .env.example .env

# Run migrations
poetry run python -c "from db.models import create_tables; create_tables()"
```

### Development

```bash
# Run with hot reload
poetry run uvicorn app:app --reload --host 0.0.0.0 --port 8000

# Or use the Makefile from root
make backend
```

## Packet Capture Modes

### Live Capture (requires privileges)

```bash
# Linux: Grant capabilities
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Then run normally
CAPTURE_MODE=live IFACE=eth0 poetry run python app.py
```

### PCAP Mode (recommended for testing)

```bash
CAPTURE_MODE=pcap PCAP_PATH=data/sample.pcap poetry run python app.py
```

## API Endpoints

### REST API

- `GET /api/devices` - List all discovered devices
- `GET /api/flows?since={timestamp}` - Get network flows
- `GET /api/alerts?since={timestamp}` - Get security alerts
- `POST /api/mode` - Switch capture mode
- `POST /api/pcap` - Upload PCAP file
- `GET /health` - Health check

### WebSocket

- `/ws/stream` - Real-time updates stream

Message format:
```json
{
  "type": "update",
  "data": {
    "devices": [...],
    "flows": [...],
    "alerts": [...]
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## Detection System

### Machine Learning

- **Algorithm**: Isolation Forest (unsupervised anomaly detection)
- **Features**: Traffic patterns, port entropy, DNS behavior
- **Retraining**: Automatic daily retraining on baseline data

### Heuristic Rules

1. High-risk port access (23, 2323, 445, etc.)
2. DNS tunneling detection (high QPS, random subdomains)
3. Unusual TLS patterns (rapid SNI changes)
4. Outbound connections to non-RFC1918 addresses

## Database Schema

### Tables

- `devices`: MAC, IP, vendor, first/last seen, risk score
- `flows`: Source/dest IP:port, protocol, bytes, packets
- `alerts`: Timestamp, severity, title, details, associations

## Testing

```bash
# Run tests with coverage
poetry run pytest tests/ -v --cov

# Lint
poetry run ruff check .
poetry run black --check .
```

## Performance Tuning

- Adjust `FLOW_WINDOW_SECONDS` for flow aggregation
- Modify `MAX_FLOWS_CACHE` based on memory availability
- Tune `ANOMALY_CONTAMINATION` for your network

## Security Considerations

1. **Privileges**: Use capabilities instead of root when possible
2. **Data**: All data stays local, no external telemetry
3. **API**: Bind to localhost only in production
4. **CORS**: Configure allowed origins carefully

## Troubleshooting

### Permission Denied on Capture

```bash
# Check capabilities
getcap $(which python3)

# Re-apply if needed
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

### High Memory Usage

Reduce cache sizes in `.env`:
```
MAX_FLOWS_CACHE=5000
MAX_ALERTS_CACHE=500
```

### Model Not Detecting Anomalies

Adjust contamination factor:
```
ANOMALY_CONTAMINATION=0.05  # Increase for more sensitive detection
```
