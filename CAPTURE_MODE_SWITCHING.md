# Capture Mode Switching Feature

## Overview
Added a UI control to switch between Live and PCAP capture modes without using curl commands.

## Backend Changes (FastAPI)

### New API Endpoints

1. **GET `/api/mode`**
   - Returns current capture mode configuration
   - Response: `{ "mode": "live"|"pcap", "iface": "eth0", "pcap_path": "/path/to/file.pcap" }`

2. **GET `/api/interfaces`**
   - Returns list of available network interfaces for live capture
   - Response: `["lo", "eth0", "Wi-Fi", ...]`
   - Works on Windows (requires Npcap), macOS, and Linux

3. **POST `/api/mode`**
   - Switches capture mode dynamically
   - Request body: `{ "mode": "live"|"pcap", "iface": "Wi-Fi", "pcap_path": "data/sample.pcap" }`
   - Stops current capture, updates configuration, and restarts with new mode
   - Response: Updated mode configuration

4. **POST `/api/pcap`**
   - Simple PCAP upload endpoint
   - Accepts `.pcap` or `.pcapng` files
   - Saves to `data/` directory
   - Response: `{ "ok": true, "pcap_path": "data/filename.pcap", ... }`

### Implementation Details

- Added `ModeRequest` Pydantic model for request validation
- Integrated with existing `CaptureManager` to restart capture seamlessly
- Maintains idempotent behavior - posting same mode is safe
- CORS already configured for http://localhost:5173

### File Modified
- `backend/app.py` (lines 746-943)

## Frontend Changes (React + Vite + TypeScript + Tailwind)

### New Settings Component

Created `frontend/src/components/Settings.tsx` with:

#### Features
1. **Mode Badge** - Shows current mode (LIVE/PCAP) with color coding
2. **Live Capture Section**
   - Network interface dropdown (auto-populated)
   - "Switch to Live Mode" button
   - Help text for Windows users about Npcap/Administrator requirements

3. **PCAP Mode Section**
   - File upload input (accepts .pcap/.pcapng)
   - "Use Default sample.pcap" button
   - Shows current PCAP file path

#### UI/UX
- Modern, clean design with Tailwind CSS
- Responsive grid layout
- Loading states during API calls
- Alert dialogs for success/error feedback
- Disabled states for buttons during operations

#### API Integration
- Fetches current mode on component mount
- Fetches available interfaces on mount
- Switches modes via POST to `/api/mode`
- Uploads PCAP files via POST to `/api/pcap`
- Automatically switches to PCAP mode after upload

### File Created/Modified
- `frontend/src/components/Settings.tsx` (completely replaced)

## Usage

### Accessing Settings
1. Start the application: `docker-compose up -d` or use `LAUNCH-BACKGROUND.bat`
2. Open browser to http://localhost:5173
3. Navigate to Settings page (already routed in App.tsx)

### Switching to Live Mode
1. Select network interface from dropdown
2. Click "Switch to Live Mode"
3. Alert confirms switch with interface name
4. Traffic starts populating dashboard immediately

### Switching to PCAP Mode
**Option 1: Upload a file**
1. Click "Upload PCAP" file input
2. Select `.pcap` or `.pcapng` file
3. File uploads and mode switches automatically
4. Alert shows success and file path

**Option 2: Use default**
1. Click "Use Default sample.pcap"
2. Switches to default PCAP file
3. Alert confirms switch

## Requirements

### For Live Capture on Windows
- **Npcap** must be installed (https://npcap.com/)
- Backend must run as **Administrator**
- Docker Desktop requires privileged access

### For Live Capture on Linux/macOS
- No special requirements (libpcap included)
- May need `sudo` for backend if not running in Docker

## Testing

All endpoints tested and working:
```bash
# Test mode endpoint
curl http://localhost:8000/api/mode

# Test interfaces endpoint
curl http://localhost:8000/api/interfaces

# Test mode switch
curl -X POST http://localhost:8000/api/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "pcap", "pcap_path": "data/sample.pcap"}'
```

## Architecture

```
Frontend (Settings.tsx)
    ↓ HTTP REST
Backend (FastAPI /api/mode, /api/interfaces, /api/pcap)
    ↓
CaptureManager
    ↓ restart_capture()
    ├─ LiveSniffer (for live mode)
    └─ PcapFileReader (for pcap mode)
```

## Notes

- Mode switching is **idempotent** - safe to call repeatedly with same config
- Capture automatically restarts when mode changes
- WebSocket connections remain active during mode switch
- No page reload required
- All existing functionality preserved (Dashboard, Devices, Flows, Alerts)

## Future Enhancements

Potential improvements:
- Real-time capture statistics in Settings
- Multiple PCAP file management
- Scheduled capture start/stop
- Capture filtering options
- Export captured data

