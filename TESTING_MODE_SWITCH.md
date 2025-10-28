# Testing Capture Mode Switching

## Quick Test Guide

### 1. Access the Settings Page
```bash
# Start the application
docker-compose up -d

# Or use the batch file
LAUNCH-BACKGROUND.bat

# Open browser
http://localhost:5173/settings
```

### 2. Test Live Mode (Linux/macOS/Docker)
1. In the Settings UI, you'll see a "Network Interface" dropdown
2. Select an interface (e.g., "eth0")
3. Click "Switch to Live Mode"
4. You should see an alert: "Switched to LIVE on iface=eth0"
5. The badge at the top will change to "LIVE" (green)

**Note for Windows**: 
- Install Npcap from https://npcap.com/
- Run backend as Administrator
- Available interfaces may include "Ethernet", "Wi-Fi", etc.

### 3. Test PCAP Mode

#### Option A: Use Default (if sample.pcap exists)
1. Click "Use Default sample.pcap" button
2. Alert shows: "Switched to PCAP (data/sample.pcap)"
3. Badge changes to "PCAP" (blue)

#### Option B: Upload Your Own File
1. Click the "Upload PCAP" file input
2. Select a `.pcap` or `.pcapng` file from your computer
3. File uploads automatically
4. Alert shows: "Switched to PCAP (data/yourfile.pcap)"
5. You'll see "Current PCAP: data/yourfile.pcap" below the upload area

### 4. Verify Mode Switch via API

```bash
# Check current mode
curl http://localhost:8000/api/mode

# Should return:
# {"mode":"live","iface":"eth0","pcap_path":null}
# OR
# {"mode":"pcap","iface":"eth0","pcap_path":"data/sample.pcap"}

# List available interfaces
curl http://localhost:8000/api/interfaces

# Should return (example):
# ["lo","eth0","wlan0"]

# Switch to PCAP mode via API
curl -X POST http://localhost:8000/api/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "pcap", "pcap_path": "data/sample.pcap"}'

# Switch to Live mode via API
curl -X POST http://localhost:8000/api/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "live", "iface": "eth0"}'
```

### 5. Check Backend Logs

```bash
# Watch for mode switch messages
docker-compose logs -f backend

# You should see:
# - "Stopped packet capture"
# - "Switched to pcap mode" or "Switched to live mode"
# - "Started PCAP processing: ..." or "Started live capture on interface ..."
```

### 6. Generate Sample PCAP (Optional)

If you need a sample PCAP file for testing:

```bash
# Using the provided script
cd backend
python scripts/generate_synthetic_pcap.py

# Or download a sample
cd data
curl -O https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http.cap
mv http.cap sample.pcap
```

## Expected Behavior

### ✅ Success Indicators
- Alert dialogs show success messages
- Mode badge updates to show current mode
- Backend logs confirm capture restart
- Dashboard starts showing data (for live mode or valid PCAP)
- No page reload required

### ❌ Common Issues

**"iface is required for live mode"**
- Solution: Select an interface from the dropdown before clicking "Switch to Live Mode"

**"pcap_path is required for pcap mode"**
- Solution: Either upload a file first or ensure data/sample.pcap exists

**Empty interface dropdown**
- On Windows: Install Npcap and run backend as Administrator
- On Linux/Docker: Check that backend has network permissions

**"Failed to switch to LIVE"**
- Check backend has proper permissions (CAP_NET_RAW capability)
- Verify interface name is correct
- Check Docker container has `NET_ADMIN` capability (already in compose.yaml)

## Integration Test

Complete workflow test:

```bash
# 1. Start in PCAP mode (default)
docker-compose up -d
curl http://localhost:8000/api/mode
# Should show: {"mode":"pcap",...}

# 2. Switch to Live mode
curl -X POST http://localhost:8000/api/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "live", "iface": "eth0"}'

# 3. Verify switch
curl http://localhost:8000/api/mode
# Should show: {"mode":"live","iface":"eth0",...}

# 4. Check dashboard has live data
# Open http://localhost:5173 and check for real-time updates

# 5. Switch back to PCAP
curl -X POST http://localhost:8000/api/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "pcap", "pcap_path": "data/sample.pcap"}'

# 6. Verify
curl http://localhost:8000/api/mode
# Should show: {"mode":"pcap",...}
```

## Architecture Verification

```
User clicks "Switch to Live Mode"
    ↓
Frontend POST /api/mode {"mode":"live","iface":"eth0"}
    ↓
Backend validates request
    ↓
Backend stops current capture
    ↓
Backend updates settings.capture_mode and settings.iface
    ↓
Backend restarts capture with LiveSniffer
    ↓
Frontend receives response {"mode":"live","iface":"eth0"}
    ↓
Frontend shows success alert and updates badge
    ↓
Dashboard starts receiving live traffic data via WebSocket
```

## Performance Notes

- Mode switch typically completes in < 2 seconds
- No data loss during switch (flows in progress are finalized)
- WebSocket connections remain active
- Dashboard UI doesn't reload
- Switching is idempotent (safe to call repeatedly)

## Troubleshooting

### Backend not restarting capture
```bash
# Check backend logs
docker-compose logs backend --tail=50

# Manually restart backend
docker-compose restart backend
```

### Frontend not updating
```bash
# Clear browser cache
# Hard reload: Ctrl+Shift+R (Windows/Linux) or Cmd+Shift+R (Mac)

# Check frontend logs
docker-compose logs frontend --tail=20

# Rebuild frontend
docker-compose build frontend
docker-compose up -d frontend
```

### CORS errors
- Verify backend CORS settings include http://localhost:5173
- Check browser console for specific error messages
- Already configured in app.py, should work out-of-box

## Success Criteria ✅

- [x] GET /api/mode returns current mode
- [x] GET /api/interfaces returns interface list
- [x] POST /api/mode switches mode successfully
- [x] POST /api/pcap uploads files and switches mode
- [x] Settings UI displays current mode badge
- [x] Interface dropdown populates from API
- [x] Live mode switch works with alert confirmation
- [x] PCAP upload works with automatic mode switch
- [x] Default PCAP button works
- [x] No page reload required
- [x] Backend logs show capture restart
- [x] Dashboard receives data after switch

