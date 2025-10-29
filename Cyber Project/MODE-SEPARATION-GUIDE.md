# Home Net Guardian - Mode Separation Guide

## 🎯 **Mode Separation Implementation**

The system now properly differentiates between **Live Capture Mode** and **PCAP Analysis Mode** with distinct data sources and user interfaces.

## 📡 **Live Capture Mode**

### What it shows:
- **Real-time connected devices** (Docker containers, network infrastructure)
- **Live network traffic** from actual network interfaces
- **Docker container monitoring** with real-time metrics
- **Current system status** and active connections

### Data Sources:
- Docker containers (updated every 3-4 seconds)
- Live network interface capture
- Real-time system metrics (CPU, memory, network)
- Active network flows

### UI Components:
- 🔴 **Live Mode Indicator** - Red badge showing "LIVE MODE"
- **Docker Status Component** - Shows running containers and metrics
- **Real-time device updates** - Devices appear/disappear as they connect/disconnect
- **Live flow monitoring** - Current network activity

## 📁 **PCAP Analysis Mode**

### What it shows:
- **Devices discovered in uploaded PCAP file**
- **Historical network flows** from the capture file
- **PCAP file analysis statistics**
- **Network patterns** from the captured timeframe

### Data Sources:
- Uploaded PCAP/PCAPNG files
- Historical packet analysis
- Device fingerprinting from captured traffic
- Flow reconstruction from packet data

### UI Components:
- 📁 **PCAP Mode Indicator** - Blue badge showing "PCAP MODE"
- **PCAP Analysis Component** - File info, processing status, statistics
- **Historical device list** - Devices found in the capture file
- **File-based flow analysis** - Network activity from the capture period

## 🔄 **Mode Switching Behavior**

### When switching modes:
1. **Data is cleared** - Previous mode data is removed from the UI
2. **Components change** - Mode-specific components show/hide
3. **Data sources switch** - Backend changes what data to collect/display
4. **User feedback** - Clear notifications about what each mode does

### Live → PCAP:
- Docker monitoring stops affecting UI data
- Ready to analyze uploaded files
- Shows message: "Switched to PCAP mode - ready to analyze uploaded files"

### PCAP → Live:
- Clears PCAP analysis data
- Starts showing real-time devices
- Docker containers appear as devices
- Shows message: "Switched to Live mode - now monitoring real-time devices"

## 🎨 **Visual Indicators**

### Mode Indicator Component:
```
🔴 LIVE MODE                    📁 PCAP MODE
Monitoring live network         Analyzing uploaded PCAP
traffic and connected devices   file data
[●] Active                     [●] Processing/Ready
```

### Dashboard Changes:
- **Live Mode**: Shows Docker Status component
- **PCAP Mode**: Shows PCAP Analysis component
- **Both**: Mode indicator in header, appropriate statistics

## 🔧 **Technical Implementation**

### Backend Changes:
1. **Mode-aware device filtering** - `/api/devices` endpoint filters by mode
2. **Docker monitoring conditional** - Only processes Docker data in live mode
3. **PCAP processing isolation** - PCAP analysis doesn't interfere with live data

### Frontend Changes:
1. **Store mode management** - Clears data when switching modes
2. **Conditional components** - Show/hide based on current mode
3. **Mode-specific queries** - Different API calls for different modes

## 📊 **Data Flow**

### Live Mode Data Flow:
```
Docker Containers → Backend → WebSocket → Frontend → Live Device List
Network Interface → Packet Capture → Flow Analysis → Real-time Flows
```

### PCAP Mode Data Flow:
```
Uploaded File → PCAP Reader → Packet Analysis → Historical Devices
PCAP Packets → Flow Reconstruction → Historical Flows → Analysis UI
```

## 🎯 **User Experience**

### Clear Separation:
- **Live Mode**: "See what's connected right now"
- **PCAP Mode**: "Analyze what happened in this file"

### No Confusion:
- Mode indicator always visible
- Different colored badges (red for live, blue for PCAP)
- Clear descriptions of what each mode does
- Data clears when switching to avoid mixing live and historical data

### Appropriate Features:
- **Live Mode**: Docker monitoring, real-time alerts, current status
- **PCAP Mode**: File analysis, historical patterns, upload new files

This implementation ensures users understand exactly what data they're looking at and prevents confusion between live monitoring and historical analysis!
