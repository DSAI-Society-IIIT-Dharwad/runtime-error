# PCAP Upload & Analysis Guide

## Where Uploaded Files Go

**Upload Location:** `backend/uploads/`

All PCAP files you upload through the web interface are saved to:
```
D:\Hackathon Cyber\Cyber Project\Cyber Project\backend\uploads\
```

Currently uploaded files:
- `4SICS-GeekLounge-151020.pcap`
- `4SICS-GeekLounge-151021.pcap`
- `sample.pcap`

## How Upload Works (Fixed)

### Backend Process:
1. **File Upload** → Saves to `backend/uploads/`
2. **Mode Switch** → Stops live capture, switches to PCAP mode
3. **Data Wipe** → Clears all old devices/flows/alerts from database
4. **PCAP Analysis** → Parses every packet in the file
5. **DB Population** → Extracts and saves:
   - Network flows (src/dst IPs, ports, protocols, bytes)
   - Devices (MAC addresses, IPs, vendors)
6. **Response** → Returns packet count and analysis summary

### Frontend Process:
1. **Upload File** → Sends file to backend
2. **Show Success Toast** → Displays packet count
3. **Auto Reload** → Refreshes page after 1.5 seconds to show results

## What Was Fixed

### Problem:
- Files were uploaded but analysis results weren't visible
- Dashboard showed zeros for devices/flows
- Backend wasn't populating database with PCAP data
- Frontend didn't refresh to show new data

### Solution:
1. **Backend:** Added callback function to process PCAP packets and save to DB
2. **Backend:** Added comprehensive logging to track analysis progress
3. **Backend:** Updates global `capture_manager` to PCAP mode
4. **Frontend:** Auto-reloads page after upload to fetch new data
5. **Frontend:** Shows packet count in success message

## How to Test

1. **Upload a PCAP file:**
   - Go to Settings page
   - Switch to PCAP mode
   - Click "Upload" and select a .pcap file
   - Wait for success message

2. **Check the logs:**
   ```
   backend/logs/guardian.log
   ```
   Look for:
   - `=== PCAP UPLOAD STARTED: filename.pcap ===`
   - `[PCAP Upload] Processed X flows`
   - `[PCAP Upload] Added X devices`
   - `=== PCAP UPLOAD COMPLETE ===`

3. **View results:**
   - Dashboard should show:
     - Active Devices count
     - Network Flows count
     - Device table with discovered devices
   - PCAP Analysis panel shows file details

## Troubleshooting

### If dashboard still shows zeros:

1. **Check the log file** for errors during analysis
2. **Verify file was saved:**
   ```
   dir backend\uploads
   ```
3. **Check database has data:**
   - Look at `backend/guardian.db`
   - Should have entries in `device` and `flow` tables

### If upload fails:

- Check file format (must be .pcap or .pcapng)
- Check file size (very large files may timeout)
- Check backend logs for specific error messages

### Common Errors (FIXED):

#### ❌ `'EDecimal' object cannot be interpreted as an integer`
**Cause:** PCAP files with high-precision timestamps  
**Status:** ✅ **FIXED** - Now converts EDecimal timestamps to float automatically

## Expected Log Output

```
2025-10-29 XX:XX:XX - app - INFO - === PCAP UPLOAD STARTED: sample.pcap ===
2025-10-29 XX:XX:XX - app - INFO - File saved to: D:\...\backend\uploads\sample.pcap (652800 bytes)
2025-10-29 XX:XX:XX - app - INFO - Stopped previous capture
2025-10-29 XX:XX:XX - app - INFO - Updated capture_manager to PCAP mode
2025-10-29 XX:XX:XX - app - INFO - Wiping all old data...
2025-10-29 XX:XX:XX - app - INFO - Data wiped successfully
2025-10-29 XX:XX:XX - app - INFO - Starting PCAP analysis for: uploads\sample.pcap
2025-10-29 XX:XX:XX - capture.pcap_reader - INFO - Starting PCAP processing: uploads\sample.pcap
2025-10-29 XX:XX:XX - capture.pcap_reader - INFO - PCAP file size: 0.62 MB
2025-10-29 XX:XX:XX - app - INFO - [PCAP Upload] Processed 15/15 flows (total: 15)
2025-10-29 XX:XX:XX - app - INFO - [PCAP Upload] Processed 20/20 flows (total: 35)
... (continues for all packets) ...
2025-10-29 XX:XX:XX - capture.pcap_reader - INFO - PCAP processing complete: 1003 packets
2025-10-29 XX:XX:XX - app - INFO - PCAP analysis completed successfully
2025-10-29 XX:XX:XX - app - INFO - === PCAP UPLOAD COMPLETE ===
2025-10-29 XX:XX:XX - app - INFO - File: sample.pcap
2025-10-29 XX:XX:XX - app - INFO - Packets: 1003
2025-10-29 XX:XX:XX - app - INFO - Flows added to DB: 250
2025-10-29 XX:XX:XX - app - INFO - Devices added to DB: 5
2025-10-29 XX:XX:XX - app - INFO - Status: SUCCESS
```

## Summary

✅ **Files ARE being uploaded** to `backend/uploads/`  
✅ **Analysis IS happening** and saving to database  
✅ **Dashboard WILL refresh** automatically after upload  
✅ **Logs WILL show** detailed progress and results  

The issue is now **FIXED**! 🎉

