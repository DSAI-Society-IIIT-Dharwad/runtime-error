# 🔗 Security Scanner Integration Guide

This document explains how the Enterprise Security Scanner integrates with your existing Cyber Project (Guardian Network Security Platform).

## 📋 Overview

The Enterprise Security Scanner is a **standalone security assessment tool** that complements your existing Guardian platform by providing:

- External vulnerability scanning (while Guardian monitors internal network)
- Application security testing (DAST with ZAP)
- Infrastructure scanning (Nmap)
- Dependency analysis (Trivy)
- CVE enrichment and prioritization

## 🏗️ Architecture Integration

```
Your Cyber Project
├── backend/                    # Guardian Network Monitor (existing)
│   ├── capture/               # Network packet capture
│   ├── detection/             # IDS/anomaly detection
│   └── db/                    # Alert & device database
├── frontend/                   # Guardian Dashboard (existing)
│   └── components/            # Device monitoring UI
└── scanner/                    # NEW: Security Scanner
    ├── engines/               # DAST, Nuclei, Nmap, Trivy
    ├── enrich/                # EPSS, KEV enrichment
    └── report/                # Professional reporting
```

## 🔄 Use Cases

### 1. Guardian (Existing) - Internal Network Monitoring
- **What**: Real-time network traffic analysis
- **Where**: Internal network (pcap/live capture)
- **Detects**: Anomalies, device fingerprinting, behavioral analysis
- **Output**: Real-time alerts, device inventory

### 2. Scanner (New) - External Vulnerability Assessment
- **What**: Periodic security scanning
- **Where**: External applications/infrastructure
- **Detects**: Known vulnerabilities, misconfigurations, CVEs
- **Output**: Professional reports, SBOM

### Combined Power
```
Guardian monitors WHAT is happening on your network
Scanner discovers WHAT vulnerabilities exist in your applications
Together: Complete security visibility
```

## 🔀 Integration Patterns

### Pattern 1: Complementary Scanning

**Guardian**: Monitors network traffic 24/7
```bash
# Already running as per your existing setup
cd backend
python app.py
```

**Scanner**: Periodic vulnerability assessments
```bash
# Run weekly scans of your web applications
python -m scanner.orchestrator \
  --targets https://your-guardian-frontend.com \
  --passive-only
```

### Pattern 2: Unified Dashboard (Future Enhancement)

You could extend Guardian's frontend to display scanner results:

```typescript
// frontend/src/components/SecurityScanner.tsx
import { useState, useEffect } from 'react';

export const SecurityScanner = () => {
  const [scanResults, setScanResults] = useState(null);
  
  useEffect(() => {
    // Load scanner results from out/report.json
    fetch('/scanner-api/latest-report')
      .then(res => res.json())
      .then(data => setScanResults(data));
  }, []);
  
  return (
    <div>
      <h2>External Vulnerability Scan</h2>
      {scanResults && (
        <>
          <KPICards findings={scanResults.findings} />
          <FindingsTable findings={scanResults.findings} />
        </>
      )}
    </div>
  );
};
```

### Pattern 3: Shared Backend Database (Advanced)

Store scanner findings in Guardian's database:

```python
# scanner/integrations/guardian_db.py
from scanner.orchestrator import ScanOrchestrator
from backend.db.repo import Repository

def store_scan_in_guardian(findings, sbom):
    """Store scanner results in Guardian database"""
    repo = Repository()
    
    for finding in findings:
        repo.create_vulnerability_alert(
            severity=finding['severity'],
            title=finding['title'],
            cve=finding.get('cve'),
            epss_score=finding.get('epss_score'),
            is_kev=finding.get('is_kev'),
            location=finding['location'],
            source='security-scanner'
        )
```

## 📊 Data Flow Examples

### Scenario 1: New Device on Network

**Guardian detects**:
```
New device: 192.168.1.100
Fingerprint: Nginx web server
Behavior: Normal HTTP traffic
```

**Scanner can investigate**:
```bash
python -m scanner.orchestrator \
  --targets http://192.168.1.100 \
  --passive-only
```

**Result**: Discover if the web server has vulnerabilities

### Scenario 2: Suspicious Activity Detected

**Guardian alerts**:
```
Alert: Unusual SQL traffic pattern from 192.168.1.50
```

**Scanner can assess**:
```bash
python scanner/cli.py \
  --targets http://192.168.1.50 \
  --skip-zap --skip-nuclei  # Just do network enum
```

**Result**: Identify services and versions for correlation

### Scenario 3: Compliance Reporting

**Guardian provides**:
- Network device inventory
- Traffic anomalies
- Intrusion attempts

**Scanner adds**:
- Vulnerability inventory
- SBOM for compliance
- CVE tracking with KEV prioritization

**Combined Report**: Complete security posture

## 🔧 Configuration Recommendations

### Guardian Configuration (Existing)
```python
# backend/core/config.py
GUARDIAN_MODE = "live"  # or "pcap"
ALERT_THRESHOLD = "medium"
```

### Scanner Configuration (New)
```json
{
  "targets": [
    "https://your-guardian-frontend.com",
    "http://192.168.1.0/24"
  ],
  "controls": {
    "passive_only": true,
    "max_concurrency": 2
  }
}
```

### Coordination Strategy
```bash
# Cron job for periodic scanning
0 2 * * 0 python -m scanner.orchestrator --config /etc/scanner/config.json

# Guardian runs continuously
systemctl start guardian-backend
```

## 🎯 Practical Integration Steps

### Step 1: Run Both Systems Independently

**Guardian (Existing)**:
```bash
# Terminal 1: Backend
cd backend
python app.py

# Terminal 2: Frontend
cd frontend
npm run dev
```

**Scanner (New)**:
```bash
# Terminal 3: Scanner
python -m scanner.orchestrator --targets https://localhost:5173 --passive-only
```

### Step 2: Create Unified Launch Script

```bash
#!/bin/bash
# start-security-platform.sh

echo "Starting Guardian Network Monitor..."
cd backend
python app.py &
GUARDIAN_PID=$!

cd ../frontend
npm run dev &
FRONTEND_PID=$!

echo "Guardian running (PID: $GUARDIAN_PID, $FRONTEND_PID)"
echo "Access dashboard: http://localhost:5173"
echo ""
echo "To run vulnerability scan:"
echo "  python -m scanner.orchestrator --targets https://localhost:5173"
```

### Step 3: Scheduled Scanning

```bash
# crontab -e
# Run scanner every Sunday at 2 AM
0 2 * * 0 cd /path/to/project && python -m scanner.orchestrator --config scanner-config.json

# Send report via email
5 2 * * 0 mail -s "Weekly Security Scan" admin@company.com < out/report.html
```

### Step 4: CI/CD Integration

```yaml
# .github/workflows/security-check.yml
name: Complete Security Check

on:
  push:
    branches: [main]

jobs:
  guardian-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Guardian tests
        run: |
          cd backend
          python -m pytest tests/

  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run vulnerability scan
        run: |
          python -m scanner.orchestrator \
            --targets ${{ secrets.TARGET_URL }} \
            --passive-only
      - name: Upload reports
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: out/
```

## 📈 Evolution Path

### Phase 1: Side-by-Side (Current)
- Guardian monitors network
- Scanner assesses vulnerabilities
- Separate interfaces

### Phase 2: Unified Dashboard
- Single frontend showing both
- Guardian alerts + Scanner findings
- Cross-reference capabilities

### Phase 3: Automated Correlation
- Guardian detects anomaly → Triggers scanner
- Scanner finds vulnerability → Guardian monitors exploitation attempts
- Shared threat intelligence

### Phase 4: AI-Enhanced
- ML models trained on both datasets
- Predictive threat detection
- Automated remediation workflows

## 🛠️ API Integration Example

Create an API endpoint in Guardian to trigger scans:

```python
# backend/app.py
from scanner.orchestrator import ScanOrchestrator
from scanner.settings import ScannerConfig

@app.post("/api/security-scan")
async def trigger_security_scan(target: str):
    """Trigger vulnerability scan from Guardian UI"""
    
    config = ScannerConfig()
    config.targets = [target]
    config.controls.passive_only = True
    
    # Run scan asynchronously
    orchestrator = ScanOrchestrator(config)
    findings = orchestrator.run()
    
    return {
        "scan_id": "scan-001",
        "total_findings": len(findings),
        "kev_count": sum(1 for f in findings if f.get('is_kev')),
        "report_url": "/scanner-reports/latest"
    }
```

Frontend button:
```typescript
// frontend/src/components/QuickActions.tsx
const triggerScan = async (target: string) => {
  const response = await fetch('/api/security-scan', {
    method: 'POST',
    body: JSON.stringify({ target }),
    headers: { 'Content-Type': 'application/json' }
  });
  
  const result = await response.json();
  alert(`Scan complete: ${result.total_findings} findings`);
};
```

## 📚 Documentation Structure

```
Your Project Documentation
├── README.md                       # Main project overview
├── QUICKSTART.txt                  # Guardian quick start (existing)
├── SECURITY_SCANNER_README.md      # Scanner documentation (new)
├── SCANNER_QUICKSTART.md           # Scanner quick start (new)
└── SCANNER_INTEGRATION.md          # This file
```

## 💡 Best Practices

### 1. Separation of Concerns
- **Guardian**: Real-time network monitoring
- **Scanner**: Periodic vulnerability assessment
- Keep them modular and independent

### 2. Scheduled Scanning
- Don't run scanner continuously
- Schedule weekly/monthly scans
- Guardian provides continuous monitoring

### 3. Target Selection
- Guardian: Internal network (192.168.x.x)
- Scanner: External apps (https://your-app.com)
- Or scan Guardian's own web interface

### 4. Report Storage
```
out/
├── guardian-alerts/          # Guardian alerts
│   └── 2024-10-28/
└── scanner-reports/          # Scanner reports
    └── 2024-10-28/
```

### 5. Unified Notifications
```python
# shared/notifications.py
def send_security_alert(alert_type, details):
    """Unified alerting for Guardian and Scanner"""
    if alert_type == 'guardian':
        # Network anomaly detected
        notify_security_team(f"Network Alert: {details}")
    elif alert_type == 'scanner':
        # Vulnerability found
        notify_security_team(f"Vulnerability: {details}")
```

## 🚀 Quick Start Integration

```bash
# 1. Your existing Guardian system
cd backend && python app.py &
cd frontend && npm run dev &

# 2. Run first security scan
python -m scanner.orchestrator \
  --targets https://localhost:5173 \
  --passive-only

# 3. View combined security status
# - Guardian dashboard: http://localhost:5173
# - Scanner report: out/report.html
```

## ⚠️ Important Notes

1. **Independent Systems**: Scanner and Guardian are separate but complementary
2. **Different Purposes**: Guardian=monitoring, Scanner=assessment
3. **No Conflicts**: They can run simultaneously without interference
4. **Data Separation**: Each maintains its own database/files
5. **Future Integration**: Easy to integrate more tightly later

## 📞 Support

- **Guardian Issues**: Use existing Guardian documentation
- **Scanner Issues**: See SECURITY_SCANNER_README.md
- **Integration Questions**: This document

---

**The scanner enhances your existing Guardian platform with vulnerability assessment capabilities. Together, they provide comprehensive security coverage.**

