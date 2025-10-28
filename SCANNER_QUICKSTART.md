# ⚡ Quick Start Guide - 5 Minutes to Your First Scan

## Prerequisites Check

```bash
# Verify you have Python 3.11+
python --version

# Should output: Python 3.11.x or higher
```

## Installation (One-Time Setup)

### Step 1: Install Python Dependencies

```bash
pip install -r scanner/requirements.txt
```

### Step 2: Install Security Tools

**Choose your platform:**

**Linux (Ubuntu/Debian):**
```bash
sudo snap install zaproxy --classic
sudo apt-get install nmap
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip
unzip nuclei_linux_amd64.zip && sudo mv nuclei /usr/local/bin/
```

**macOS:**
```bash
brew install --cask owasp-zap
brew install nuclei nmap trivy
```

**Windows:**
- Download ZAP: https://www.zaproxy.org/download/
- Download Nuclei: https://github.com/projectdiscovery/nuclei/releases
- Download Nmap: https://nmap.org/download.html

## Your First Scan (3 Ways)

### Option 1: Command Line (Fastest)

```bash
python -m scanner.orchestrator \
  --targets https://example.com \
  --passive-only \
  --max-concurrency 2
```

**That's it!** Results will be in `out/report.html`

### Option 2: Interactive UI (Easiest)

```bash
streamlit run streamlit_app.py
```

1. Open browser to http://localhost:8501
2. Enter target URL
3. Check "Passive Mode Only"
4. Click "Start Scan"
5. View results in the web interface

### Option 3: Using CLI Tool (Most Flexible)

```bash
python scanner/cli.py \
  --targets https://example.com \
  --passive-only \
  --output-dir my-first-scan \
  --verbose
```

## Understanding Your Results

After the scan completes, check these files:

```
out/
├── report.html       # 👈 Open this first! Beautiful web report
├── report.json       # Machine-readable results
├── findings.json     # All findings with EPSS + KEV enrichment
└── sbom.json        # Software bill of materials
```

### Key Metrics in Report

1. **Total Findings** - All vulnerabilities discovered
2. **By Severity** - Critical, High, Medium, Low, Info
3. **KEV Count** - 🔴 Known Exploited Vulnerabilities (urgent!)
4. **EPSS Scores** - Likelihood of exploitation

### Priority Order

Findings are automatically sorted by:
1. **KEV Status** (Known exploited = highest priority)
2. **Severity** (Critical > High > Medium > Low)
3. **EPSS Score** (Higher = more likely to be exploited)

## Common First Scans

### Safe Website Scan (Passive)

```bash
# Won't harm the target, only observes
python -m scanner.orchestrator \
  --targets https://yourapp.com \
  --passive-only
```

### Multiple Targets

```bash
python -m scanner.orchestrator \
  --targets https://app.com https://api.app.com https://admin.app.com \
  --passive-only
```

### Scan from File

```bash
# Create targets.txt
cat > targets.txt << EOF
https://app1.example.com
https://app2.example.com
https://api.example.com
EOF

# Scan all targets
python scanner/cli.py --targets-file targets.txt --passive-only
```

### With Authentication

```bash
python scanner/cli.py \
  --targets https://yourapp.com \
  --zap-auth "testuser:testpass:https://yourapp.com/login" \
  --passive-only
```

## Reading the Report

### 1. Executive Summary (Top of Report)

```
Total Findings: 42
Critical: 2  ← 🔴 Fix immediately
High: 8      ← 🟠 Fix urgently
Medium: 15   ← 🟡 Fix soon
Low: 17      ← 🟢 Fix when possible

KEV Present: YES (2 findings) ← ⚡ CRITICAL! Known exploited!
```

### 2. Risk Prioritization Table

Shows all findings sorted by priority. Focus on:
- **KEV badge** = Known exploited, fix NOW
- **High EPSS** (>0.5) = Likely to be exploited soon
- **Critical/High severity** = Significant security impact

### 3. Detailed Findings

Each finding includes:
- **What**: Description of vulnerability
- **Where**: Exact location (URL, component, etc.)
- **Why**: Security impact and risk
- **How to Fix**: Remediation guidance
- **References**: Links to more information

## Troubleshooting

### "Tool not found" Error

```bash
# Verify installations
zap.sh -version
nuclei -version
nmap --version
trivy --version

# If missing, see INSTALLATION.md
```

### "No targets specified"

```bash
# Make sure to include --targets
python -m scanner.orchestrator --targets https://example.com
```

### ZAP won't start

```bash
# Kill any existing ZAP processes
pkill -f "zap"

# Try again
python -m scanner.orchestrator --targets https://example.com --passive-only
```

### Scan is too slow

```bash
# Reduce concurrency
python -m scanner.orchestrator \
  --targets https://example.com \
  --max-concurrency 1 \
  --passive-only
```

### Permission denied (Nmap)

```bash
# Run with sudo
sudo python -m scanner.orchestrator --targets 10.0.0.1
```

## Next Steps

### 1. Customize Your Scan

Create `config.json`:
```json
{
  "targets": ["https://yourapp.com"],
  "controls": {
    "passive_only": true,
    "max_concurrency": 4
  }
}
```

Run it:
```bash
python scanner/cli.py --config config.json
```

### 2. Integrate with CI/CD

The GitHub Action is already configured in `.github/workflows/quick-scan.yml`

Just add `TARGET_URL` to your repository secrets and it runs automatically on PRs!

### 3. Explore Advanced Features

- **ZAP with authentication**: `--zap-auth`
- **OpenAPI import**: `--zap-openapi`
- **Custom Nuclei templates**: `--nuclei-templates`
- **Trivy image scanning**: `--trivy-target image`

### 4. Read Full Documentation

- `SECURITY_SCANNER_README.md` - Complete guide
- `scanner/README.md` - Package documentation
- `scanner/INSTALLATION.md` - Detailed installation
- `.github/workflows/quick-scan.yml` - CI/CD example

## Important Reminders

### ⚠️ Authorization Required

**ALWAYS** get written permission before scanning systems you don't own. Unauthorized scanning may be illegal.

### 🛡️ Use Passive Mode for Production

```bash
--passive-only  # Safe for production
```

Never run active scans against production systems without approval!

### 📊 Understand Results

Not all findings are equal:
- **KEV** = Actively exploited, fix NOW
- **Critical** = Severe impact, fix urgently
- **High EPSS** = Likely to be exploited
- **Low severity** = Less urgent, but still address

## Quick Reference

```bash
# Basic scan
python -m scanner.orchestrator --targets URL --passive-only

# UI
streamlit run streamlit_app.py

# From file
python scanner/cli.py --targets-file targets.txt --passive-only

# With auth
python scanner/cli.py --targets URL --zap-auth "user:pass:login_url"

# Custom output
python scanner/cli.py --targets URL --output-dir results/scan-001

# Help
python scanner/cli.py --help
```

## Getting Help

1. Check troubleshooting section above
2. Review detailed docs in `SECURITY_SCANNER_README.md`
3. Read installation guide in `scanner/INSTALLATION.md`
4. Check tool-specific documentation:
   - ZAP: https://www.zaproxy.org/docs/
   - Nuclei: https://docs.projectdiscovery.io/
   - Nmap: https://nmap.org/book/
   - Trivy: https://aquasecurity.github.io/trivy/

---

**Ready?** Run your first scan:

```bash
python -m scanner.orchestrator --targets https://example.com --passive-only
```

Then open `out/report.html` in your browser! 🎉

