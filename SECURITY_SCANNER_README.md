# 🛡️ Enterprise Security Scanner

> Professional multi-engine security assessment platform with automated CVE enrichment and comprehensive reporting.

## 📋 Overview

This enterprise-grade security scanner integrates multiple industry-standard scanning engines to provide comprehensive vulnerability assessment with intelligent prioritization based on real-world exploit data.

### Key Components

- **Multi-Engine Scanning**: OWASP ZAP, Nuclei, Nmap, Trivy
- **CVE Enrichment**: EPSS scores + CISA KEV catalog
- **Professional Reporting**: HTML/PDF/JSON with executive summaries
- **SBOM Generation**: CycloneDX software bill of materials
- **CI/CD Integration**: GitHub Actions workflow included

## 🚀 Quick Start

### 1. Install Python Dependencies

```bash
pip install -r scanner/requirements.txt
```

### 2. Install External Tools

**Required tools** (choose your platform):

#### Linux (Ubuntu/Debian)
```bash
# OWASP ZAP
sudo snap install zaproxy --classic

# Nuclei
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip
unzip nuclei_linux_amd64.zip
sudo mv nuclei /usr/local/bin/

# Nmap
sudo apt-get install nmap

# Trivy
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy
```

#### macOS (Homebrew)
```bash
brew install --cask owasp-zap
brew install nuclei nmap trivy
```

#### Windows
- ZAP: Download from https://www.zaproxy.org/download/
- Nuclei: Download from https://github.com/projectdiscovery/nuclei/releases
- Nmap: Download from https://nmap.org/download.html
- Trivy: Download from https://github.com/aquasecurity/trivy/releases

### 3. Run Your First Scan

```bash
# Command line
python -m scanner.orchestrator --targets https://example.com --passive-only

# Interactive UI
streamlit run streamlit_app.py
```

## 📖 Usage Examples

### Basic Scanning

```bash
# Single target
python -m scanner.orchestrator --targets https://app.example.com

# Multiple targets
python -m scanner.orchestrator \
  --targets https://app.example.com https://api.example.com

# Passive mode (safe for production)
python -m scanner.orchestrator \
  --targets https://example.com \
  --passive-only \
  --max-concurrency 4
```

### Advanced Usage

```bash
# With authentication
python scanner/cli.py \
  --targets https://example.com \
  --zap-auth "testuser:testpass:https://example.com/login" \
  --zap-openapi https://example.com/api/openapi.json

# Custom output directory
python scanner/cli.py \
  --targets https://example.com \
  --output-dir results/scan-$(date +%Y%m%d) \
  --verbose

# Skip specific engines
python scanner/cli.py \
  --targets https://example.com \
  --skip-zap \
  --skip-nmap

# Scan from file
echo "https://app1.example.com" > targets.txt
echo "https://app2.example.com" >> targets.txt
python scanner/cli.py --targets-file targets.txt
```

### Streamlit UI

```bash
streamlit run streamlit_app.py
```

Features:
- Interactive target configuration
- Real-time scan progress
- Visual KPI dashboard
- Embedded HTML report viewer
- Download reports (HTML/PDF/JSON/SBOM)

## 📊 Output Structure

```
out/
├── report.html              # Professional HTML report
├── report.pdf               # PDF export (if WeasyPrint installed)
├── report.json              # Complete findings + metadata
├── findings.json            # Normalized, enriched findings
├── sbom.json               # CycloneDX SBOM
└── raw/                    # Raw engine outputs
    ├── zap_alerts.json
    ├── nuclei_findings.json
    ├── nmap_findings.json
    ├── nmap_output.xml
    └── trivy_vulnerabilities.json
```

## 🎯 Report Features

### Executive Summary
- Total findings by severity
- KEV vulnerability detection
- Target scope and scan metadata
- Top 5 prioritized findings

### Risk Prioritization
Findings sorted by:
1. **KEV Status** (Known Exploited Vulnerabilities)
2. **Severity** (Critical → High → Medium → Low)
3. **EPSS Score** (Exploit Prediction)

### Detailed Findings
- Complete descriptions
- CVE/CWE identifiers
- Evidence and proof-of-concept
- Remediation guidance
- Reference links
- CVSS scores

## 🔧 Configuration

### Configuration File (JSON)

Create `config.json`:

```json
{
  "targets": ["https://example.com"],
  "output_dir": "results",
  "scan_opts": {
    "zap": {
      "auth": {
        "username": "testuser",
        "password": "testpass",
        "login_url": "https://example.com/login"
      },
      "ajax_crawl": true
    },
    "nuclei": {
      "templates": "http,ssl",
      "severity": ["critical", "high", "medium"],
      "rate_limit": 150
    },
    "nmap": {
      "flags": "-sV -T4"
    },
    "trivy": {
      "target": "fs",
      "path": "."
    }
  },
  "controls": {
    "max_concurrency": 4,
    "passive_only": true,
    "exclude": ["/logout", "/admin/delete"],
    "timeout": 3600
  }
}
```

Run with:
```bash
python scanner/cli.py --config config.json
```

### Environment Variables

```bash
export SCANNER_TARGETS="https://example.com,https://api.example.com"
export SCANNER_PASSIVE_ONLY="true"
export SCANNER_MAX_CONCURRENCY="4"
export SCANNER_TIMEOUT="3600"

python -m scanner.orchestrator
```

## 🔄 CI/CD Integration

### GitHub Actions

Pre-configured workflow in `.github/workflows/quick-scan.yml`

#### Setup:
1. Add `TARGET_URL` to repository secrets
2. Workflow runs automatically on pull requests
3. Fails build if KEV or High/Critical findings detected
4. Posts results as PR comment

#### Manual Trigger:
```bash
# Via GitHub UI: Actions → Security Quick Scan → Run workflow
```

### Exit Codes
- `0` - Success, no critical findings
- `1` - Critical severity findings detected
- `2` - Known Exploited Vulnerabilities (KEV) detected

## 🛡️ Security Controls

### Passive vs Active Mode

| Mode | Description | Use Case |
|------|-------------|----------|
| **Passive** | Observation only, no exploitation | Production environments |
| **Active** | Verification attempts, may modify state | Test/staging only |

Enable passive mode:
```bash
--passive-only
```

### Rate Limiting

Protect target systems:
```bash
--max-concurrency 2  # Limit concurrent engines
--timeout 1800       # Per-engine timeout (seconds)
```

### Scope Control

Define clear boundaries:
```bash
--targets https://app.example.com https://api.example.com  # Allowlist
--exclude /logout /admin/delete /api/v1/reset             # Denylist
```

## 🔍 Understanding Results

### Severity Levels
- **Critical**: Immediate action required
- **High**: Prompt attention needed
- **Medium**: Should be addressed
- **Low**: Minor issues
- **Info**: Informational findings

### EPSS Score
Exploit Prediction Scoring System (0.0 - 1.0)
- `> 0.5`: High likelihood of exploitation
- `0.1 - 0.5`: Moderate likelihood
- `< 0.1`: Lower likelihood

### KEV (Known Exploited Vulnerabilities)
CVEs listed in CISA's catalog of vulnerabilities actively exploited in the wild. **Immediate remediation required.**

## 🐛 Troubleshooting

### Common Issues

**ZAP won't start:**
```bash
# Kill existing processes
pkill -f "zap"

# Verify installation
zap.sh -version
```

**Nuclei templates outdated:**
```bash
nuclei -update-templates
```

**Trivy database issues:**
```bash
trivy image --clear-cache
trivy image --download-db-only
```

**Permission errors (Nmap):**
```bash
# Run with sudo
sudo python -m scanner.orchestrator --targets 10.0.0.1

# Or set capabilities (Linux)
sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)
```

## 📚 Architecture

```
scanner/
├── __init__.py
├── settings.py              # Configuration management
├── orchestrator.py          # Main scan coordination
├── cli.py                   # CLI interface
├── engines/                 # Scan engines
│   ├── zap_runner.py       # OWASP ZAP DAST
│   ├── nuclei_runner.py    # Nuclei templates
│   ├── nmap_runner.py      # Nmap enumeration
│   └── trivy_runner.py     # Trivy SCA/SBOM
├── enrich/                  # CVE enrichment
│   ├── epss.py             # EPSS scoring
│   └── kev.py              # CISA KEV catalog
└── report/                  # Report generation
    └── renderer.py         # HTML/PDF/JSON
```

## 🤝 Integration Examples

### Python Script

```python
from scanner.settings import ScannerConfig
from scanner.orchestrator import ScanOrchestrator
from scanner.report.renderer import ReportRenderer

# Configure
config = ScannerConfig()
config.targets = ["https://example.com"]
config.controls.passive_only = True

# Scan
orchestrator = ScanOrchestrator(config)
findings = orchestrator.run()

# Report
renderer = ReportRenderer(config, findings, orchestrator.sbom)
renderer.generate_all()

# Process results
kev_findings = [f for f in findings if f.get('is_kev')]
print(f"Found {len(kev_findings)} KEV vulnerabilities")
```

### Custom Workflow

```python
from scanner.engines.nuclei_runner import NucleiRunner
from scanner.enrich.kev import KEVEnricher

# Run single engine
config = ScannerConfig()
nuclei = NucleiRunner(config)
findings = nuclei.run(["https://example.com"])

# Enrich
kev = KEVEnricher()
findings = kev.add_kev(findings)

# Process
for finding in findings:
    if finding.get('is_kev'):
        print(f"KEV Alert: {finding['title']}")
```

## ⚡ Performance Tips

1. **Adjust concurrency** based on target capacity
2. **Use passive mode** for production
3. **Skip unnecessary engines** with `--skip-*` flags
4. **Limit Nuclei templates** to relevant categories
5. **Set appropriate timeouts** to prevent hanging

## ⚠️ Important Notes

### Authorization Required
Always obtain written authorization before scanning systems you don't own. Unauthorized scanning may be illegal.

### Production Safety
- Use `--passive-only` for production systems
- Test in staging first with active mode
- Monitor target system performance during scans
- Respect rate limits and scope restrictions

### Data Sensitivity
Reports contain sensitive security information:
- Store securely
- Limit access appropriately
- Follow your organization's data handling policies

## 📄 License

This tool is provided as-is for authorized security testing purposes only.

## 🆘 Support

For detailed documentation, see:
- `scanner/README.md` - Comprehensive package documentation
- `.github/workflows/quick-scan.yml` - CI/CD workflow
- `streamlit_app.py` - Interactive UI source

---

**Built with:** Python 3.11+ | OWASP ZAP | Nuclei | Nmap | Trivy | Streamlit

**Enterprise Security Scanner v1.0** - Professional vulnerability assessment platform

