# 🛡️ Enterprise Security Scanner

Professional multi-engine security scanner with CVE enrichment and automated reporting.

## 🎯 Features

### Multi-Engine Scanning
- **OWASP ZAP** - Dynamic Application Security Testing (DAST)
- **Nuclei** - Template-based vulnerability scanning
- **Nmap** - Network service enumeration with NSE scripts
- **Trivy** - Software Composition Analysis (SCA) and SBOM generation

### CVE Enrichment
- **EPSS Scores** - Exploit Prediction Scoring System from FIRST.org
- **CISA KEV** - Known Exploited Vulnerabilities catalog integration
- **Smart Prioritization** - Automatically ranks findings by: KEV Status → Severity → EPSS Score

### Professional Reporting
- **HTML Report** - Beautiful, professional security assessment report
- **PDF Export** - Print-ready documentation (WeasyPrint or Playwright)
- **JSON Export** - Machine-readable results for integration
- **CycloneDX SBOM** - Standard software bill of materials

### Security Controls
- **Passive Mode** - Non-intrusive scanning without active exploitation
- **Rate Limiting** - Configurable concurrency and request throttling
- **Scope Control** - Target allowlists and exclude patterns
- **Timeout Protection** - Per-engine and global timeout limits

## 📋 Prerequisites

### Python Dependencies
```bash
pip install -r requirements.txt
```

### External Tools

#### 1. OWASP ZAP
```bash
# Linux (Snap)
sudo snap install zaproxy --classic

# macOS (Homebrew)
brew install --cask owasp-zap

# Or download from: https://www.zaproxy.org/download/
```

#### 2. Nuclei
```bash
# Linux/macOS
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Or download binary from: https://github.com/projectdiscovery/nuclei/releases
```

#### 3. Nmap
```bash
# Linux (Ubuntu/Debian)
sudo apt-get install nmap

# macOS (Homebrew)
brew install nmap

# Or download from: https://nmap.org/download.html
```

#### 4. Trivy
```bash
# Linux
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# macOS (Homebrew)
brew install trivy

# Or see: https://aquasecurity.github.io/trivy/latest/getting-started/installation/
```

## 🚀 Quick Start

### Command Line

#### Basic Scan
```bash
python -m scanner.orchestrator --targets https://example.com
```

#### Passive Scan
```bash
python -m scanner.orchestrator \
  --targets https://example.com \
  --passive-only \
  --max-concurrency 4
```

#### Multiple Targets
```bash
python -m scanner.orchestrator \
  --targets https://app1.example.com https://app2.example.com \
  --output-dir results/scan-001
```

#### With Exclusions
```bash
python -m scanner.orchestrator \
  --targets https://example.com \
  --exclude /logout /admin/delete \
  --verbose
```

### Streamlit UI

Launch the interactive web interface:

```bash
streamlit run streamlit_app.py
```

Navigate to http://localhost:8501 and configure your scan through the UI.

## 📖 Usage Guide

### Configuration

Create a configuration file or use environment variables:

#### Python Configuration
```python
from scanner.settings import ScannerConfig, Controls

config = ScannerConfig()
config.targets = ["https://example.com"]
config.controls.passive_only = True
config.controls.max_concurrency = 4
config.output_dir = "results"

from scanner.orchestrator import ScanOrchestrator
orchestrator = ScanOrchestrator(config)
findings = orchestrator.run()
```

#### Environment Variables
```bash
export SCANNER_TARGETS="https://example.com,https://api.example.com"
export SCANNER_PASSIVE_ONLY="true"
export SCANNER_MAX_CONCURRENCY="4"
export SCANNER_TIMEOUT="3600"

python -m scanner.orchestrator
```

### ZAP Authentication

Configure authentication in settings:

```python
from scanner.settings import ScannerConfig, ZapSettings

config = ScannerConfig()
config.scan_opts.zap = ZapSettings(
    auth={
        "username": "testuser",
        "password": "testpass",
        "login_url": "https://example.com/login"
    },
    openapi_url="https://example.com/api/openapi.json",
    ajax_crawl=True  # For SPAs
)
```

### Trivy Configuration

Scan different targets:

```python
from scanner.settings import TrivySettings

# Filesystem scan
config.scan_opts.trivy = TrivySettings(
    target="fs",
    path="/path/to/project"
)

# Container image scan
config.scan_opts.trivy = TrivySettings(
    target="image",
    path="nginx:latest"
)

# Git repository scan
config.scan_opts.trivy = TrivySettings(
    target="repo",
    path="https://github.com/user/repo"
)
```

## 📊 Understanding Results

### Report Structure

#### Executive Summary
- Total findings count
- Breakdown by severity (Critical, High, Medium, Low, Info)
- KEV vulnerabilities detected (yes/no)
- Top 5 prioritized findings

#### Risk Prioritization Table
Findings sorted by:
1. **KEV Status** - Known Exploited Vulnerabilities first
2. **Severity** - Critical → High → Medium → Low → Info
3. **EPSS Score** - Higher exploitation probability first

Columns:
- **Severity** - Finding severity level
- **EPSS** - Exploit prediction score (0.0-1.0)
- **KEV** - Badge if in CISA KEV catalog
- **CVE** - CVE identifier(s)
- **Affected** - Target location/component
- **Title** - Finding description
- **Source** - Detection engine (ZAP/Nuclei/Nmap/Trivy)

#### Detailed Findings
- Full description
- Evidence and proof-of-concept
- Remediation guidance
- Reference links
- CVSS scores
- CWE classifications

### Output Files

All outputs saved to configured directory (default: `out/`):

```
out/
├── report.html          # Professional HTML report
├── report.pdf           # PDF export (if WeasyPrint/Playwright installed)
├── report.json          # Complete findings in JSON
├── findings.json        # Normalized, enriched findings
├── sbom.json           # CycloneDX SBOM
└── raw/                # Raw engine outputs
    ├── zap_alerts.json
    ├── nuclei_findings.json
    ├── nmap_findings.json
    ├── trivy_vulnerabilities.json
    └── nmap_output.xml
```

## 🔧 Advanced Configuration

### Custom Scan Options

```python
from scanner.settings import (
    ScannerConfig,
    ZapSettings,
    NucleiSettings,
    NmapSettings,
    TrivySettings,
    Controls
)

config = ScannerConfig()

# ZAP configuration
config.scan_opts.zap = ZapSettings(
    auth={"username": "user", "password": "pass", "login_url": "https://example.com/login"},
    openapi_url="https://example.com/api/openapi.json",
    ajax_crawl=True
)

# Nuclei configuration
config.scan_opts.nuclei = NucleiSettings(
    templates="http,ssl,dns",
    severity=["critical", "high"],
    rate_limit=150,
    timeout=10
)

# Nmap configuration
config.scan_opts.nmap = NmapSettings(
    flags="-sV -sC -T4",
    script="vuln,exploit"  # Only when not passive_only
)

# Trivy configuration
config.scan_opts.trivy = TrivySettings(
    target="fs",
    path=".",
    timeout=600
)

# Control settings
config.controls = Controls(
    max_concurrency=4,
    passive_only=True,
    exclude=["/logout", "/admin/delete"],
    timeout=3600,
    rate_limit=100
)
```

### Programmatic Usage

```python
from scanner.orchestrator import ScanOrchestrator
from scanner.settings import ScannerConfig
from scanner.report.renderer import ReportRenderer

# Configure
config = ScannerConfig()
config.targets = ["https://example.com"]

# Run scan
orchestrator = ScanOrchestrator(config)
findings = orchestrator.run()

# Generate reports
renderer = ReportRenderer(config, findings, orchestrator.sbom)
renderer.generate_all()

# Access results
print(f"Total findings: {len(findings)}")

kev_findings = [f for f in findings if f.get('is_kev')]
print(f"KEV vulnerabilities: {len(kev_findings)}")

critical_findings = [f for f in findings if f.get('severity') == 'critical']
print(f"Critical findings: {len(critical_findings)}")
```

## 🔄 CI/CD Integration

### GitHub Actions

The scanner includes a pre-configured GitHub Action for PR scans:

`.github/workflows/quick-scan.yml`

#### Setup
1. Add `TARGET_URL` to repository secrets
2. The workflow runs automatically on pull requests
3. Fails if KEV or High/Critical findings detected
4. Posts results as PR comment

#### Manual Trigger
```bash
# Via GitHub UI: Actions → Security Quick Scan → Run workflow
# Enter target URL
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: python:3.11
  before_script:
    - pip install -r scanner/requirements.txt
    - apt-get update && apt-get install -y nmap
    # Install other tools...
  script:
    - python -m scanner.orchestrator --targets $TARGET_URL --passive-only
  artifacts:
    paths:
      - out/
    expire_in: 30 days
  only:
    - merge_requests
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    pip install -r scanner/requirements.txt
                    python -m scanner.orchestrator \
                        --targets ${TARGET_URL} \
                        --passive-only \
                        --output-dir results/${BUILD_NUMBER}
                '''
            }
        }
        stage('Archive Reports') {
            steps {
                archiveArtifacts artifacts: 'results/**/*', fingerprint: true
            }
        }
    }
}
```

## 🛡️ Security Best Practices

### Passive vs Active Scanning

**Passive Mode** (Recommended for production):
- No active exploitation attempts
- Safe for production environments
- Observation-only techniques
- Limited to detecting potential issues

**Active Mode** (Use with caution):
- Attempts to verify vulnerabilities
- May modify application state
- Higher detection accuracy
- **Only use in test/staging environments**

### Rate Limiting

Adjust based on target capacity:

```python
config.controls.max_concurrency = 2  # Conservative
config.controls.rate_limit = 50       # Requests per second
config.scan_opts.nuclei.rate_limit = 100
```

### Scope Management

Always define clear scope:

```python
# Allowlist
config.targets = [
    "https://app.example.com",
    "https://api.example.com"
]

# Denylist
config.controls.exclude = [
    "/logout",
    "/admin/delete",
    "/api/v1/reset",
    "production.example.com"
]
```

## 🐛 Troubleshooting

### ZAP Daemon Issues

```bash
# Check if ZAP is already running
ps aux | grep zap

# Kill existing process
pkill -f "zap"

# Verify ZAP installation
zap.sh -version
```

### Nuclei Template Updates

```bash
# Update templates
nuclei -update-templates

# Verify installation
nuclei -version
nuclei -tl  # List templates
```

### Trivy Cache Issues

```bash
# Clear Trivy cache
trivy image --clear-cache

# Force update vulnerability database
trivy image --download-db-only
```

### Permission Errors

```bash
# Nmap requires root for certain scans
sudo python -m scanner.orchestrator --targets 10.0.0.1

# Or use capabilities (Linux)
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

## 📚 API Reference

### Orchestrator

```python
from scanner.orchestrator import ScanOrchestrator

orchestrator = ScanOrchestrator(config)
findings = orchestrator.run()  # Returns List[Dict[str, Any]]
```

### Individual Engines

```python
from scanner.engines.zap_runner import ZapRunner
from scanner.engines.nuclei_runner import NucleiRunner
from scanner.engines.nmap_runner import NmapRunner
from scanner.engines.trivy_runner import TrivyRunner

# Run individual engines
zap = ZapRunner(config)
zap_findings = zap.run("https://example.com")

nuclei = NucleiRunner(config)
nuclei_findings = nuclei.run(["https://example.com"])

nmap = NmapRunner(config)
nmap_findings = nmap.run(["example.com"])

trivy = TrivyRunner(config)
trivy_results = trivy.run()
```

### Enrichment

```python
from scanner.enrich.epss import EPSSEnricher
from scanner.enrich.kev import KEVEnricher

# EPSS enrichment
epss = EPSSEnricher()
findings = epss.add_epss(findings)

# KEV enrichment
kev = KEVEnricher()
findings = kev.add_kev(findings)
```

### Report Generation

```python
from scanner.report.renderer import ReportRenderer

renderer = ReportRenderer(config, findings, sbom)
renderer.save_html()
renderer.save_json()
renderer.save_pdf("out/report.html")
```

## 📄 License

This tool is provided as-is for security assessment purposes. Ensure you have authorization before scanning any systems.

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional scan engines
- Enhanced reporting templates
- More enrichment sources
- Performance optimizations

## 📞 Support

For issues, questions, or feature requests, please refer to the project documentation or create an issue in the repository.

## ⚠️ Disclaimer

This tool is for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any systems. Unauthorized scanning may be illegal.

