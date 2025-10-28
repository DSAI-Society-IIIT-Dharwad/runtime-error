# 📚 Enterprise Security Scanner - Documentation Index

Quick navigation to all documentation and resources for the Enterprise Security Scanner.

## 🚀 Getting Started

| Document | Purpose | Time Required |
|----------|---------|---------------|
| [SCANNER_QUICKSTART.md](SCANNER_QUICKSTART.md) | Get scanning in 5 minutes | ⏱️ 5 min |
| [SECURITY_SCANNER_README.md](SECURITY_SCANNER_README.md) | Complete user guide | 📖 30 min |
| [scanner/INSTALLATION.md](scanner/INSTALLATION.md) | Detailed setup instructions | 🔧 15 min |

## 📖 Core Documentation

### User Documentation
- **[SECURITY_SCANNER_README.md](SECURITY_SCANNER_README.md)** - Complete reference guide
  - Features overview
  - Usage examples
  - Configuration options
  - API reference
  - Troubleshooting

- **[SCANNER_QUICKSTART.md](SCANNER_QUICKSTART.md)** - Fast-track guide
  - Installation commands
  - Your first scan
  - Common scenarios
  - Quick reference

- **[scanner/README.md](scanner/README.md)** - Package documentation
  - Architecture details
  - Module descriptions
  - API documentation
  - Extension guide

### Installation & Setup
- **[scanner/INSTALLATION.md](scanner/INSTALLATION.md)** - Installation guide
  - Platform-specific instructions
  - Tool installation
  - Verification scripts
  - Troubleshooting

### Integration
- **[SCANNER_INTEGRATION.md](SCANNER_INTEGRATION.md)** - Integration with Guardian
  - Architecture overview
  - Use case scenarios
  - API integration
  - Best practices

### Summary
- **[SCANNER_SUMMARY.md](SCANNER_SUMMARY.md)** - Implementation overview
  - Complete feature list
  - Package structure
  - What's included
  - Next steps

## 📁 Configuration Files

| File | Purpose |
|------|---------|
| [config.example.json](config.example.json) | Full configuration template |
| [targets.example.txt](targets.example.txt) | Target list example |
| [scanner.env.example](scanner.env.example) | Environment variables |
| [Makefile.scanner](Makefile.scanner) | Common make targets |
| [.gitignore.scanner](.gitignore.scanner) | Gitignore entries |

## 🛠️ Source Code

### Main Components
```
scanner/
├── orchestrator.py      # Main scan coordinator
├── cli.py              # Advanced CLI interface
├── settings.py         # Configuration management
└── __main__.py         # Module entry point
```

### Engines
```
scanner/engines/
├── zap_runner.py       # OWASP ZAP DAST
├── nuclei_runner.py    # Nuclei template scanning
├── nmap_runner.py      # Nmap service enumeration
└── trivy_runner.py     # Trivy SCA/SBOM
```

### Enrichment
```
scanner/enrich/
├── epss.py            # EPSS scoring
└── kev.py             # CISA KEV catalog
```

### Reporting
```
scanner/report/
└── renderer.py        # HTML/PDF/JSON generation
```

### UI & CI/CD
```
streamlit_app.py                    # Interactive web UI
.github/workflows/quick-scan.yml    # GitHub Actions workflow
```

## 🎯 Quick Reference by Task

### Installation
1. Read [SCANNER_QUICKSTART.md](SCANNER_QUICKSTART.md) - Section "Installation"
2. Or see [scanner/INSTALLATION.md](scanner/INSTALLATION.md) for detailed steps
3. Run: `pip install -r scanner/requirements.txt`
4. Install external tools (ZAP, Nuclei, Nmap, Trivy)

### First Scan
1. Read [SCANNER_QUICKSTART.md](SCANNER_QUICKSTART.md) - Section "Your First Scan"
2. Run: `python -m scanner.orchestrator --targets https://example.com --passive-only`
3. Open: `out/report.html`

### Configuration
1. Read [SECURITY_SCANNER_README.md](SECURITY_SCANNER_README.md) - Section "Configuration"
2. Copy: `cp config.example.json my-config.json`
3. Edit: `my-config.json`
4. Run: `python scanner/cli.py --config my-config.json`

### Integration with Guardian
1. Read [SCANNER_INTEGRATION.md](SCANNER_INTEGRATION.md)
2. Choose integration pattern
3. Follow practical steps

### CI/CD Setup
1. Review [.github/workflows/quick-scan.yml](.github/workflows/quick-scan.yml)
2. Add `TARGET_URL` secret
3. Workflow runs on PRs automatically

### Troubleshooting
1. Check [SECURITY_SCANNER_README.md](SECURITY_SCANNER_README.md) - Section "Troubleshooting"
2. Check [scanner/INSTALLATION.md](scanner/INSTALLATION.md) - Section "Troubleshooting"
3. Review [SCANNER_QUICKSTART.md](SCANNER_QUICKSTART.md) - Section "Troubleshooting"

## 📊 Usage Examples by Scenario

### Scenario: Basic Web App Scan
**Read**: [SCANNER_QUICKSTART.md](SCANNER_QUICKSTART.md) - "Safe Website Scan"
```bash
python -m scanner.orchestrator --targets https://yourapp.com --passive-only
```

### Scenario: Authenticated Scan
**Read**: [SECURITY_SCANNER_README.md](SECURITY_SCANNER_README.md) - "ZAP Authentication"
```bash
python scanner/cli.py --targets https://app.com --zap-auth "user:pass:login_url"
```

### Scenario: Multiple Targets
**Read**: [SCANNER_QUICKSTART.md](SCANNER_QUICKSTART.md) - "Scan from File"
```bash
python scanner/cli.py --targets-file targets.txt --passive-only
```

### Scenario: Container Scanning
**Read**: [SECURITY_SCANNER_README.md](SECURITY_SCANNER_README.md) - "Trivy Configuration"
```bash
python scanner/cli.py --trivy-target image --trivy-path nginx:latest
```

### Scenario: CI/CD Integration
**Read**: [SCANNER_INTEGRATION.md](SCANNER_INTEGRATION.md) - "CI/CD Integration"
- GitHub Actions: Pre-configured in `.github/workflows/quick-scan.yml`
- GitLab CI: Example in SCANNER_INTEGRATION.md
- Jenkins: Example in SCANNER_INTEGRATION.md

## 🔍 API Reference

### Orchestrator
**Read**: [scanner/README.md](scanner/README.md) - "API Reference"
```python
from scanner.orchestrator import ScanOrchestrator
from scanner.settings import ScannerConfig

config = ScannerConfig()
orchestrator = ScanOrchestrator(config)
findings = orchestrator.run()
```

### Individual Engines
**Read**: [scanner/README.md](scanner/README.md) - "Individual Engines"
```python
from scanner.engines.nuclei_runner import NucleiRunner

nuclei = NucleiRunner(config)
findings = nuclei.run(["https://example.com"])
```

### Report Generation
**Read**: [scanner/README.md](scanner/README.md) - "Report Generation"
```python
from scanner.report.renderer import ReportRenderer

renderer = ReportRenderer(config, findings, sbom)
renderer.generate_all()
```

## 📱 User Interfaces

### Command Line Interface
**Read**: [SECURITY_SCANNER_README.md](SECURITY_SCANNER_README.md) - "Command Line"
```bash
python -m scanner.orchestrator --help
python scanner/cli.py --help
```

### Streamlit UI
**Read**: [SCANNER_QUICKSTART.md](SCANNER_QUICKSTART.md) - "Option 2: Interactive UI"
```bash
streamlit run streamlit_app.py
```

### Programmatic API
**Read**: [scanner/README.md](scanner/README.md) - "Programmatic Usage"
```python
from scanner.orchestrator import ScanOrchestrator
# ... see API Reference section
```

## 🎓 Learning Path

### Beginner (First Hour)
1. ✅ Read [SCANNER_QUICKSTART.md](SCANNER_QUICKSTART.md)
2. ✅ Install dependencies
3. ✅ Run first scan
4. ✅ View report

### Intermediate (First Day)
1. ✅ Read [SECURITY_SCANNER_README.md](SECURITY_SCANNER_README.md)
2. ✅ Create custom configuration
3. ✅ Try different scan types
4. ✅ Explore Streamlit UI

### Advanced (First Week)
1. ✅ Read [scanner/README.md](scanner/README.md)
2. ✅ Programmatic integration
3. ✅ CI/CD setup
4. ✅ Custom report templates

### Expert (Ongoing)
1. ✅ Read [SCANNER_INTEGRATION.md](SCANNER_INTEGRATION.md)
2. ✅ Integrate with existing systems
3. ✅ Extend with new engines
4. ✅ Customize workflows

## 🆘 Support & Troubleshooting

### Common Issues
| Issue | Solution |
|-------|----------|
| Tool not found | [scanner/INSTALLATION.md](scanner/INSTALLATION.md) - Troubleshooting |
| ZAP won't start | [SECURITY_SCANNER_README.md](SECURITY_SCANNER_README.md) - Troubleshooting |
| Scan is slow | [SECURITY_SCANNER_README.md](SECURITY_SCANNER_README.md) - Performance Tips |
| Permission denied | [scanner/INSTALLATION.md](scanner/INSTALLATION.md) - Troubleshooting |

### Getting Help
1. Check relevant documentation section above
2. Search documentation for error message
3. Review example configurations
4. Check tool-specific documentation:
   - [ZAP Docs](https://www.zaproxy.org/docs/)
   - [Nuclei Docs](https://docs.projectdiscovery.io/)
   - [Nmap Docs](https://nmap.org/book/)
   - [Trivy Docs](https://aquasecurity.github.io/trivy/)

## 📋 Checklists

### Pre-Scan Checklist
- [ ] Authorization obtained
- [ ] Tools installed and verified
- [ ] Configuration reviewed
- [ ] Target list validated
- [ ] Output directory prepared
- [ ] Passive mode enabled (for production)

### Post-Scan Checklist
- [ ] Report generated successfully
- [ ] KEV vulnerabilities identified
- [ ] Critical findings prioritized
- [ ] Remediation plan created
- [ ] Stakeholders notified
- [ ] Results archived

### CI/CD Integration Checklist
- [ ] Workflow file added
- [ ] Secrets configured
- [ ] Test run successful
- [ ] Failure conditions set
- [ ] Notifications configured
- [ ] Artifacts uploaded

## 🗺️ Roadmap & Future Features

See [SCANNER_SUMMARY.md](SCANNER_SUMMARY.md) for:
- Current implementation status
- Future enhancement ideas
- Extension opportunities

## 📞 Quick Links

| Resource | Link |
|----------|------|
| Main README | [SECURITY_SCANNER_README.md](SECURITY_SCANNER_README.md) |
| Quick Start | [SCANNER_QUICKSTART.md](SCANNER_QUICKSTART.md) |
| Installation | [scanner/INSTALLATION.md](scanner/INSTALLATION.md) |
| Integration | [SCANNER_INTEGRATION.md](SCANNER_INTEGRATION.md) |
| Package Docs | [scanner/README.md](scanner/README.md) |
| Summary | [SCANNER_SUMMARY.md](SCANNER_SUMMARY.md) |
| Config Example | [config.example.json](config.example.json) |
| Makefile | [Makefile.scanner](Makefile.scanner) |

## 🏆 What's Included

See [SCANNER_SUMMARY.md](SCANNER_SUMMARY.md) for complete list of:
- ✅ Implemented features
- 📦 Package contents
- 🎯 Use cases
- 📊 Output examples
- 🔧 Configuration options

---

**Start here**: [SCANNER_QUICKSTART.md](SCANNER_QUICKSTART.md) for the fastest path to your first scan!

**Need help?** All documentation is comprehensive with examples and troubleshooting guides.

**Ready to integrate?** See [SCANNER_INTEGRATION.md](SCANNER_INTEGRATION.md) for combining with your existing Guardian platform.

