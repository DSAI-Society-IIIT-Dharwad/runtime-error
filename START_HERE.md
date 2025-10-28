# 🎯 START HERE - Enterprise Security Scanner

Welcome! This is your starting point for the newly added Enterprise Security Scanner.

## ⚡ What Is This?

An **enterprise-grade security scanner** that combines multiple industry-standard tools to perform comprehensive vulnerability assessments with automated CVE enrichment and professional reporting.

## 🚀 Quick Actions

### Just Want to Scan?

```bash
# 1. Install Python dependencies (one-time)
pip install -r scanner/requirements.txt

# 2. Install security tools (one-time)
# See scanner/INSTALLATION.md for your platform

# 3. Run a scan!
python -m scanner.orchestrator --targets https://example.com --passive-only

# 4. View the report
open out/report.html
```

### Want the Interactive UI?

```bash
streamlit run streamlit_app.py
# Open browser to http://localhost:8501
```

## 📚 Documentation Roadmap

Choose your path:

### 🏃 Fast Track (5 minutes)
→ **[SCANNER_QUICKSTART.md](SCANNER_QUICKSTART.md)**
- Installation in 3 steps
- Your first scan in 2 commands
- Understanding results

### 📖 Complete Guide (30 minutes)
→ **[SECURITY_SCANNER_README.md](SECURITY_SCANNER_README.md)**
- All features explained
- Configuration options
- Advanced usage
- Integration patterns
- Troubleshooting

### 🔧 Installation Details
→ **[scanner/INSTALLATION.md](scanner/INSTALLATION.md)**
- Platform-specific instructions
- Tool installation
- Verification scripts
- Common issues

### 🔗 Integration with Guardian
→ **[SCANNER_INTEGRATION.md](SCANNER_INTEGRATION.md)**
- How it fits with your existing project
- Combined workflows
- API integration
- Best practices

### 📋 Complete Overview
→ **[SCANNER_SUMMARY.md](SCANNER_SUMMARY.md)**
- Everything that's included
- Feature checklist
- Code statistics
- Next steps

### 🗺️ All Documentation
→ **[SCANNER_INDEX.md](SCANNER_INDEX.md)**
- Master index of all docs
- Quick reference
- Task-based navigation

## 🎯 What Can It Do?

### Multi-Engine Scanning
- **OWASP ZAP** - Dynamic application security testing
- **Nuclei** - Template-based vulnerability scanning
- **Nmap** - Network service enumeration
- **Trivy** - Software composition analysis + SBOM

### Smart CVE Enrichment
- **EPSS Scores** - Exploit prediction (how likely to be exploited?)
- **CISA KEV** - Known exploited vulnerabilities (actively being exploited!)

### Professional Reports
- **HTML** - Beautiful, interactive web report
- **PDF** - Print-ready documentation
- **JSON** - Machine-readable for integration
- **SBOM** - Software bill of materials

### Security Controls
- **Passive Mode** - Safe for production (no active attacks)
- **Rate Limiting** - Protect target systems
- **Scope Control** - Define what to scan
- **CI/CD Ready** - GitHub Actions included

## 🎓 Learning Path

### Beginner
1. Read [SCANNER_QUICKSTART.md](SCANNER_QUICKSTART.md)
2. Install dependencies
3. Run first scan
4. Explore the report

### Intermediate
1. Read [SECURITY_SCANNER_README.md](SECURITY_SCANNER_README.md)
2. Create custom configuration
3. Try different scan types
4. Use the Streamlit UI

### Advanced
1. Read [scanner/README.md](scanner/README.md)
2. Integrate programmatically
3. Set up CI/CD
4. Customize reports

## 💡 Quick Examples

### Scan a Website (Passive)
```bash
python -m scanner.orchestrator \
  --targets https://example.com \
  --passive-only
```

### Multiple Targets
```bash
python -m scanner.orchestrator \
  --targets https://app.example.com https://api.example.com \
  --passive-only
```

### With Authentication
```bash
python scanner/cli.py \
  --targets https://example.com \
  --zap-auth "testuser:testpass:https://example.com/login"
```

### From Configuration File
```bash
python scanner/cli.py --config config.example.json
```

### Interactive UI
```bash
streamlit run streamlit_app.py
```

## ⚠️ Important Before You Start

### Authorization Required
**ALWAYS** get written permission before scanning systems you don't own. Unauthorized scanning may be illegal.

### Use Passive Mode
For production systems, always use `--passive-only` flag. This ensures no active exploitation attempts.

### Install External Tools
The scanner requires these tools to be installed:
- OWASP ZAP
- Nuclei  
- Nmap
- Trivy

See [scanner/INSTALLATION.md](scanner/INSTALLATION.md) for installation instructions.

## 🆘 Need Help?

### Quick Issues
- **Tool not found?** → [scanner/INSTALLATION.md](scanner/INSTALLATION.md) - Troubleshooting
- **First scan?** → [SCANNER_QUICKSTART.md](SCANNER_QUICKSTART.md)
- **Configuration?** → [SECURITY_SCANNER_README.md](SECURITY_SCANNER_README.md) - Configuration section

### All Documentation
Navigate everything: [SCANNER_INDEX.md](SCANNER_INDEX.md)

## 📦 What's Included

```
✅ Complete scanner package
✅ 4 scanning engines (ZAP, Nuclei, Nmap, Trivy)
✅ CVE enrichment (EPSS + KEV)
✅ Professional HTML/PDF/JSON reports
✅ Interactive Streamlit UI
✅ GitHub Actions CI/CD workflow
✅ 8 comprehensive documentation files
✅ Example configurations
✅ Make targets for common tasks
```

## 🎉 You're Ready!

Everything is implemented, documented, and ready to use.

**Start with**: [SCANNER_QUICKSTART.md](SCANNER_QUICKSTART.md) (5 minutes to your first scan)

**Or jump right in**:
```bash
python -m scanner.orchestrator --targets https://example.com --passive-only
```

---

**Questions?** All documentation is comprehensive with examples and troubleshooting.

**Want to integrate?** See [SCANNER_INTEGRATION.md](SCANNER_INTEGRATION.md) for combining with Guardian.

**Ready to scan!** 🛡️

