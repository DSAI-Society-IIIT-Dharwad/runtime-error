# 🔧 Installation Guide

Complete installation instructions for the Enterprise Security Scanner.

## Prerequisites

- **Python**: 3.11 or higher
- **OS**: Linux, macOS, or Windows
- **RAM**: 4GB minimum, 8GB recommended
- **Disk**: 2GB free space for tools and databases

## Step-by-Step Installation

### 1. Python Environment

#### Option A: Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv scanner-env

# Activate
# Linux/macOS:
source scanner-env/bin/activate
# Windows:
scanner-env\Scripts\activate

# Install dependencies
pip install -r scanner/requirements.txt
```

#### Option B: System Python

```bash
pip install -r scanner/requirements.txt
```

### 2. External Security Tools

#### Linux (Ubuntu/Debian)

```bash
#!/bin/bash

# Update package lists
sudo apt-get update

# Install Nmap
sudo apt-get install -y nmap

# Install OWASP ZAP
sudo snap install zaproxy --classic

# Install Nuclei
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip
unzip nuclei_linux_amd64.zip
sudo mv nuclei /usr/local/bin/
sudo chmod +x /usr/local/bin/nuclei
rm nuclei_linux_amd64.zip

# Update Nuclei templates
nuclei -update-templates

# Install Trivy
sudo apt-get install -y wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy

# Verify installations
echo "Verifying installations..."
zap.sh -version
nuclei -version
nmap --version
trivy --version
```

#### macOS (Homebrew)

```bash
#!/bin/bash

# Install Homebrew if not already installed
if ! command -v brew &> /dev/null; then
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Install tools
brew install --cask owasp-zap
brew install nuclei
brew install nmap
brew install trivy

# Update Nuclei templates
nuclei -update-templates

# Verify installations
echo "Verifying installations..."
/Applications/ZAP.app/Contents/Java/zap.sh -version
nuclei -version
nmap --version
trivy --version
```

#### Windows

**PowerShell (Run as Administrator):**

```powershell
# Install Chocolatey if not already installed
if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

# Install Nmap
choco install -y nmap

# Download and install OWASP ZAP
$zapUrl = "https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2_14_0_windows.exe"
$zapInstaller = "$env:TEMP\zap_installer.exe"
Invoke-WebRequest -Uri $zapUrl -OutFile $zapInstaller
Start-Process -FilePath $zapInstaller -ArgumentList "/S" -Wait
Remove-Item $zapInstaller

# Download and install Nuclei
$nucleiUrl = "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_windows_amd64.zip"
$nucleiZip = "$env:TEMP\nuclei.zip"
$nucleiDir = "C:\Program Files\nuclei"
Invoke-WebRequest -Uri $nucleiUrl -OutFile $nucleiZip
Expand-Archive -Path $nucleiZip -DestinationPath $nucleiDir -Force
Remove-Item $nucleiZip
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";$nucleiDir", [EnvironmentVariableTarget]::Machine)

# Download and install Trivy
$trivyUrl = "https://github.com/aquasecurity/trivy/releases/latest/download/trivy_windows-64bit.zip"
$trivyZip = "$env:TEMP\trivy.zip"
$trivyDir = "C:\Program Files\trivy"
Invoke-WebRequest -Uri $trivyUrl -OutFile $trivyZip
Expand-Archive -Path $trivyZip -DestinationPath $trivyDir -Force
Remove-Item $trivyZip
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";$trivyDir", [EnvironmentVariableTarget]::Machine)

Write-Host "Installation complete. Please restart your terminal."
```

**Or install manually:**

1. **OWASP ZAP**: Download from https://www.zaproxy.org/download/
2. **Nuclei**: Download from https://github.com/projectdiscovery/nuclei/releases
3. **Nmap**: Download from https://nmap.org/download.html
4. **Trivy**: Download from https://github.com/aquasecurity/trivy/releases

Add installation directories to system PATH.

### 3. Optional: PDF Generation

Choose one of these for PDF report generation:

#### Option A: WeasyPrint (Recommended)

```bash
# Linux (Ubuntu/Debian)
sudo apt-get install -y python3-cffi python3-brotli libpango-1.0-0 libpangoft2-1.0-0
pip install weasyprint

# macOS
brew install pango
pip install weasyprint

# Windows (may require Visual C++)
pip install weasyprint
```

#### Option B: Playwright

```bash
pip install playwright
playwright install chromium
```

### 4. Verification

Run the verification script:

```bash
python3 << 'EOF'
import subprocess
import sys

tools = {
    'ZAP': ['zap.sh', '-version'],
    'Nuclei': ['nuclei', '-version'],
    'Nmap': ['nmap', '--version'],
    'Trivy': ['trivy', '--version']
}

print("Verifying tool installations...\n")

for tool, cmd in tools.items():
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        if result.returncode == 0:
            print(f"✅ {tool}: Installed")
        else:
            print(f"❌ {tool}: Not working properly")
    except FileNotFoundError:
        print(f"❌ {tool}: Not found in PATH")
    except Exception as e:
        print(f"❌ {tool}: Error checking - {e}")

print("\nVerifying Python packages...")
try:
    import requests
    print("✅ requests: Installed")
except ImportError:
    print("❌ requests: Not installed")

try:
    import streamlit
    print("✅ streamlit: Installed")
except ImportError:
    print("⚠️  streamlit: Not installed (optional)")

try:
    import weasyprint
    print("✅ weasyprint: Installed")
except ImportError:
    try:
        import playwright
        print("✅ playwright: Installed")
    except ImportError:
        print("⚠️  PDF generation: Not available (optional)")

print("\n" + "="*50)
print("Installation verification complete!")
EOF
```

### 5. Initial Configuration

```bash
# Create output directory
mkdir -p out

# Update Nuclei templates
nuclei -update-templates

# Update Trivy database
trivy image --download-db-only

# Test basic scan (if you have authorization)
python -m scanner.orchestrator --targets https://example.com --passive-only --verbose
```

## Troubleshooting

### Common Issues

#### Issue: ZAP command not found

**Solution (Linux/macOS):**
```bash
# Find ZAP installation
find /opt /Applications -name "zap.sh" 2>/dev/null

# Create symlink
sudo ln -s /path/to/zap.sh /usr/local/bin/zap.sh
```

**Solution (Windows):**
Add ZAP installation directory to PATH:
```
C:\Program Files\ZAP\Zed Attack Proxy\
```

#### Issue: Nuclei templates not updating

**Solution:**
```bash
# Clear cache and re-download
rm -rf ~/.config/nuclei/
nuclei -update-templates
```

#### Issue: Trivy database download fails

**Solution:**
```bash
# Clear cache
trivy image --clear-cache

# Manually download
trivy image --download-db-only

# Check connectivity
curl -I https://ghcr.io
```

#### Issue: WeasyPrint installation fails

**Solution (Linux):**
```bash
# Install system dependencies
sudo apt-get install -y \
    python3-dev \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    python3-cffi \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info

pip install weasyprint
```

**Alternative:**
```bash
# Use Playwright instead
pip install playwright
playwright install chromium
```

#### Issue: Permission denied errors

**Solution:**
```bash
# Run with appropriate permissions
sudo python -m scanner.orchestrator --targets <target>

# Or grant capabilities (Linux, for Nmap)
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

### Verification Scripts

#### Check Python Environment

```bash
python3 << 'EOF'
import sys
print(f"Python version: {sys.version}")
print(f"Python executable: {sys.executable}")

import scanner
print(f"Scanner package: {scanner.__file__}")
EOF
```

#### Check Tool Versions

```bash
#!/bin/bash
echo "Tool Versions:"
echo "=============="
zap.sh -version 2>/dev/null || echo "ZAP: Not found"
nuclei -version 2>/dev/null || echo "Nuclei: Not found"
nmap --version 2>/dev/null | head -n1 || echo "Nmap: Not found"
trivy --version 2>/dev/null || echo "Trivy: Not found"
```

## Docker Alternative (Coming Soon)

For a containerized installation:

```bash
# Build Docker image
docker build -t security-scanner .

# Run scan
docker run -v $(pwd)/out:/app/out security-scanner \
  --targets https://example.com \
  --passive-only
```

## Next Steps

After successful installation:

1. Read the [Quick Start Guide](SECURITY_SCANNER_README.md#-quick-start)
2. Review [Usage Examples](SECURITY_SCANNER_README.md#-usage-examples)
3. Configure your first scan
4. Review [Security Controls](SECURITY_SCANNER_README.md#-security-controls)

## Support

For installation issues:
1. Check troubleshooting section above
2. Verify system requirements
3. Review tool-specific documentation:
   - [ZAP](https://www.zaproxy.org/docs/)
   - [Nuclei](https://docs.projectdiscovery.io/tools/nuclei/overview)
   - [Nmap](https://nmap.org/book/man.html)
   - [Trivy](https://aquasecurity.github.io/trivy/)

## System Requirements

### Minimum
- CPU: 2 cores
- RAM: 4GB
- Disk: 2GB free
- Network: Internet connection for CVE enrichment

### Recommended
- CPU: 4+ cores
- RAM: 8GB+
- Disk: 10GB+ free (for tool databases)
- Network: High-speed connection

### Performance Notes
- ZAP requires ~1GB RAM
- Trivy database is ~200MB
- Nuclei templates are ~100MB
- Concurrent scanning scales with available CPU cores

