"""
Professional HTML/PDF report renderer
"""
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class ReportRenderer:
    """Generate professional security scan reports"""
    
    def __init__(self, config, findings: List[Dict[str, Any]], sbom: Dict[str, Any] = None):
        self.config = config
        self.findings = findings
        self.sbom = sbom or {}
        self.timestamp = datetime.now()
    
    def generate_executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary statistics"""
        summary = {
            "total_findings": len(self.findings),
            "by_severity": {},
            "has_kev": False,
            "kev_count": 0,
            "top_5_prioritized": [],
            "scan_date": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "targets": self.config.targets,
            "passive_mode": self.config.controls.passive_only
        }
        
        # Count by severity
        for finding in self.findings:
            severity = finding.get("severity", "unknown")
            summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
            
            if finding.get("is_kev"):
                summary["has_kev"] = True
                summary["kev_count"] += 1
        
        # Top 5 prioritized (already sorted by orchestrator)
        summary["top_5_prioritized"] = self.findings[:5]
        
        return summary
    
    def generate_html(self) -> str:
        """Generate HTML report"""
        logger.info("Generating HTML report")
        
        summary = self.generate_executive_summary()
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {summary['scan_date']}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        header {{
            border-bottom: 4px solid #0066cc;
            padding-bottom: 20px;
            margin-bottom: 40px;
        }}
        
        h1 {{
            color: #0066cc;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        h2 {{
            color: #0066cc;
            font-size: 1.8em;
            margin-top: 40px;
            margin-bottom: 20px;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }}
        
        h3 {{
            color: #333;
            font-size: 1.3em;
            margin-top: 25px;
            margin-bottom: 15px;
        }}
        
        .meta-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        
        .meta-item {{
            padding: 10px;
        }}
        
        .meta-label {{
            font-weight: bold;
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .meta-value {{
            color: #333;
            font-size: 1.1em;
            margin-top: 5px;
        }}
        
        .severity-badges {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            margin: 20px 0;
        }}
        
        .badge {{
            padding: 10px 20px;
            border-radius: 5px;
            font-weight: bold;
            text-align: center;
            min-width: 120px;
        }}
        
        .badge-critical {{
            background: #dc3545;
            color: white;
        }}
        
        .badge-high {{
            background: #fd7e14;
            color: white;
        }}
        
        .badge-medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .badge-low {{
            background: #28a745;
            color: white;
        }}
        
        .badge-info {{
            background: #17a2b8;
            color: white;
        }}
        
        .badge-kev {{
            background: #8b0000;
            color: white;
            border: 2px solid #ff0000;
        }}
        
        .kev-alert {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
        }}
        
        .kev-alert.critical {{
            background: #f8d7da;
            border-left-color: #dc3545;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        
        th {{
            background: #0066cc;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 0.5px;
        }}
        
        td {{
            padding: 12px;
            border-bottom: 1px solid #eee;
        }}
        
        tr:hover {{
            background: #f8f9fa;
        }}
        
        .severity {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .severity-critical {{
            background: #dc3545;
            color: white;
        }}
        
        .severity-high {{
            background: #fd7e14;
            color: white;
        }}
        
        .severity-medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .severity-low {{
            background: #28a745;
            color: white;
        }}
        
        .severity-info {{
            background: #17a2b8;
            color: white;
        }}
        
        .kev-indicator {{
            background: #8b0000;
            color: white;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            margin-left: 5px;
        }}
        
        .source-tag {{
            background: #6c757d;
            color: white;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        
        .epss-score {{
            font-family: 'Courier New', monospace;
            font-weight: bold;
        }}
        
        .high-epss {{
            color: #dc3545;
        }}
        
        .medium-epss {{
            color: #fd7e14;
        }}
        
        .low-epss {{
            color: #28a745;
        }}
        
        .evidence {{
            background: #f8f9fa;
            border-left: 3px solid #0066cc;
            padding: 10px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }}
        
        .description {{
            margin: 10px 0;
            line-height: 1.8;
        }}
        
        .references {{
            margin: 10px 0;
        }}
        
        .references a {{
            color: #0066cc;
            text-decoration: none;
            display: block;
            padding: 2px 0;
        }}
        
        .references a:hover {{
            text-decoration: underline;
        }}
        
        .appendix {{
            margin-top: 60px;
            padding-top: 30px;
            border-top: 3px solid #0066cc;
        }}
        
        footer {{
            margin-top: 60px;
            padding-top: 20px;
            border-top: 2px solid #eee;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            
            .container {{
                box-shadow: none;
                padding: 20px;
            }}
            
            tr {{
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Security Scan Report</h1>
            <p style="color: #666; font-size: 1.1em;">Comprehensive Multi-Engine Security Assessment</p>
        </header>
        
        <div class="meta-info">
            <div class="meta-item">
                <div class="meta-label">Scan Date</div>
                <div class="meta-value">{summary['scan_date']}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Total Findings</div>
                <div class="meta-value">{summary['total_findings']}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Scan Mode</div>
                <div class="meta-value">{'Passive' if summary['passive_mode'] else 'Active'}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Targets</div>
                <div class="meta-value">{len(summary['targets'])}</div>
            </div>
        </div>
        
        <section>
            <h2>🎯 Executive Summary</h2>
            
            <h3>Findings by Severity</h3>
            <div class="severity-badges">
"""
        
        # Severity badges
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = summary["by_severity"].get(severity, 0)
            if count > 0:
                html += f'                <div class="badge badge-{severity}">{severity.upper()}<br>{count}</div>\n'
        
        html += "            </div>\n"
        
        # KEV Alert
        if summary["has_kev"]:
            html += f"""
            <div class="kev-alert critical">
                <h3>⚠️ CRITICAL: Known Exploited Vulnerabilities (KEV) Detected</h3>
                <p><strong>{summary['kev_count']}</strong> finding(s) are listed in CISA's Known Exploited Vulnerabilities catalog. These vulnerabilities are actively exploited in the wild and require immediate remediation.</p>
            </div>
"""
        else:
            html += """
            <div class="kev-alert">
                <h3>✅ No Known Exploited Vulnerabilities (KEV) Detected</h3>
                <p>None of the identified vulnerabilities are currently listed in CISA's KEV catalog.</p>
            </div>
"""
        
        html += """
            <h3>Target Scope</h3>
            <ul>
"""
        
        for target in summary["targets"]:
            html += f"                <li>{target}</li>\n"
        
        html += """
            </ul>
        </section>
        
        <section>
            <h2>🔥 Risk Prioritization</h2>
            <p>Findings are prioritized by: <strong>1) KEV Status</strong>, <strong>2) Severity</strong>, <strong>3) EPSS Score</strong></p>
            
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>EPSS</th>
                        <th>KEV</th>
                        <th>CVE</th>
                        <th>Affected</th>
                        <th>Title</th>
                        <th>Source</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        # Risk prioritization table
        for finding in self.findings:
            severity = finding.get("severity", "unknown")
            epss = finding.get("epss_score", 0.0)
            is_kev = finding.get("is_kev", False)
            cve = finding.get("cve") or "N/A"
            location = finding.get("location", "")
            title = finding.get("title", "Untitled")
            source = finding.get("source", "unknown")
            
            # Truncate long titles
            if len(title) > 60:
                title = title[:57] + "..."
            
            # Truncate long locations
            if len(location) > 50:
                location = location[:47] + "..."
            
            # EPSS formatting
            epss_class = "high-epss" if epss > 0.5 else "medium-epss" if epss > 0.1 else "low-epss"
            epss_display = f'{epss:.4f}' if epss > 0 else '-'
            
            kev_badge = '<span class="kev-indicator">KEV</span>' if is_kev else ''
            
            html += f"""                    <tr>
                        <td><span class="severity severity-{severity}">{severity}</span></td>
                        <td><span class="epss-score {epss_class}">{epss_display}</span></td>
                        <td>{kev_badge}</td>
                        <td>{cve}</td>
                        <td>{location}</td>
                        <td>{title}</td>
                        <td><span class="source-tag">{source.upper()}</span></td>
                    </tr>
"""
        
        html += """
                </tbody>
            </table>
        </section>
        
        <section>
            <h2>📋 Detailed Findings</h2>
"""
        
        # Detailed findings
        for idx, finding in enumerate(self.findings, 1):
            severity = finding.get("severity", "unknown")
            title = finding.get("title", "Untitled Finding")
            cve = finding.get("cve")
            cwe = finding.get("cwe")
            description = finding.get("description", "No description available.")
            solution = finding.get("solution", "No remediation guidance available.")
            evidence = finding.get("evidence")
            references = finding.get("references", [])
            is_kev = finding.get("is_kev", False)
            epss = finding.get("epss_score", 0.0)
            location = finding.get("location", "")
            source = finding.get("source", "unknown")
            
            kev_badge = '<span class="kev-indicator">KEV</span>' if is_kev else ''
            
            html += f"""
            <div class="finding" id="finding-{idx}">
                <h3>#{idx}: {title} <span class="severity severity-{severity}">{severity}</span> {kev_badge}</h3>
                
                <div class="meta-info">
                    <div class="meta-item">
                        <div class="meta-label">Source</div>
                        <div class="meta-value"><span class="source-tag">{source.upper()}</span></div>
                    </div>
"""
            
            if cve:
                html += f"""                    <div class="meta-item">
                        <div class="meta-label">CVE</div>
                        <div class="meta-value">{cve}</div>
                    </div>
"""
            
            if cwe:
                html += f"""                    <div class="meta-item">
                        <div class="meta-label">CWE</div>
                        <div class="meta-value">{cwe}</div>
                    </div>
"""
            
            if epss > 0:
                epss_class = "high-epss" if epss > 0.5 else "medium-epss" if epss > 0.1 else "low-epss"
                html += f"""                    <div class="meta-item">
                        <div class="meta-label">EPSS Score</div>
                        <div class="meta-value"><span class="epss-score {epss_class}">{epss:.4f}</span></div>
                    </div>
"""
            
            html += f"""                    <div class="meta-item">
                        <div class="meta-label">Location</div>
                        <div class="meta-value">{location}</div>
                    </div>
                </div>
                
                <div class="description">
                    <strong>Description:</strong><br>
                    {description}
                </div>
                
                <div class="description">
                    <strong>Remediation:</strong><br>
                    {solution}
                </div>
"""
            
            if evidence:
                html += f"""                <div class="evidence">
                    <strong>Evidence:</strong><br>
                    {evidence}
                </div>
"""
            
            if references and isinstance(references, list) and len(references) > 0:
                html += """                <div class="references">
                    <strong>References:</strong><br>
"""
                for ref in references[:5]:  # Limit to 5 references
                    if ref:
                        html += f'                    <a href="{ref}" target="_blank">{ref}</a>\n'
                html += "                </div>\n"
            
            html += "            </div>\n"
        
        html += """
        </section>
        
        <section class="appendix">
            <h2>📊 Technical Appendix</h2>
            
            <h3>Scan Engines Used</h3>
            <ul>
                <li><strong>OWASP ZAP</strong> - Dynamic Application Security Testing (DAST)</li>
                <li><strong>Nuclei</strong> - Template-based vulnerability scanning</li>
                <li><strong>Nmap</strong> - Network service enumeration with NSE scripts</li>
                <li><strong>Trivy</strong> - Software Composition Analysis (SCA) and SBOM generation</li>
            </ul>
            
            <h3>Enrichment Sources</h3>
            <ul>
                <li><strong>EPSS</strong> - Exploit Prediction Scoring System from FIRST.org</li>
                <li><strong>CISA KEV</strong> - Known Exploited Vulnerabilities Catalog</li>
            </ul>
            
            <h3>Report Metadata</h3>
            <ul>
                <li><strong>Generated:</strong> {summary['scan_date']}</li>
                <li><strong>Configuration:</strong> {'Passive Mode' if summary['passive_mode'] else 'Active Mode'}</li>
                <li><strong>Total Findings:</strong> {summary['total_findings']}</li>
            </ul>
        </section>
        
        <footer>
            <p>Enterprise Security Scanner v1.0 | Generated on {summary['scan_date']}</p>
            <p>This report contains confidential security information. Handle with care.</p>
        </footer>
    </div>
</body>
</html>
"""
        
        return html
    
    def save_html(self) -> str:
        """Save HTML report to file"""
        html_content = self.generate_html()
        
        output_file = f"{self.config.output_dir}/report.html"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved to {output_file}")
        return output_file
    
    def save_json(self) -> str:
        """Save JSON report"""
        summary = self.generate_executive_summary()
        
        report_data = {
            "metadata": {
                "scan_date": summary["scan_date"],
                "targets": summary["targets"],
                "passive_mode": summary["passive_mode"],
                "total_findings": summary["total_findings"]
            },
            "summary": summary,
            "findings": self.findings,
            "sbom": self.sbom
        }
        
        output_file = f"{self.config.output_dir}/report.json"
        with open(output_file, "w") as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"JSON report saved to {output_file}")
        return output_file
    
    def save_pdf(self, html_file: str) -> str:
        """Convert HTML to PDF using WeasyPrint or Playwright"""
        logger.info("Generating PDF report")
        
        output_file = f"{self.config.output_dir}/report.pdf"
        
        try:
            # Try WeasyPrint first
            from weasyprint import HTML
            HTML(filename=html_file).write_pdf(output_file)
            logger.info(f"PDF report saved to {output_file} (via WeasyPrint)")
            return output_file
        
        except ImportError:
            logger.warning("WeasyPrint not available, trying Playwright")
            
            try:
                from playwright.sync_api import sync_playwright
                
                with sync_playwright() as p:
                    browser = p.chromium.launch()
                    page = browser.new_page()
                    page.goto(f"file://{os.path.abspath(html_file)}")
                    page.pdf(path=output_file)
                    browser.close()
                
                logger.info(f"PDF report saved to {output_file} (via Playwright)")
                return output_file
            
            except ImportError:
                logger.error("Neither WeasyPrint nor Playwright available. PDF generation skipped.")
                logger.info("Install with: pip install weasyprint  OR  pip install playwright && playwright install")
                return None
        
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return None
    
    def generate_all(self):
        """Generate all report formats"""
        logger.info("Generating all report formats")
        
        # HTML
        html_file = self.save_html()
        
        # JSON
        self.save_json()
        
        # PDF
        self.save_pdf(html_file)
        
        logger.info("All reports generated successfully")

