"""
Streamlit UI for Enterprise Security Scanner
"""
import json
import os
import streamlit as st
from datetime import datetime
from scanner.settings import ScannerConfig, ScanOptions, Controls
from scanner.orchestrator import ScanOrchestrator
from scanner.report.renderer import ReportRenderer


# Page config
st.set_page_config(
    page_title="Enterprise Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main {
        padding-top: 2rem;
    }
    .stButton>button {
        width: 100%;
        background-color: #0066cc;
        color: white;
        font-weight: bold;
        padding: 0.75rem;
        border-radius: 0.5rem;
    }
    .stButton>button:hover {
        background-color: #0052a3;
    }
    .kpi-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 0.5rem;
        color: white;
        text-align: center;
        margin-bottom: 1rem;
    }
    .kpi-value {
        font-size: 2.5rem;
        font-weight: bold;
        margin: 0.5rem 0;
    }
    .kpi-label {
        font-size: 0.9rem;
        opacity: 0.9;
    }
    .severity-critical {
        background-color: #dc3545;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 0.25rem;
        font-weight: bold;
    }
    .severity-high {
        background-color: #fd7e14;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 0.25rem;
        font-weight: bold;
    }
    .severity-medium {
        background-color: #ffc107;
        color: #333;
        padding: 0.25rem 0.75rem;
        border-radius: 0.25rem;
        font-weight: bold;
    }
    .severity-low {
        background-color: #28a745;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 0.25rem;
        font-weight: bold;
    }
    .kev-badge {
        background-color: #8b0000;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.8rem;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


# Initialize session state
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None
if 'scan_running' not in st.session_state:
    st.session_state.scan_running = False


def run_scan(targets, passive_only, max_concurrency):
    """Execute security scan"""
    # Create configuration
    config = ScannerConfig()
    config.targets = [t.strip() for t in targets.split('\n') if t.strip()]
    config.controls.passive_only = passive_only
    config.controls.max_concurrency = max_concurrency
    config.output_dir = "out"
    
    # Run orchestrator
    orchestrator = ScanOrchestrator(config)
    findings = orchestrator.run()
    
    # Generate reports
    renderer = ReportRenderer(config, findings, orchestrator.sbom)
    renderer.generate_all()
    
    return {
        'findings': findings,
        'config': config,
        'sbom': orchestrator.sbom,
        'timestamp': datetime.now()
    }


# Header
st.title("🛡️ Enterprise Security Scanner")
st.markdown("Multi-engine security scanning with CVE enrichment and professional reporting")

# Sidebar - Controls
with st.sidebar:
    st.header("⚙️ Scan Configuration")
    
    targets_input = st.text_area(
        "Target URLs/Hosts",
        value="https://example.com",
        height=150,
        help="Enter one target per line"
    )
    
    passive_only = st.checkbox(
        "Passive Mode Only",
        value=True,
        help="Disable active exploitation and intrusive tests"
    )
    
    max_concurrency = st.slider(
        "Max Concurrency",
        min_value=1,
        max_value=8,
        value=4,
        help="Maximum concurrent scan engines"
    )
    
    st.markdown("---")
    
    scan_button = st.button("🚀 Start Scan", type="primary", disabled=st.session_state.scan_running)
    
    if scan_button:
        if not targets_input.strip():
            st.error("Please enter at least one target")
        else:
            st.session_state.scan_running = True
            
            with st.spinner("🔍 Running security scan..."):
                try:
                    results = run_scan(targets_input, passive_only, max_concurrency)
                    st.session_state.scan_results = results
                    st.success("✅ Scan completed successfully!")
                except Exception as e:
                    st.error(f"❌ Scan failed: {str(e)}")
                finally:
                    st.session_state.scan_running = False
            
            st.rerun()
    
    st.markdown("---")
    st.markdown("### 🔧 Scan Engines")
    st.markdown("""
    - **ZAP** - DAST
    - **Nuclei** - Templates
    - **Nmap** - Service Enum
    - **Trivy** - SCA/SBOM
    """)

# Main content
if st.session_state.scan_results is None:
    # Welcome screen
    st.info("👈 Configure scan parameters in the sidebar and click 'Start Scan' to begin")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🎯 Features")
        st.markdown("""
        - **Multi-Engine Scanning**: ZAP, Nuclei, Nmap, Trivy
        - **CVE Enrichment**: EPSS scores + CISA KEV
        - **Smart Prioritization**: KEV → Severity → EPSS
        - **Professional Reports**: HTML, PDF, JSON
        - **SBOM Generation**: CycloneDX format
        """)
    
    with col2:
        st.markdown("### 🔒 Security Controls")
        st.markdown("""
        - **Passive Mode**: No active exploitation
        - **Rate Limiting**: Configurable concurrency
        - **Scope Control**: Target allow/deny lists
        - **Timeout Protection**: Per-engine limits
        """)

else:
    # Display results
    results = st.session_state.scan_results
    findings = results['findings']
    config = results['config']
    
    # KPIs
    st.header("📊 Scan Summary")
    
    # Count by severity
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    kev_count = 0
    
    for finding in findings:
        severity = finding.get('severity', 'unknown')
        if severity in severity_counts:
            severity_counts[severity] += 1
        if finding.get('is_kev'):
            kev_count += 1
    
    # Display KPIs
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("Total Findings", len(findings))
    
    with col2:
        st.metric("Critical", severity_counts['critical'], delta_color="inverse")
    
    with col3:
        st.metric("High", severity_counts['high'], delta_color="inverse")
    
    with col4:
        st.metric("Medium", severity_counts['medium'], delta_color="inverse")
    
    with col5:
        st.metric("KEV", kev_count, delta_color="inverse")
    
    # KEV Alert
    if kev_count > 0:
        st.error(f"⚠️ **CRITICAL**: {kev_count} Known Exploited Vulnerabilities detected! Immediate action required.")
    else:
        st.success("✅ No Known Exploited Vulnerabilities detected")
    
    st.markdown("---")
    
    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🔥 Top Risks", "📋 All Findings", "📊 Report", "📦 Downloads"])
    
    with tab1:
        st.subheader("Top Priority Findings")
        st.markdown("Sorted by: **KEV Status** → **Severity** → **EPSS Score**")
        
        # Display top 10
        for idx, finding in enumerate(findings[:10], 1):
            with st.expander(
                f"#{idx} - {finding.get('title', 'Untitled')} "
                f"{'🔴 KEV' if finding.get('is_kev') else ''}"
            ):
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    severity = finding.get('severity', 'unknown').upper()
                    st.markdown(f"**Severity:** `{severity}`")
                
                with col2:
                    epss = finding.get('epss_score', 0)
                    st.markdown(f"**EPSS:** `{epss:.4f}`")
                
                with col3:
                    cve = finding.get('cve') or 'N/A'
                    st.markdown(f"**CVE:** `{cve}`")
                
                with col4:
                    source = finding.get('source', 'unknown').upper()
                    st.markdown(f"**Source:** `{source}`")
                
                st.markdown("**Location:**")
                st.code(finding.get('location', 'N/A'))
                
                if finding.get('description'):
                    st.markdown("**Description:**")
                    st.write(finding['description'][:500])
                
                if finding.get('solution'):
                    st.markdown("**Remediation:**")
                    st.info(finding['solution'][:500])
    
    with tab2:
        st.subheader("All Findings")
        
        # Filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=['critical', 'high', 'medium', 'low', 'info'],
                default=['critical', 'high', 'medium', 'low', 'info']
            )
        
        with col2:
            source_filter = st.multiselect(
                "Filter by Source",
                options=['zap', 'nuclei', 'nmap', 'trivy'],
                default=['zap', 'nuclei', 'nmap', 'trivy']
            )
        
        with col3:
            kev_filter = st.selectbox(
                "KEV Filter",
                options=['All', 'KEV Only', 'Non-KEV'],
                index=0
            )
        
        # Apply filters
        filtered = [
            f for f in findings
            if f.get('severity') in severity_filter
            and f.get('source') in source_filter
            and (
                kev_filter == 'All'
                or (kev_filter == 'KEV Only' and f.get('is_kev'))
                or (kev_filter == 'Non-KEV' and not f.get('is_kev'))
            )
        ]
        
        st.markdown(f"**Showing {len(filtered)} of {len(findings)} findings**")
        
        # Display table
        for finding in filtered:
            severity = finding.get('severity', 'unknown')
            title = finding.get('title', 'Untitled')
            cve = finding.get('cve') or '-'
            epss = finding.get('epss_score', 0)
            is_kev = '🔴 KEV' if finding.get('is_kev') else ''
            location = finding.get('location', 'N/A')
            source = finding.get('source', 'unknown').upper()
            
            st.markdown(
                f"`{severity.upper()}` `{source}` **{title}** {is_kev}  \n"
                f"CVE: `{cve}` | EPSS: `{epss:.4f}` | {location[:80]}"
            )
    
    with tab3:
        st.subheader("📄 Security Report")
        
        # Load and display HTML report
        html_path = "out/report.html"
        if os.path.exists(html_path):
            with open(html_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            # Display in iframe
            st.components.v1.html(html_content, height=800, scrolling=True)
        else:
            st.warning("Report not yet generated")
    
    with tab4:
        st.subheader("📥 Download Reports")
        
        col1, col2, col3, col4 = st.columns(4)
        
        # HTML Report
        with col1:
            if os.path.exists("out/report.html"):
                with open("out/report.html", 'rb') as f:
                    st.download_button(
                        label="📄 Download HTML",
                        data=f,
                        file_name=f"security_report_{results['timestamp'].strftime('%Y%m%d_%H%M%S')}.html",
                        mime="text/html"
                    )
        
        # PDF Report
        with col2:
            if os.path.exists("out/report.pdf"):
                with open("out/report.pdf", 'rb') as f:
                    st.download_button(
                        label="📕 Download PDF",
                        data=f,
                        file_name=f"security_report_{results['timestamp'].strftime('%Y%m%d_%H%M%S')}.pdf",
                        mime="application/pdf"
                    )
        
        # JSON Report
        with col3:
            if os.path.exists("out/report.json"):
                with open("out/report.json", 'r') as f:
                    st.download_button(
                        label="📋 Download JSON",
                        data=f,
                        file_name=f"security_report_{results['timestamp'].strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
        
        # SBOM
        with col4:
            if os.path.exists("out/sbom.json"):
                with open("out/sbom.json", 'r') as f:
                    st.download_button(
                        label="📦 Download SBOM",
                        data=f,
                        file_name=f"sbom_{results['timestamp'].strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
        
        st.markdown("---")
        st.info("💡 All reports are also saved in the `out/` directory")
        
        # Display raw findings JSON
        with st.expander("🔍 View Raw Findings JSON"):
            st.json(findings[:5])  # Show first 5 for preview

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #666;'>"
    "Enterprise Security Scanner v1.0 | Multi-engine scanning with CVE enrichment"
    "</div>",
    unsafe_allow_html=True
)

