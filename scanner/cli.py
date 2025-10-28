#!/usr/bin/env python3
"""
CLI wrapper for Enterprise Security Scanner
"""
import argparse
import json
import logging
import sys
from pathlib import Path

from scanner.settings import ScannerConfig, load_config_from_env, load_config_from_dict
from scanner.orchestrator import ScanOrchestrator
from scanner.report.renderer import ReportRenderer


def setup_logging(verbose: bool = False):
    """Configure logging"""
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('scanner.log')
        ]
    )


def load_config_file(config_file: str) -> ScannerConfig:
    """Load configuration from JSON file"""
    try:
        with open(config_file, 'r') as f:
            data = json.load(f)
        return load_config_from_dict(data)
    except Exception as e:
        print(f"Error loading config file: {e}")
        sys.exit(1)


def print_summary(findings: list):
    """Print scan summary to console"""
    print("\n" + "=" * 80)
    print("SECURITY SCAN SUMMARY")
    print("=" * 80)
    
    print(f"\n📊 Total Findings: {len(findings)}")
    
    # Count by severity
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    kev_count = 0
    high_epss_count = 0
    
    for finding in findings:
        severity = finding.get('severity', 'unknown')
        if severity in severity_counts:
            severity_counts[severity] += 1
        
        if finding.get('is_kev'):
            kev_count += 1
        
        if finding.get('epss_score', 0) > 0.5:
            high_epss_count += 1
    
    print("\n📈 By Severity:")
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        count = severity_counts[severity]
        if count > 0:
            emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢', 'info': '🔵'}
            print(f"   {emoji.get(severity, '⚪')} {severity.upper():12} {count:4}")
    
    print(f"\n⚠️  Known Exploited Vulnerabilities (KEV): {kev_count}")
    if kev_count > 0:
        print("   ⚡ CRITICAL: These vulnerabilities are actively exploited!")
    
    print(f"\n🎯 High EPSS Score (>0.5): {high_epss_count}")
    
    # Top 3 findings
    if findings:
        print("\n🔥 Top 3 Priority Findings:")
        for idx, finding in enumerate(findings[:3], 1):
            title = finding.get('title', 'Untitled')[:60]
            severity = finding.get('severity', 'unknown').upper()
            kev_badge = ' [KEV]' if finding.get('is_kev') else ''
            epss = finding.get('epss_score', 0)
            
            print(f"   {idx}. [{severity}] {title}{kev_badge}")
            print(f"      EPSS: {epss:.4f} | Location: {finding.get('location', 'N/A')[:50]}")
    
    print("\n" + "=" * 80)


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Enterprise Security Scanner - Multi-engine vulnerability assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  %(prog)s --targets https://example.com
  
  # Passive scan with custom output
  %(prog)s --targets https://example.com --passive-only --output-dir results/scan-001
  
  # Multiple targets from file
  %(prog)s --targets-file targets.txt --max-concurrency 4
  
  # Load from config file
  %(prog)s --config config.json
  
  # Scan with authentication
  %(prog)s --targets https://example.com --zap-auth username:password:https://example.com/login
        """
    )
    
    # Input sources
    input_group = parser.add_argument_group('Input')
    input_group.add_argument(
        '--targets',
        nargs='+',
        help='Target URLs or hosts to scan'
    )
    input_group.add_argument(
        '--targets-file',
        type=str,
        help='File containing targets (one per line)'
    )
    input_group.add_argument(
        '--config',
        type=str,
        help='Load configuration from JSON file'
    )
    
    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument(
        '--passive-only',
        action='store_true',
        help='Run in passive mode (no active exploitation)'
    )
    scan_group.add_argument(
        '--max-concurrency',
        type=int,
        default=4,
        help='Maximum concurrent engines (default: 4)'
    )
    scan_group.add_argument(
        '--timeout',
        type=int,
        default=3600,
        help='Per-engine timeout in seconds (default: 3600)'
    )
    scan_group.add_argument(
        '--exclude',
        nargs='+',
        help='Exclude patterns (paths/domains to skip)'
    )
    
    # Engine-specific
    engine_group = parser.add_argument_group('Engine Configuration')
    engine_group.add_argument(
        '--skip-zap',
        action='store_true',
        help='Skip OWASP ZAP scan'
    )
    engine_group.add_argument(
        '--skip-nuclei',
        action='store_true',
        help='Skip Nuclei scan'
    )
    engine_group.add_argument(
        '--skip-nmap',
        action='store_true',
        help='Skip Nmap scan'
    )
    engine_group.add_argument(
        '--skip-trivy',
        action='store_true',
        help='Skip Trivy scan'
    )
    engine_group.add_argument(
        '--zap-auth',
        type=str,
        help='ZAP authentication (format: username:password:login_url)'
    )
    engine_group.add_argument(
        '--zap-openapi',
        type=str,
        help='ZAP OpenAPI specification URL'
    )
    engine_group.add_argument(
        '--nuclei-templates',
        type=str,
        default='http',
        help='Nuclei template tags (default: http)'
    )
    engine_group.add_argument(
        '--trivy-target',
        choices=['fs', 'repo', 'image'],
        default='fs',
        help='Trivy scan target type (default: fs)'
    )
    engine_group.add_argument(
        '--trivy-path',
        type=str,
        default='.',
        help='Trivy scan path (default: .)'
    )
    
    # Output
    output_group = parser.add_argument_group('Output')
    output_group.add_argument(
        '--output-dir',
        default='out',
        help='Output directory for results (default: out)'
    )
    output_group.add_argument(
        '--no-report',
        action='store_true',
        help='Skip report generation (findings JSON only)'
    )
    output_group.add_argument(
        '--no-pdf',
        action='store_true',
        help='Skip PDF generation'
    )
    
    # Misc
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='Enterprise Security Scanner v1.0.0'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    # Load configuration
    if args.config:
        logger.info(f"Loading configuration from {args.config}")
        config = load_config_file(args.config)
    else:
        config = load_config_from_env()
    
    # Override with CLI arguments
    if args.targets:
        config.targets = args.targets
    elif args.targets_file:
        try:
            with open(args.targets_file, 'r') as f:
                config.targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Failed to read targets file: {e}")
            sys.exit(1)
    
    if not config.targets:
        logger.error("No targets specified. Use --targets or --targets-file")
        parser.print_help()
        sys.exit(1)
    
    # Apply CLI options
    if args.passive_only:
        config.controls.passive_only = True
    
    if args.max_concurrency:
        config.controls.max_concurrency = args.max_concurrency
    
    if args.timeout:
        config.controls.timeout = args.timeout
    
    if args.exclude:
        config.controls.exclude = args.exclude
    
    if args.output_dir:
        config.output_dir = args.output_dir
    
    # ZAP configuration
    if args.zap_auth:
        parts = args.zap_auth.split(':')
        if len(parts) == 3:
            config.scan_opts.zap.auth = {
                'username': parts[0],
                'password': parts[1],
                'login_url': parts[2]
            }
        else:
            logger.error("Invalid ZAP auth format. Use: username:password:login_url")
            sys.exit(1)
    
    if args.zap_openapi:
        config.scan_opts.zap.openapi_url = args.zap_openapi
    
    # Nuclei configuration
    if args.nuclei_templates:
        config.scan_opts.nuclei.templates = args.nuclei_templates
    
    # Trivy configuration
    if args.trivy_target:
        config.scan_opts.trivy.target = args.trivy_target
    
    if args.trivy_path:
        config.scan_opts.trivy.path = args.trivy_path
    
    # Create output directory
    Path(config.output_dir).mkdir(parents=True, exist_ok=True)
    
    # Print configuration
    logger.info("=" * 80)
    logger.info("ENTERPRISE SECURITY SCANNER")
    logger.info("=" * 80)
    logger.info(f"Targets: {', '.join(config.targets)}")
    logger.info(f"Mode: {'Passive' if config.controls.passive_only else 'Active'}")
    logger.info(f"Concurrency: {config.controls.max_concurrency}")
    logger.info(f"Output: {config.output_dir}")
    logger.info("=" * 80)
    
    # Run scan
    try:
        orchestrator = ScanOrchestrator(config)
        findings = orchestrator.run()
        
        # Generate reports
        if not args.no_report:
            logger.info("Generating reports...")
            renderer = ReportRenderer(config, findings, orchestrator.sbom)
            
            # HTML
            renderer.save_html()
            
            # JSON
            renderer.save_json()
            
            # PDF (unless disabled)
            if not args.no_pdf:
                html_file = f"{config.output_dir}/report.html"
                renderer.save_pdf(html_file)
        
        # Print summary
        print_summary(findings)
        
        # Exit with appropriate code
        kev_count = sum(1 for f in findings if f.get('is_kev'))
        critical_count = sum(1 for f in findings if f.get('severity') == 'critical')
        
        if kev_count > 0:
            logger.warning(f"Exiting with error code due to {kev_count} KEV findings")
            sys.exit(2)
        elif critical_count > 0:
            logger.warning(f"Exiting with error code due to {critical_count} critical findings")
            sys.exit(1)
        else:
            logger.info("Scan completed successfully")
            sys.exit(0)
    
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(130)
    
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()

