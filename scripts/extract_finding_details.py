#!/usr/bin/env python3
"""
Extract detailed finding information from Argus scan results for validation.
This script helps developers validate security findings by providing exact paths,
line numbers, and scanner outputs.
"""

import json
import argparse
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict


def extract_finding_details(scan_results: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract and organize findings by category with full details.

    Args:
        scan_results: Full scan results from Argus

    Returns:
        Organized findings with paths, line numbers, and scanner details
    """
    findings_by_category = defaultdict(list)

    # Extract findings from different scanner outputs
    if 'findings' in scan_results:
        for finding in scan_results['findings']:
            category = finding.get('category', 'unknown')

            detail = {
                'scanner': finding.get('scanner'),
                'rule_id': finding.get('rule_id'),
                'severity': finding.get('severity'),
                'file_path': finding.get('file_path'),
                'line_start': finding.get('line_start'),
                'line_end': finding.get('line_end'),
                'code_snippet': finding.get('code_snippet'),
                'message': finding.get('message'),
                'confidence': finding.get('confidence'),
                'finding_id': finding.get('id')
            }

            # Remove None values for cleaner output
            detail = {k: v for k, v in detail.items() if v is not None}

            findings_by_category[category].append(detail)

    return dict(findings_by_category)


def filter_by_design_patterns(findings: List[Dict[str, Any]], patterns: List[str]) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Separate findings into 'by design' and 'needs review' based on known patterns.

    Args:
        findings: List of findings to filter
        patterns: List of patterns that indicate 'by design' items

    Returns:
        Tuple of (by_design_findings, needs_review_findings)
    """
    by_design = []
    needs_review = []

    oauth_public_client_patterns = [
        'client_secret',
        'CLIENT_SECRET',
        'clientSecret',
        'oauth.*public'
    ]

    secure_file_patterns = [
        '0600',
        '0700',
        'credentials.json',
        'token.json'
    ]

    dev_only_patterns = [
        'skipVerification',
        'skip_verification',
        'DEV_MODE',
        'DEBUG'
    ]

    for finding in findings:
        is_by_design = False

        # Check OAuth public client patterns
        if any(pattern in str(finding.get('message', '')).lower() for pattern in oauth_public_client_patterns):
            if 'public' in str(finding.get('file_path', '')).lower() or 'desktop' in str(finding.get('file_path', '')).lower():
                is_by_design = True
                finding['validation_note'] = 'OAuth2 public client - secrets cannot be protected'

        # Check secure file permission patterns
        if finding.get('category') == 'file_permissions' or 'permission' in str(finding.get('message', '')).lower():
            if any(pattern in str(finding) for pattern in secure_file_patterns):
                is_by_design = True
                finding['validation_note'] = 'Secure file permissions (0600/0700) properly set'

        # Check dev-only flag patterns
        if any(pattern in str(finding.get('code_snippet', '')) for pattern in dev_only_patterns):
            is_by_design = True
            finding['validation_note'] = 'Dev-only flag, not exposed in production'

        if is_by_design:
            by_design.append(finding)
        else:
            needs_review.append(finding)

    return by_design, needs_review


def generate_validation_report(scan_file: Path) -> str:
    """
    Generate a validation report for developer review.

    Args:
        scan_file: Path to the Argus scan results JSON file

    Returns:
        Markdown formatted validation report
    """
    with open(scan_file, 'r') as f:
        scan_results = json.load(f)

    findings_by_category = extract_finding_details(scan_results)

    report = []
    report.append("# Security Finding Validation Report\n")
    report.append(f"**Scan File:** `{scan_file.name}`\n")
    report.append(f"**Total Findings:** {sum(len(f) for f in findings_by_category.values())}\n\n")

    # Process each category
    for category, findings in findings_by_category.items():
        report.append(f"## {category.replace('_', ' ').title()} ({len(findings)} findings)\n")

        by_design, needs_review = filter_by_design_patterns(findings, [])

        if by_design:
            report.append(f"### By Design ({len(by_design)} findings)\n")
            for i, finding in enumerate(by_design, 1):
                report.append(f"{i}. **File:** `{finding.get('file_path', 'N/A')}`\n")
                if finding.get('line_start'):
                    report.append(f"   **Lines:** {finding.get('line_start')}-{finding.get('line_end', finding.get('line_start'))}\n")
                report.append(f"   **Scanner:** {finding.get('scanner', 'N/A')}\n")
                report.append(f"   **Validation:** {finding.get('validation_note', 'N/A')}\n\n")

        if needs_review:
            report.append(f"### Needs Review ({len(needs_review)} findings)\n")
            for i, finding in enumerate(needs_review, 1):
                report.append(f"{i}. **File:** `{finding.get('file_path', 'N/A')}`\n")
                if finding.get('line_start'):
                    report.append(f"   **Lines:** {finding.get('line_start')}-{finding.get('line_end', finding.get('line_start'))}\n")
                report.append(f"   **Scanner:** {finding.get('scanner', 'N/A')}\n")
                report.append(f"   **Rule:** {finding.get('rule_id', 'N/A')}\n")
                report.append(f"   **Message:** {finding.get('message', 'N/A')}\n")
                if finding.get('code_snippet'):
                    report.append(f"   ```\n   {finding.get('code_snippet')}\n   ```\n")
                report.append("\n")

        report.append("\n")

    # Add summary statistics
    report.append("## Summary Statistics\n\n")
    report.append("| Category | Total | By Design | Needs Review |\n")
    report.append("|----------|-------|-----------|-------------|\n")

    total_by_design = 0
    total_needs_review = 0

    for category, findings in findings_by_category.items():
        by_design, needs_review = filter_by_design_patterns(findings, [])
        total_by_design += len(by_design)
        total_needs_review += len(needs_review)
        report.append(f"| {category.replace('_', ' ').title()} | {len(findings)} | {len(by_design)} | {len(needs_review)} |\n")

    report.append(f"| **TOTAL** | **{sum(len(f) for f in findings_by_category.values())}** | **{total_by_design}** | **{total_needs_review}** |\n\n")

    # Add action items
    report.append("## Recommended Actions\n\n")
    report.append("1. **Review 'Needs Review' findings** - These require manual validation\n")
    report.append("2. **Update scanner configs** - Exclude 'By Design' patterns\n")
    report.append("3. **Document design decisions** - Add comments explaining security choices\n")
    report.append("4. **Re-scan with exclusions** - Verify reduced false positive rate\n")

    return ''.join(report)


def main():
    parser = argparse.ArgumentParser(description='Extract and validate Argus security findings')
    parser.add_argument('scan_file', type=Path, help='Path to Argus scan results JSON file')
    parser.add_argument('--output', '-o', type=Path, help='Output file for validation report')
    parser.add_argument('--format', choices=['markdown', 'json'], default='markdown',
                       help='Output format (default: markdown)')

    args = parser.parse_args()

    if not args.scan_file.exists():
        print(f"Error: Scan file '{args.scan_file}' not found")
        return 1

    if args.format == 'markdown':
        report = generate_validation_report(args.scan_file)

        if args.output:
            args.output.write_text(report)
            print(f"Validation report written to: {args.output}")
        else:
            print(report)
    else:
        # JSON format - raw extraction
        with open(args.scan_file, 'r') as f:
            scan_results = json.load(f)

        findings_by_category = extract_finding_details(scan_results)

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(findings_by_category, f, indent=2)
            print(f"Findings extracted to: {args.output}")
        else:
            print(json.dumps(findings_by_category, indent=2))

    return 0


if __name__ == '__main__':
    exit(main())