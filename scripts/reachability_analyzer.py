#!/usr/bin/env python3
"""
Reachability Analyzer for CVEs
Determines if vulnerable code is actually reachable in the application
Uses open source tools: Trivy (Apache 2.0) + language-specific analyzers
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ReachabilityResult:
    """Result of reachability analysis"""

    finding_id: str
    package: str
    cve: str
    is_reachable: bool
    confidence: str  # 'high', 'medium', 'low'
    evidence: list[str]
    call_chain: Optional[list[str]] = None


class ReachabilityAnalyzer:
    """Analyze if vulnerable code is reachable"""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.language = self._detect_language()

    def _detect_language(self) -> str:
        """Detect primary language of repository"""
        # Check for language-specific files
        if (self.repo_path / "package.json").exists():
            return "javascript"
        elif (self.repo_path / "requirements.txt").exists() or (self.repo_path / "pyproject.toml").exists():
            return "python"
        elif (self.repo_path / "go.mod").exists():
            return "go"
        elif (self.repo_path / "pom.xml").exists() or (self.repo_path / "build.gradle").exists():
            return "java"
        elif (self.repo_path / "Cargo.toml").exists():
            return "rust"
        else:
            return "unknown"

    def analyze_findings(self, findings: list[dict]) -> list[ReachabilityResult]:
        """
        Analyze reachability for CVE findings

        Args:
            findings: List of normalized findings (from normalizer)

        Returns:
            List[ReachabilityResult]: Reachability results
        """
        results = []

        # Filter for CVE findings only
        cve_findings = [f for f in findings if f.get("category") == "VULN"]

        print(f"🔍 Analyzing reachability for {len(cve_findings)} CVE findings...")

        for finding in cve_findings:
            result = self._analyze_finding(finding)
            results.append(result)

        # Print summary
        reachable_count = sum(1 for r in results if r.is_reachable)
        total = len(results)
        reachable_pct = (reachable_count / total * 100) if total > 0 else 0.0
        print("\n📊 Reachability Analysis:")
        print(f"   Total CVEs: {total}")
        print(f"   Reachable: {reachable_count} ({reachable_pct:.1f}%)")
        print(f"   Not Reachable: {total - reachable_count}")

        return results

    def _analyze_finding(self, finding: dict) -> ReachabilityResult:
        """Analyze single finding for reachability"""
        package = finding.get("title", "").split()[0]  # Extract package name
        cve = finding.get("rule_id", "")

        # Check if package is imported/used
        is_imported = self._check_imports(package)

        # Check if vulnerable functions are called
        vulnerable_funcs = self._get_vulnerable_functions(finding)
        func_calls = self._find_function_calls(vulnerable_funcs)

        # Determine reachability
        if func_calls:
            # High confidence: direct function calls found
            is_reachable = True
            confidence = "high"
            evidence = [
                f"Package '{package}' is imported",
                f"Vulnerable function calls found: {', '.join(func_calls[:3])}",
            ]
            call_chain = func_calls
        elif is_imported:
            # Medium confidence: package imported but no direct calls
            is_reachable = True
            confidence = "medium"
            evidence = [
                f"Package '{package}' is imported",
                "No direct vulnerable function calls detected (may be indirect)",
            ]
            call_chain = None
        else:
            # Low confidence: package not imported
            is_reachable = False
            confidence = "high"
            evidence = [
                f"Package '{package}' not imported in codebase",
                "Likely a transitive dependency with no direct usage",
            ]
            call_chain = None

        return ReachabilityResult(
            finding_id=finding.get("id"),
            package=package,
            cve=cve,
            is_reachable=is_reachable,
            confidence=confidence,
            evidence=evidence,
            call_chain=call_chain,
        )

    def _check_imports(self, package: str) -> bool:
        """Check if package is imported anywhere in codebase"""
        patterns = {
            "python": [rf"^import\s+{re.escape(package)}", rf"^from\s+{re.escape(package)}\s+import"],
            "javascript": [
                r'require\([\'"]' + re.escape(package) + r'[\'"]\)',
                r'from\s+[\'"]' + re.escape(package) + r'[\'"]',
                r'import\s+.*\s+from\s+[\'"]' + re.escape(package) + r'[\'"]',
            ],
            "java": [r"import\s+" + re.escape(package)],
            "go": [r'import\s+[\'"]' + re.escape(package) + r'[\'"]'],
        }

        search_patterns = patterns.get(self.language, [])

        for pattern in search_patterns:
            # Search in all source files
            for source_file in self._get_source_files():
                try:
                    with open(source_file) as f:
                        content = f.read()
                        if re.search(pattern, content, re.MULTILINE):
                            return True
                except Exception:
                    continue

        return False

    def _get_vulnerable_functions(self, finding: dict) -> list[str]:
        """Extract vulnerable function names from finding"""
        # Parse from CWE data or description
        description = finding.get("description", "").lower()

        # Common vulnerable functions by language
        vuln_funcs = {
            "python": ["eval", "exec", "pickle.loads", "yaml.load"],
            "javascript": ["eval", "Function", "innerHTML", "dangerouslySetInnerHTML"],
            "java": ["Runtime.exec", "ProcessBuilder", "deserialize"],
        }

        funcs = []
        lang_funcs = vuln_funcs.get(self.language, [])

        for func in lang_funcs:
            if func.lower() in description:
                funcs.append(func)

        return funcs

    def _find_function_calls(self, functions: list[str]) -> list[str]:
        """Find calls to specific functions in codebase"""
        calls_found = []

        for func in functions:
            pattern = rf"\b{re.escape(func)}\s*\("

            for source_file in self._get_source_files():
                try:
                    with open(source_file) as f:
                        for line_num, line in enumerate(f, 1):
                            if re.search(pattern, line):
                                location = f"{source_file.name}:{line_num}"
                                calls_found.append(location)
                except Exception:
                    continue

        return calls_found

    def _get_source_files(self) -> list[Path]:
        """Get all source files for the detected language"""
        extensions = {
            "python": [".py"],
            "javascript": [".js", ".jsx", ".ts", ".tsx"],
            "java": [".java"],
            "go": [".go"],
            "rust": [".rs"],
        }

        exts = extensions.get(self.language, [])

        source_files = []
        for ext in exts:
            source_files.extend(self.repo_path.rglob(f"*{ext}"))

        # Limit to first 500 files for performance
        return source_files[:500]

    def enrich_findings(self, findings: list[dict]) -> list[dict]:
        """
        Enrich findings with reachability data

        Args:
            findings: List of normalized findings

        Returns:
            List[Dict]: Findings with reachability added
        """
        # Analyze reachability
        reachability_results = self.analyze_findings(findings)

        # Create lookup map
        reachability_map = {r.finding_id: r for r in reachability_results}

        # Enrich findings
        enriched = []
        for finding in findings:
            finding_id = finding.get("id")

            if finding_id in reachability_map:
                result = reachability_map[finding_id]
                finding["reachable"] = result.is_reachable
                finding["reachability_confidence"] = result.confidence
                finding["reachability_evidence"] = result.evidence

                if result.call_chain:
                    finding["call_chain"] = result.call_chain

            enriched.append(finding)

        return enriched


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Analyze CVE reachability (open source)")
    parser.add_argument("findings", help="Path to findings JSON file")
    parser.add_argument("--repo", default=".", help="Repository path (default: current directory)")
    parser.add_argument("-o", "--output", help="Output file for enriched findings")

    args = parser.parse_args()

    # Load findings
    with open(args.findings) as f:
        findings = json.load(f)

    # Analyze reachability
    analyzer = ReachabilityAnalyzer(args.repo)
    enriched = analyzer.enrich_findings(findings)

    # Output results
    if args.output:
        with open(args.output, "w") as f:
            json.dump(enriched, f, indent=2)
        print(f"\n✅ Enriched findings written to {args.output}")
    else:
        print(json.dumps(enriched, indent=2))


if __name__ == "__main__":
    main()
