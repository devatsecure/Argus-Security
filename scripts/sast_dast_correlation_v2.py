#!/usr/bin/env python3
"""
Enhanced SAST-DAST Correlation Engine for Argus
Matches static findings with dynamic confirmations to validate exploitability
"""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)


@dataclass
class CorrelationRule:
    """Rule for correlating SAST and DAST findings"""
    
    vuln_type: str
    sast_patterns: list[str]  # Regex patterns for SAST rule IDs
    dast_patterns: list[str]  # Regex patterns for DAST findings
    confidence_boost: float  # Confidence increase when both find it
    severity_upgrade: Optional[str] = None  # Upgrade to this severity if correlated


# Correlation rules for common vulnerability types
CORRELATION_RULES = [
    CorrelationRule(
        vuln_type="SQL Injection",
        sast_patterns=[
            r".*sql.*injection.*",
            r".*sqli.*",
            r"python\.django\.security\.audit\.avoid-raw-sql",
            r"python\.lang\.security\.audit\.sqli",
        ],
        dast_patterns=[
            r".*sql.*injection.*",
            r".*sqli.*",
            r".*40018.*",  # ZAP SQLi plugin
        ],
        confidence_boost=0.9,
        severity_upgrade="critical",
    ),
    CorrelationRule(
        vuln_type="Cross-Site Scripting (XSS)",
        sast_patterns=[
            r".*xss.*",
            r".*cross.*site.*scripting.*",
            r"javascript\.lang\.security\.audit\.xss",
        ],
        dast_patterns=[
            r".*xss.*",
            r".*cross.*site.*scripting.*",
            r".*40012.*",  # ZAP XSS plugin
        ],
        confidence_boost=0.85,
        severity_upgrade="high",
    ),
    CorrelationRule(
        vuln_type="Server-Side Request Forgery (SSRF)",
        sast_patterns=[
            r".*ssrf.*",
            r".*server.*side.*request.*forgery.*",
            r"python\.lang\.security\.audit\.ssrf",
        ],
        dast_patterns=[
            r".*ssrf.*",
            r".*server.*side.*request.*forgery.*",
        ],
        confidence_boost=0.88,
        severity_upgrade="high",
    ),
    CorrelationRule(
        vuln_type="XML External Entity (XXE)",
        sast_patterns=[
            r".*xxe.*",
            r".*xml.*external.*entity.*",
            r".*xml.*injection.*",
        ],
        dast_patterns=[
            r".*xxe.*",
            r".*xml.*external.*entity.*",
        ],
        confidence_boost=0.87,
        severity_upgrade="high",
    ),
    CorrelationRule(
        vuln_type="Remote Code Execution (RCE)",
        sast_patterns=[
            r".*remote.*code.*execution.*",
            r".*command.*injection.*",
            r".*code.*injection.*",
            r".*dangerous.*function.*",
        ],
        dast_patterns=[
            r".*remote.*code.*execution.*",
            r".*rce.*",
            r".*command.*injection.*",
        ],
        confidence_boost=0.95,
        severity_upgrade="critical",
    ),
    CorrelationRule(
        vuln_type="Path Traversal / LFI",
        sast_patterns=[
            r".*path.*traversal.*",
            r".*directory.*traversal.*",
            r".*lfi.*",
            r".*local.*file.*inclusion.*",
        ],
        dast_patterns=[
            r".*path.*traversal.*",
            r".*directory.*traversal.*",
            r".*lfi.*",
        ],
        confidence_boost=0.86,
        severity_upgrade="high",
    ),
    CorrelationRule(
        vuln_type="Authentication Bypass",
        sast_patterns=[
            r".*auth.*bypass.*",
            r".*authentication.*missing.*",
            r".*insecure.*auth.*",
        ],
        dast_patterns=[
            r".*auth.*bypass.*",
            r".*authentication.*",
        ],
        confidence_boost=0.80,
        severity_upgrade="critical",
    ),
    CorrelationRule(
        vuln_type="CSRF",
        sast_patterns=[
            r".*csrf.*",
            r".*cross.*site.*request.*forgery.*",
        ],
        dast_patterns=[
            r".*csrf.*",
            r".*cross.*site.*request.*forgery.*",
        ],
        confidence_boost=0.82,
        severity_upgrade="medium",
    ),
]


@dataclass
class CorrelatedFinding:
    """A finding with both SAST and DAST evidence"""
    
    id: str
    vuln_type: str
    severity: str
    confidence: float
    sast_finding: dict
    dast_finding: dict
    correlation_score: float
    exploitable: bool
    evidence: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "sast_finding": self.sast_finding,
            "dast_finding": self.dast_finding,
            "correlation_score": self.correlation_score,
            "exploitable": self.exploitable,
            "evidence": self.evidence,
        }


class SASTDASTCorrelator:
    """
    Correlates SAST and DAST findings to confirm exploitability
    """
    
    def __init__(
        self,
        correlation_rules: Optional[list[CorrelationRule]] = None,
        confidence_threshold: float = 0.7,
    ):
        """
        Initialize correlator
        
        Args:
            correlation_rules: Custom correlation rules
            confidence_threshold: Minimum confidence for correlation
        """
        self.rules = correlation_rules or CORRELATION_RULES
        self.confidence_threshold = confidence_threshold
    
    def correlate(
        self,
        sast_findings: list[dict],
        dast_findings: list[dict],
    ) -> dict[str, Any]:
        """
        Correlate SAST and DAST findings
        
        Args:
            sast_findings: SAST findings from Semgrep, Trivy, etc.
            dast_findings: DAST findings from Nuclei, ZAP
            
        Returns:
            Correlation results with matched and unmatched findings
        """
        logger.info(f"🔗 Correlating {len(sast_findings)} SAST + {len(dast_findings)} DAST findings...")
        
        correlated = []
        sast_matched = set()
        dast_matched = set()
        
        # Try to correlate each SAST finding with DAST findings
        for sast_idx, sast_finding in enumerate(sast_findings):
            for dast_idx, dast_finding in enumerate(dast_findings):
                # Try each correlation rule
                for rule in self.rules:
                    match = self._check_correlation(sast_finding, dast_finding, rule)
                    
                    if match and match.correlation_score >= self.confidence_threshold:
                        correlated.append(match)
                        sast_matched.add(sast_idx)
                        dast_matched.add(dast_idx)
                        logger.debug(f"   ✅ Correlated: {match.vuln_type} (score: {match.correlation_score:.2f})")
                        break  # Found a match, move to next SAST finding
        
        # Unmatched findings
        sast_only = [f for idx, f in enumerate(sast_findings) if idx not in sast_matched]
        dast_only = [f for idx, f in enumerate(dast_findings) if idx not in dast_matched]
        
        result = {
            "correlated_findings": [f.to_dict() for f in correlated],
            "sast_only_findings": sast_only,
            "dast_only_findings": dast_only,
            "stats": {
                "total_sast": len(sast_findings),
                "total_dast": len(dast_findings),
                "correlated": len(correlated),
                "sast_only": len(sast_only),
                "dast_only": len(dast_only),
                "correlation_rate": len(correlated) / max(len(sast_findings), 1),
            },
        }
        
        logger.info(f"   ✅ Correlated: {len(correlated)} findings")
        logger.info(f"   📊 SAST only: {len(sast_only)}, DAST only: {len(dast_only)}")
        logger.info(f"   📈 Correlation rate: {result['stats']['correlation_rate']:.1%}")
        
        return result
    
    def _check_correlation(
        self,
        sast_finding: dict,
        dast_finding: dict,
        rule: CorrelationRule,
    ) -> Optional[CorrelatedFinding]:
        """
        Check if SAST and DAST findings correlate based on a rule
        
        Args:
            sast_finding: SAST finding
            dast_finding: DAST finding
            rule: Correlation rule
            
        Returns:
            CorrelatedFinding if match, None otherwise
        """
        # Check if SAST finding matches rule
        sast_match = self._matches_patterns(sast_finding, rule.sast_patterns)
        if not sast_match:
            return None
        
        # Check if DAST finding matches rule
        dast_match = self._matches_patterns(dast_finding, rule.dast_patterns)
        if not dast_match:
            return None
        
        # Calculate URL similarity
        sast_url = self._extract_url_from_sast(sast_finding)
        dast_url = self._extract_url_from_dast(dast_finding)
        url_similarity = self._calculate_similarity(sast_url, dast_url) if sast_url and dast_url else 0.5
        
        # Calculate overall correlation score
        correlation_score = (sast_match + dast_match + url_similarity) / 3
        
        # If low correlation, skip
        if correlation_score < self.confidence_threshold:
            return None
        
        # Determine severity (use upgraded severity if correlated)
        severity = rule.severity_upgrade or sast_finding.get("severity", "medium")
        
        # Calculate confidence (boost if correlated)
        base_confidence = max(
            sast_finding.get("confidence", 0.7),
            self._map_dast_confidence(dast_finding),
        )
        confidence = min(base_confidence + rule.confidence_boost, 1.0)
        
        # Build correlated finding
        return CorrelatedFinding(
            id=f"correlated-{sast_finding.get('id', 'unknown')}-{dast_finding.get('id', 'unknown')}",
            vuln_type=rule.vuln_type,
            severity=severity,
            confidence=confidence,
            sast_finding=sast_finding,
            dast_finding=dast_finding,
            correlation_score=correlation_score,
            exploitable=True,  # If DAST confirmed it, it's exploitable
            evidence={
                "sast_file": sast_finding.get("path", sast_finding.get("file", "")),
                "sast_line": sast_finding.get("line", 0),
                "dast_url": dast_url,
                "dast_method": dast_finding.get("method", ""),
                "poc": dast_finding.get("curl_command", ""),
            },
        )
    
    def _matches_patterns(self, finding: dict, patterns: list[str]) -> float:
        """
        Check if finding matches any pattern
        
        Returns:
            Match strength (0.0-1.0)
        """
        # Extract searchable text from finding
        text = " ".join([
            str(finding.get("rule_id", "")),
            str(finding.get("name", "")),
            str(finding.get("alert", "")),
            str(finding.get("id", "")),
            str(finding.get("category", "")),
        ]).lower()
        
        # Check each pattern
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return 1.0  # Strong match
        
        return 0.0  # No match
    
    def _extract_url_from_sast(self, finding: dict) -> Optional[str]:
        """Extract URL/endpoint from SAST finding"""
        # Look for API endpoints in file path or code
        path = finding.get("path", finding.get("file", ""))
        if "api/" in path or "routes/" in path or "endpoints/" in path:
            # Try to extract endpoint from path
            parts = path.split("/")
            for part in reversed(parts):
                if part.startswith("@app.") or part.startswith("@router."):
                    return part
        
        return path
    
    def _extract_url_from_dast(self, finding: dict) -> Optional[str]:
        """Extract URL from DAST finding"""
        return finding.get("url", finding.get("matched_at", ""))
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate string similarity (0.0-1.0)"""
        return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()
    
    def _map_dast_confidence(self, dast_finding: dict) -> float:
        """Map DAST confidence to 0-1 scale"""
        confidence = dast_finding.get("confidence", "medium")
        
        if isinstance(confidence, str):
            confidence_map = {
                "high": 0.9,
                "medium": 0.7,
                "low": 0.5,
            }
            return confidence_map.get(confidence.lower(), 0.7)
        
        return float(confidence)


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="SAST-DAST Correlation Engine")
    parser.add_argument("--sast-file", required=True, help="SAST findings JSON file")
    parser.add_argument("--dast-file", required=True, help="DAST findings JSON file")
    parser.add_argument("--output", "-o", help="Output file")
    parser.add_argument("--confidence-threshold", type=float, default=0.7)
    parser.add_argument("--verbose", "-v", action="store_true")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level)
    
    # Load findings
    with open(args.sast_file) as f:
        sast_data = json.load(f)
        sast_findings = sast_data.get("findings", sast_data) if isinstance(sast_data, dict) else sast_data
    
    with open(args.dast_file) as f:
        dast_data = json.load(f)
        # Handle both direct findings and nested findings
        if isinstance(dast_data, dict):
            dast_findings = dast_data.get("findings", dast_data.get("aggregated_findings", []))
        else:
            dast_findings = dast_data
    
    # Create correlator
    correlator = SASTDASTCorrelator(confidence_threshold=args.confidence_threshold)
    
    # Correlate
    result = correlator.correlate(sast_findings, dast_findings)
    
    # Save results
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)
        
        print(f"\n✅ Correlation results saved to: {output_path}")
    else:
        print(json.dumps(result, indent=2))
    
    # Print summary
    print(f"\n📊 Correlation Summary:")
    print(f"   Total SAST findings: {result['stats']['total_sast']}")
    print(f"   Total DAST findings: {result['stats']['total_dast']}")
    print(f"   Correlated: {result['stats']['correlated']}")
    print(f"   Correlation rate: {result['stats']['correlation_rate']:.1%}")
    
    return 0


if __name__ == "__main__":
    exit(main())
