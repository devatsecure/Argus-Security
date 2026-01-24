#!/usr/bin/env python3
"""
SAST-DAST Correlation Engine for Argus

Uses AI to verify if SAST findings are exploitable via DAST results.
Correlates static analysis findings with dynamic testing results to confirm
real-world exploitability and reduce false positives.

Features:
- Multi-criteria matching (path, type, CWE)
- Fuzzy path/endpoint matching
- AI-powered verification using Claude/OpenAI/Ollama
- Detailed reasoning and confidence scores
- Integration with LLMManager for cost tracking
- Decision logging for observability

Example Usage:
    # Programmatic usage
    from sast_dast_correlator import SASTDASTCorrelator
    correlator = SASTDASTCorrelator()
    results = correlator.correlate(sast_findings, dast_findings)

    # CLI usage
    python sast_dast_correlator.py \\
        --sast-file semgrep-results.json \\
        --dast-file zap-results.json \\
        --output-file correlation-results.json
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass
from difflib import SequenceMatcher
from enum import Enum
from pathlib import Path
from typing import Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class CorrelationStatus(Enum):
    """Status of SAST-DAST correlation"""
    CONFIRMED = "confirmed"  # DAST verified SAST finding is exploitable
    PARTIAL = "partial"  # Similar but not exact match
    NOT_VERIFIED = "not_verified"  # Couldn't verify (might be FP)
    NO_DAST_COVERAGE = "no_dast_coverage"  # No DAST test for this endpoint


@dataclass
class CorrelationResult:
    """Result of correlating SAST and DAST findings"""
    sast_finding_id: str
    dast_finding_id: Optional[str]
    status: CorrelationStatus
    confidence: float  # 0.0-1.0
    exploitability: str  # trivial, moderate, complex, theoretical
    reasoning: str
    poc_exploit: Optional[str] = None
    match_score: float = 0.0  # Similarity score (0.0-1.0)
    sast_summary: Optional[dict] = None
    dast_summary: Optional[dict] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        result = asdict(self)
        result["status"] = self.status.value
        return result


class SASTDASTCorrelator:
    """Correlate SAST and DAST findings using AI"""

    # Vulnerability type mappings for better matching
    VULN_TYPE_ALIASES = {
        "sql-injection": ["sqli", "sql_injection", "cwe-89"],
        "xss": ["cross-site-scripting", "cross_site_scripting", "cwe-79"],
        "command-injection": ["command_injection", "os-command-injection", "cwe-78"],
        "path-traversal": ["directory-traversal", "path_traversal", "cwe-22"],
        "ssrf": ["server-side-request-forgery", "cwe-918"],
        "xxe": ["xml-external-entity", "cwe-611"],
        "csrf": ["cross-site-request-forgery", "cwe-352"],
        "open-redirect": ["url-redirection", "unvalidated-redirect", "cwe-601"],
    }

    # CWE to vulnerability type mapping
    CWE_TO_VULN_TYPE = {
        "CWE-89": "sql-injection",
        "CWE-79": "xss",
        "CWE-78": "command-injection",
        "CWE-77": "command-injection",
        "CWE-22": "path-traversal",
        "CWE-918": "ssrf",
        "CWE-611": "xxe",
        "CWE-352": "csrf",
        "CWE-601": "open-redirect",
    }

    def __init__(self, llm_manager=None, config: dict = None):
        """Initialize SAST-DAST correlator

        Args:
            llm_manager: Pre-initialized LLMManager (optional)
            config: Configuration dictionary (optional)
        """
        self.config = config or {}
        self.llm = llm_manager

        # Initialize LLM manager if not provided
        if self.llm is None:
            try:
                # Import LLMManager from orchestrator
                import sys
                from pathlib import Path

                scripts_dir = Path(__file__).parent
                if str(scripts_dir) not in sys.path:
                    sys.path.insert(0, str(scripts_dir))

                from orchestrator.llm_manager import LLMManager

                # Get config from environment if not provided
                if not self.config:
                    import os
                    self.config = {
                        "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY"),
                        "openai_api_key": os.getenv("OPENAI_API_KEY"),
                        "ollama_endpoint": os.getenv("OLLAMA_ENDPOINT", "http://localhost:11434"),
                        "ai_provider": os.getenv("AI_PROVIDER", "auto"),
                    }

                self.llm = LLMManager(self.config)

                # Initialize the LLM manager
                if not self.llm.initialize():
                    logger.warning("LLM Manager initialization failed - AI verification will be skipped")
                    self.llm = None
                else:
                    logger.info(f"LLM Manager initialized with provider: {self.llm.provider}")

            except Exception as e:
                logger.warning(f"Could not initialize LLM Manager: {e}")
                logger.info("Correlation will use heuristics only, no AI verification")
                self.llm = None

    def correlate(
        self,
        sast_findings: list[dict],
        dast_findings: list[dict],
        use_ai: bool = True
    ) -> list[CorrelationResult]:
        """Correlate SAST and DAST findings

        Args:
            sast_findings: List of SAST findings (normalized format)
            dast_findings: List of DAST findings (normalized format)
            use_ai: Whether to use AI for verification (default: True)

        Returns:
            List of CorrelationResult objects
        """
        logger.info(f"Starting correlation: {len(sast_findings)} SAST findings, {len(dast_findings)} DAST findings")

        results = []

        # For each SAST finding, try to find matching DAST result
        for idx, sast_finding in enumerate(sast_findings, 1):
            logger.debug(f"Correlating SAST finding {idx}/{len(sast_findings)}: {sast_finding.get('id', 'unknown')}")

            result = self._correlate_single(sast_finding, dast_findings, use_ai=use_ai)
            results.append(result)

        # Print summary statistics
        self._print_summary(results)

        return results

    def _correlate_single(
        self,
        sast_finding: dict,
        dast_findings: list[dict],
        use_ai: bool = True
    ) -> CorrelationResult:
        """Correlate a single SAST finding with DAST results

        Args:
            sast_finding: SAST finding dictionary
            dast_findings: List of DAST findings
            use_ai: Whether to use AI for verification

        Returns:
            CorrelationResult object
        """
        # 1. Find potential DAST matches using heuristics
        candidates = self._find_dast_candidates(sast_finding, dast_findings)

        if not candidates:
            return CorrelationResult(
                sast_finding_id=sast_finding.get("id", "unknown"),
                dast_finding_id=None,
                status=CorrelationStatus.NO_DAST_COVERAGE,
                confidence=0.95,  # High confidence in no coverage
                exploitability="unknown",
                reasoning="No DAST test covered this endpoint or vulnerability type",
                match_score=0.0,
                sast_summary=self._summarize_finding(sast_finding)
            )

        # 2. Get best candidate
        best_candidate = candidates[0]
        match_score = best_candidate.get("match_score", 0.0)
        dast_finding = best_candidate.get("finding")

        # 3. Use AI to verify correlation if available and requested
        if use_ai and self.llm is not None:
            return self._ai_verify_correlation(sast_finding, dast_finding, match_score)

        # 4. Fallback to heuristic-based correlation
        return self._heuristic_correlation(sast_finding, dast_finding, match_score)

    def _find_dast_candidates(
        self,
        sast_finding: dict,
        dast_findings: list[dict]
    ) -> list[dict]:
        """Find DAST findings that might match SAST finding

        Args:
            sast_finding: SAST finding dictionary
            dast_findings: List of DAST findings

        Returns:
            List of candidate dictionaries with match scores, sorted by score descending
        """
        candidates = []

        sast_path = sast_finding.get("path", "")
        sast_type = self._normalize_vuln_type(sast_finding.get("rule_id", ""))
        sast_cwe = sast_finding.get("cwe", "")

        for dast in dast_findings:
            score = self._calculate_match_score(sast_finding, dast)

            # Only include candidates above threshold
            if score > 0.3:  # 30% similarity threshold
                candidates.append({
                    "finding": dast,
                    "match_score": score
                })

        # Sort by score descending
        candidates.sort(reverse=True, key=lambda x: x["match_score"])

        logger.debug(f"Found {len(candidates)} DAST candidates for SAST finding")
        return candidates

    def _calculate_match_score(
        self,
        sast_finding: dict,
        dast_finding: dict
    ) -> float:
        """Calculate similarity score between SAST and DAST findings

        Args:
            sast_finding: SAST finding dictionary
            dast_finding: DAST finding dictionary

        Returns:
            Match score (0.0-1.0), higher is better
        """
        score = 0.0
        weights = {
            "path": 0.4,      # Path/URL matching is most important
            "vuln_type": 0.35, # Vulnerability type is critical
            "cwe": 0.25        # CWE provides additional confirmation
        }

        # 1. Path/URL matching (fuzzy)
        sast_path = sast_finding.get("path", "")
        dast_url = dast_finding.get("evidence", {}).get("url", dast_finding.get("path", ""))

        path_score = self._fuzzy_match_paths(sast_path, dast_url)
        score += path_score * weights["path"]

        # 2. Vulnerability type matching
        sast_type = self._normalize_vuln_type(sast_finding.get("rule_id", ""))
        dast_type = self._normalize_vuln_type(dast_finding.get("rule_id", ""))

        if sast_type and dast_type:
            if sast_type == dast_type:
                type_score = 1.0
            elif self._are_related_vuln_types(sast_type, dast_type):
                type_score = 0.7
            else:
                type_score = 0.0
        else:
            type_score = 0.5  # Unknown, give neutral score

        score += type_score * weights["vuln_type"]

        # 3. CWE matching
        sast_cwe = sast_finding.get("cwe", "")
        dast_cwe = dast_finding.get("cwe", "")

        if sast_cwe and dast_cwe:
            if sast_cwe == dast_cwe:
                cwe_score = 1.0
            else:
                cwe_score = 0.0
        else:
            cwe_score = 0.5  # Unknown, give neutral score

        score += cwe_score * weights["cwe"]

        return score

    def _fuzzy_match_paths(self, sast_path: str, dast_url: str) -> float:
        """Fuzzy match between file path and URL endpoint

        Args:
            sast_path: File path from SAST (e.g., "src/api/users.py")
            dast_url: URL from DAST (e.g., "http://localhost/api/users")

        Returns:
            Similarity score (0.0-1.0)
        """
        # Extract endpoint from URL (remove protocol, domain, query params)
        dast_endpoint = self._extract_endpoint_from_url(dast_url)

        # Extract potential endpoint from file path
        sast_endpoint = self._extract_endpoint_from_path(sast_path)

        # Use difflib for fuzzy matching
        similarity = SequenceMatcher(None, sast_endpoint.lower(), dast_endpoint.lower()).ratio()

        # Boost score if key components match
        sast_parts = set(sast_endpoint.split("/"))
        dast_parts = set(dast_endpoint.split("/"))
        common_parts = sast_parts & dast_parts

        if common_parts:
            boost = len(common_parts) / max(len(sast_parts), len(dast_parts))
            similarity = min(1.0, similarity + boost * 0.3)

        return similarity

    def _extract_endpoint_from_url(self, url: str) -> str:
        """Extract endpoint path from URL

        Args:
            url: Full URL or path

        Returns:
            Endpoint path
        """
        # Remove protocol and domain
        if "://" in url:
            url = url.split("://", 1)[1]
            if "/" in url:
                url = "/" + url.split("/", 1)[1]
            else:
                url = "/"

        # Remove query parameters and fragments
        url = url.split("?")[0].split("#")[0]

        return url

    def _extract_endpoint_from_path(self, file_path: str) -> str:
        """Extract potential API endpoint from file path

        Args:
            file_path: Source file path (e.g., "src/api/users.py")

        Returns:
            Potential endpoint (e.g., "/api/users")
        """
        # Remove file extension
        path = Path(file_path).with_suffix("").as_posix()

        # Common patterns for API routes
        # Look for directories like: api/, routes/, controllers/, views/, handlers/
        api_markers = ["api", "routes", "controllers", "views", "handlers", "endpoints"]

        parts = path.split("/")
        endpoint_parts = []
        capture = False

        for part in parts:
            if part.lower() in api_markers:
                capture = True
                endpoint_parts.append(part)
            elif capture:
                endpoint_parts.append(part)

        if endpoint_parts:
            return "/" + "/".join(endpoint_parts)

        # Fallback: use last 2-3 path components
        return "/" + "/".join(parts[-2:]) if len(parts) >= 2 else "/" + parts[-1]

    def _normalize_vuln_type(self, identifier: str) -> str:
        """Normalize vulnerability type identifier

        Args:
            identifier: Rule ID, CWE, or vulnerability name

        Returns:
            Normalized vulnerability type
        """
        if not identifier:
            return ""

        identifier_lower = identifier.lower()

        # Check if it's a CWE
        cwe_match = re.search(r'cwe-?\d+', identifier_lower)
        if cwe_match:
            cwe = cwe_match.group(0).upper().replace("CWE-", "CWE-")
            return self.CWE_TO_VULN_TYPE.get(cwe.replace("-", "-"), "")

        # Check against known types and aliases
        for vuln_type, aliases in self.VULN_TYPE_ALIASES.items():
            if any(alias in identifier_lower for alias in aliases + [vuln_type]):
                return vuln_type

        return identifier_lower

    def _are_related_vuln_types(self, type1: str, type2: str) -> bool:
        """Check if two vulnerability types are related

        Args:
            type1: First vulnerability type
            type2: Second vulnerability type

        Returns:
            True if related, False otherwise
        """
        # Check if they share aliases
        for vuln_type, aliases in self.VULN_TYPE_ALIASES.items():
            all_names = [vuln_type] + aliases
            if type1 in all_names and type2 in all_names:
                return True
        return False

    def _ai_verify_correlation(
        self,
        sast_finding: dict,
        dast_finding: dict,
        match_score: float
    ) -> CorrelationResult:
        """Use AI to verify if DAST confirms SAST finding

        Args:
            sast_finding: SAST finding dictionary
            dast_finding: DAST finding dictionary
            match_score: Heuristic match score

        Returns:
            CorrelationResult with AI verification
        """
        # Build prompt for AI
        prompt = self._build_correlation_prompt(sast_finding, dast_finding, match_score)

        try:
            # Call LLM API
            response_text, input_tokens, output_tokens = self.llm.call_llm_api(
                prompt=prompt,
                max_tokens=500,
                operation="SAST-DAST correlation"
            )

            # Parse JSON response
            data = json.loads(response_text)

            # Log AI decision
            if self.llm:
                self.llm.log_ai_decision(
                    finding_id=sast_finding.get("id", "unknown"),
                    finding_type="correlation",
                    scanner="sast-dast-correlator",
                    decision=data.get("status", "not_verified"),
                    reasoning=data.get("reasoning", ""),
                    confidence=data.get("confidence", 0.0),
                    noise_score=1.0 - match_score  # Inverse of match score
                )

            return CorrelationResult(
                sast_finding_id=sast_finding.get("id", "unknown"),
                dast_finding_id=dast_finding.get("id"),
                status=CorrelationStatus(data["status"]),
                confidence=data["confidence"],
                exploitability=data["exploitability"],
                reasoning=data["reasoning"],
                poc_exploit=dast_finding.get("evidence", {}).get("poc"),
                match_score=match_score,
                sast_summary=self._summarize_finding(sast_finding),
                dast_summary=self._summarize_finding(dast_finding)
            )

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}")
            logger.debug(f"Response text: {response_text[:500]}")
            return self._heuristic_correlation(sast_finding, dast_finding, match_score)

        except Exception as e:
            logger.error(f"AI verification failed: {type(e).__name__}: {e}")
            return self._heuristic_correlation(sast_finding, dast_finding, match_score)

    def _build_correlation_prompt(
        self,
        sast_finding: dict,
        dast_finding: dict,
        match_score: float
    ) -> str:
        """Build prompt for AI correlation verification

        Args:
            sast_finding: SAST finding dictionary
            dast_finding: DAST finding dictionary
            match_score: Heuristic match score

        Returns:
            Formatted prompt string
        """
        # Extract code snippet if available
        code_snippet = sast_finding.get("evidence", {}).get("snippet", "N/A")
        if isinstance(code_snippet, dict):
            code_snippet = code_snippet.get("text", "N/A")

        prompt = f"""You are a security analyst correlating static (SAST) and dynamic (DAST) analysis results.

**SAST Finding (Static Analysis):**
- ID: {sast_finding.get('id', 'unknown')}
- Type: {sast_finding.get('rule_name', 'unknown')}
- File: {sast_finding.get('path', 'unknown')}
- Line: {sast_finding.get('line', 'unknown')}
- Severity: {sast_finding.get('severity', 'unknown')}
- CWE: {sast_finding.get('cwe', 'N/A')}
- Description: {sast_finding.get('evidence', {}).get('message', 'N/A')}
- Code: {code_snippet}

**DAST Finding (Dynamic Test):**
- ID: {dast_finding.get('id', 'unknown')}
- URL: {dast_finding.get('evidence', {}).get('url', dast_finding.get('path', 'unknown'))}
- Method: {dast_finding.get('evidence', {}).get('method', 'unknown')}
- Vulnerability: {dast_finding.get('rule_name', 'unknown')}
- Severity: {dast_finding.get('severity', 'unknown')}
- CWE: {dast_finding.get('cwe', 'N/A')}
- Evidence: {dast_finding.get('evidence', {}).get('message', 'N/A')}
- Proof of Concept: {dast_finding.get('evidence', {}).get('poc', 'N/A')}

**Heuristic Match Score:** {match_score:.2f} (0.0-1.0)

**Question:** Does the DAST finding CONFIRM that the SAST finding is exploitable in a running application?

Consider:
1. Do they target the same endpoint/functionality?
2. Is the vulnerability type the same or related?
3. Does the DAST evidence show actual exploitation?
4. Could this be a false correlation despite matching criteria?

**Response Format (JSON only, no additional text):**
{{
  "status": "confirmed|partial|not_verified",
  "confidence": 0.0-1.0,
  "exploitability": "trivial|moderate|complex|theoretical",
  "reasoning": "Clear explanation of why findings do/don't correlate (2-3 sentences)"
}}
"""
        return prompt

    def _heuristic_correlation(
        self,
        sast_finding: dict,
        dast_finding: dict,
        match_score: float
    ) -> CorrelationResult:
        """Perform heuristic-based correlation without AI

        Args:
            sast_finding: SAST finding dictionary
            dast_finding: DAST finding dictionary
            match_score: Match score

        Returns:
            CorrelationResult based on heuristics
        """
        # Determine status based on match score
        if match_score >= 0.8:
            status = CorrelationStatus.CONFIRMED
            confidence = match_score
            exploitability = "moderate"
            reasoning = f"High confidence match (score: {match_score:.2f}) based on path, type, and CWE alignment"
        elif match_score >= 0.5:
            status = CorrelationStatus.PARTIAL
            confidence = match_score * 0.8
            exploitability = "complex"
            reasoning = f"Partial match (score: {match_score:.2f}) - similar vulnerability type but different context"
        else:
            status = CorrelationStatus.NOT_VERIFIED
            confidence = 0.3
            exploitability = "theoretical"
            reasoning = f"Low confidence match (score: {match_score:.2f}) - correlation uncertain without AI verification"

        return CorrelationResult(
            sast_finding_id=sast_finding.get("id", "unknown"),
            dast_finding_id=dast_finding.get("id"),
            status=status,
            confidence=confidence,
            exploitability=exploitability,
            reasoning=reasoning,
            poc_exploit=dast_finding.get("evidence", {}).get("poc"),
            match_score=match_score,
            sast_summary=self._summarize_finding(sast_finding),
            dast_summary=self._summarize_finding(dast_finding)
        )

    def _summarize_finding(self, finding: dict) -> dict:
        """Create summary of finding for result export

        Args:
            finding: Finding dictionary

        Returns:
            Summary dictionary
        """
        return {
            "id": finding.get("id", "unknown"),
            "type": finding.get("rule_name", "unknown"),
            "path": finding.get("path", "unknown"),
            "severity": finding.get("severity", "unknown"),
            "cwe": finding.get("cwe", "N/A")
        }

    def _print_summary(self, results: list[CorrelationResult]) -> None:
        """Print summary statistics of correlation results

        Args:
            results: List of CorrelationResult objects
        """
        total = len(results)
        if total == 0:
            logger.info("No findings to correlate")
            return

        # Count by status
        status_counts = {}
        for result in results:
            status = result.status.value
            status_counts[status] = status_counts.get(status, 0) + 1

        # Calculate percentages
        confirmed_pct = (status_counts.get("confirmed", 0) / total) * 100
        partial_pct = (status_counts.get("partial", 0) / total) * 100
        not_verified_pct = (status_counts.get("not_verified", 0) / total) * 100
        no_coverage_pct = (status_counts.get("no_dast_coverage", 0) / total) * 100

        # Print summary
        logger.info("=" * 60)
        logger.info("SAST-DAST Correlation Summary")
        logger.info("=" * 60)
        logger.info(f"Total SAST findings processed: {total}")
        logger.info(f"  ✓ CONFIRMED:        {status_counts.get('confirmed', 0):3d} ({confirmed_pct:5.1f}%)")
        logger.info(f"  ≈ PARTIAL:          {status_counts.get('partial', 0):3d} ({partial_pct:5.1f}%)")
        logger.info(f"  ? NOT_VERIFIED:     {status_counts.get('not_verified', 0):3d} ({not_verified_pct:5.1f}%)")
        logger.info(f"  ∅ NO_DAST_COVERAGE: {status_counts.get('no_dast_coverage', 0):3d} ({no_coverage_pct:5.1f}%)")
        logger.info("=" * 60)

        # High confidence confirmations
        high_confidence = [r for r in results if r.status == CorrelationStatus.CONFIRMED and r.confidence >= 0.8]
        if high_confidence:
            logger.info(f"\n🔥 {len(high_confidence)} high-confidence exploitable findings confirmed by DAST")

    def export_results(
        self,
        results: list[CorrelationResult],
        output_file: str,
        format: str = "json"
    ) -> None:
        """Export correlation results to file

        Args:
            results: List of CorrelationResult objects
            output_file: Output file path
            format: Output format (json or markdown)
        """
        if format == "json":
            self._export_json(results, output_file)
        elif format == "markdown":
            self._export_markdown(results, output_file)
        else:
            logger.error(f"Unsupported format: {format}")
            raise ValueError(f"Unsupported format: {format}")

    def _export_json(self, results: list[CorrelationResult], output_file: str) -> None:
        """Export results as JSON

        Args:
            results: List of CorrelationResult objects
            output_file: Output file path
        """
        output_data = {
            "metadata": {
                "total_findings": len(results),
                "confirmed": len([r for r in results if r.status == CorrelationStatus.CONFIRMED]),
                "partial": len([r for r in results if r.status == CorrelationStatus.PARTIAL]),
                "not_verified": len([r for r in results if r.status == CorrelationStatus.NOT_VERIFIED]),
                "no_coverage": len([r for r in results if r.status == CorrelationStatus.NO_DAST_COVERAGE]),
            },
            "correlations": [r.to_dict() for r in results]
        }

        with open(output_file, "w") as f:
            json.dump(output_data, f, indent=2)

        logger.info(f"Results exported to {output_file}")

    def _export_markdown(self, results: list[CorrelationResult], output_file: str) -> None:
        """Export results as Markdown

        Args:
            results: List of CorrelationResult objects
            output_file: Output file path
        """
        with open(output_file, "w") as f:
            f.write("# SAST-DAST Correlation Report\n\n")

            # Summary
            f.write("## Summary\n\n")
            f.write(f"- **Total findings:** {len(results)}\n")
            f.write(f"- **Confirmed:** {len([r for r in results if r.status == CorrelationStatus.CONFIRMED])}\n")
            f.write(f"- **Partial:** {len([r for r in results if r.status == CorrelationStatus.PARTIAL])}\n")
            f.write(f"- **Not verified:** {len([r for r in results if r.status == CorrelationStatus.NOT_VERIFIED])}\n")
            f.write(f"- **No coverage:** {len([r for r in results if r.status == CorrelationStatus.NO_DAST_COVERAGE])}\n\n")

            # Confirmed findings
            confirmed = [r for r in results if r.status == CorrelationStatus.CONFIRMED]
            if confirmed:
                f.write("## Confirmed Exploitable Findings\n\n")
                for result in confirmed:
                    f.write(f"### {result.sast_finding_id}\n\n")
                    f.write(f"- **Confidence:** {result.confidence:.2f}\n")
                    f.write(f"- **Exploitability:** {result.exploitability}\n")
                    f.write(f"- **Reasoning:** {result.reasoning}\n\n")

        logger.info(f"Markdown report exported to {output_file}")


def main():
    """CLI entry point for SAST-DAST correlation"""
    parser = argparse.ArgumentParser(
        description="SAST-DAST Correlation Engine - Verify SAST findings with DAST results using AI"
    )
    parser.add_argument(
        "--sast-file",
        required=True,
        help="Path to SAST findings JSON file (normalized format)"
    )
    parser.add_argument(
        "--dast-file",
        required=True,
        help="Path to DAST findings JSON file (normalized format)"
    )
    parser.add_argument(
        "--output-file",
        required=True,
        help="Path to output correlation results JSON file"
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="json",
        help="Output format (default: json)"
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI verification, use heuristics only"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )

    args = parser.parse_args()

    # Configure logging
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load SAST findings
    try:
        with open(args.sast_file) as f:
            sast_data = json.load(f)
            if isinstance(sast_data, dict):
                sast_findings = sast_data.get("findings", [])
            else:
                sast_findings = sast_data
        logger.info(f"Loaded {len(sast_findings)} SAST findings from {args.sast_file}")
    except Exception as e:
        logger.error(f"Failed to load SAST findings: {e}")
        sys.exit(1)

    # Load DAST findings
    try:
        with open(args.dast_file) as f:
            dast_data = json.load(f)
            if isinstance(dast_data, dict):
                dast_findings = dast_data.get("findings", [])
            else:
                dast_findings = dast_data
        logger.info(f"Loaded {len(dast_findings)} DAST findings from {args.dast_file}")
    except Exception as e:
        logger.error(f"Failed to load DAST findings: {e}")
        sys.exit(1)

    # Initialize correlator
    correlator = SASTDASTCorrelator()

    # Run correlation
    try:
        results = correlator.correlate(
            sast_findings=sast_findings,
            dast_findings=dast_findings,
            use_ai=not args.no_ai
        )

        # Export results
        correlator.export_results(results, args.output_file, format=args.format)

        logger.info("Correlation complete!")
        sys.exit(0)

    except Exception as e:
        logger.error(f"Correlation failed: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
