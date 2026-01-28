#!/usr/bin/env python3
"""
AISLE Engine - AI Security Learning Engine for Argus

Inspired by AISLE (https://aisle.com), this module provides:
- Autonomous vulnerability discovery via LLM reasoning
- Semantic code understanding (Code Twins)
- Cross-function taint analysis
- Zero-day hypothesis generation
- Automated patch generation and verification

This is the main orchestrator that combines:
- semantic_code_twin.py: Deep code understanding
- proactive_ai_scanner.py: VulnHuntr-style autonomous scanning
- taint_analyzer.py: Inter-procedural data flow analysis
- zero_day_hypothesizer.py: Novel vulnerability hypothesis

Research References:
- IRIS: LLM-Assisted Static Analysis (arXiv 2405.17238)
- VulnHuntr: Zero-shot vulnerability discovery
- GPTScan: GPT + program analysis (ICSE'24)
- Pysa: Facebook's taint analysis framework
"""

import hashlib
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class AISLEPhase(Enum):
    """AISLE analysis phases"""
    SEMANTIC_ANALYSIS = "semantic_analysis"
    PROACTIVE_SCAN = "proactive_scan"
    TAINT_ANALYSIS = "taint_analysis"
    ZERO_DAY_HYPOTHESIS = "zero_day_hypothesis"
    PATCH_GENERATION = "patch_generation"
    VERIFICATION = "verification"


class FindingSeverity(Enum):
    """Severity levels for AISLE findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AISLEFinding:
    """
    Unified finding format for AISLE-discovered vulnerabilities
    """
    id: str
    source: str  # Which AISLE module found this
    title: str
    description: str
    severity: FindingSeverity
    confidence: float  # 0.0-1.0

    # Location information
    file_path: str
    line_number: int
    code_snippet: str

    # AISLE-specific metadata
    reasoning_chain: List[str]  # How the AI reached this conclusion
    attack_scenario: Optional[str] = None
    cwe_id: Optional[str] = None

    # Remediation
    suggested_fix: Optional[str] = None
    fix_confidence: float = 0.0

    # Verification status
    verified: bool = False
    verification_result: Optional[str] = None

    # Metadata
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "source": self.source,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "location": {
                "file": self.file_path,
                "line": self.line_number,
                "snippet": self.code_snippet
            },
            "reasoning_chain": self.reasoning_chain,
            "attack_scenario": self.attack_scenario,
            "cwe_id": self.cwe_id,
            "remediation": {
                "suggested_fix": self.suggested_fix,
                "fix_confidence": self.fix_confidence
            },
            "verification": {
                "verified": self.verified,
                "result": self.verification_result
            },
            "discovered_at": self.discovered_at
        }

    def to_unified_finding(self, repo: str, commit_sha: str, branch: str) -> Dict[str, Any]:
        """Convert to Argus unified Finding format"""
        return {
            "id": self.id,
            "origin": f"aisle-{self.source}",
            "repo": repo,
            "commit_sha": commit_sha,
            "branch": branch,
            "path": self.file_path,
            "line_number": self.line_number,
            "asset_type": "code",
            "rule_id": f"aisle-{self.source}-{self.cwe_id or 'unknown'}",
            "rule_name": self.title,
            "category": "AISLE",
            "severity": self.severity.value,
            "cwe": self.cwe_id,
            "evidence": {
                "description": self.description,
                "code_snippet": self.code_snippet,
                "reasoning_chain": self.reasoning_chain,
                "attack_scenario": self.attack_scenario,
                "aisle_source": self.source,
                "ai_analyzed": True
            },
            "confidence": self.confidence,
            "llm_enriched": True,
            "status": "open",
            "fix_suggestion": self.suggested_fix,
            "verified": self.verified,
            "verification_result": self.verification_result
        }


@dataclass
class AISLEAnalysisResult:
    """Result of a complete AISLE analysis"""
    findings: List[AISLEFinding]

    # Statistics
    files_analyzed: int
    functions_analyzed: int
    total_time_seconds: float

    # Phase results
    semantic_twins_created: int = 0
    proactive_findings: int = 0
    taint_flows_detected: int = 0
    zero_day_hypotheses: int = 0
    patches_generated: int = 0
    patches_verified: int = 0

    # Cost tracking
    llm_tokens_used: int = 0
    estimated_cost_usd: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "summary": {
                "total_findings": len(self.findings),
                "files_analyzed": self.files_analyzed,
                "functions_analyzed": self.functions_analyzed,
                "total_time_seconds": round(self.total_time_seconds, 2)
            },
            "phase_results": {
                "semantic_twins_created": self.semantic_twins_created,
                "proactive_findings": self.proactive_findings,
                "taint_flows_detected": self.taint_flows_detected,
                "zero_day_hypotheses": self.zero_day_hypotheses,
                "patches_generated": self.patches_generated,
                "patches_verified": self.patches_verified
            },
            "cost": {
                "llm_tokens_used": self.llm_tokens_used,
                "estimated_cost_usd": round(self.estimated_cost_usd, 4)
            },
            "findings": [f.to_dict() for f in self.findings]
        }


class AISLEEngine:
    """
    AISLE Engine - Main orchestrator for AI-powered security analysis

    Combines multiple AI-driven analysis techniques:
    1. Semantic Code Twins - Deep understanding of code intent vs behavior
    2. Proactive AI Scanner - Autonomous vulnerability reasoning
    3. Taint Analysis - Cross-function data flow tracking
    4. Zero-Day Hypothesizer - Novel vulnerability hypothesis generation

    Usage:
        engine = AISLEEngine(llm_provider=claude_provider)
        result = engine.analyze(
            files=["/path/to/file1.py", "/path/to/file2.py"],
            project_type="backend-api"
        )
    """

    # Default confidence thresholds
    DEFAULT_CONFIDENCE_THRESHOLD = 0.70
    HIGH_CONFIDENCE_THRESHOLD = 0.85

    def __init__(
        self,
        llm_provider: Optional[Any] = None,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
        enable_verification: bool = True,
        max_workers: int = 4
    ):
        """
        Initialize AISLE Engine

        Args:
            llm_provider: LLM provider for AI analysis (Anthropic, OpenAI, etc.)
            confidence_threshold: Minimum confidence to report findings
            enable_verification: Whether to verify findings with sandbox
            max_workers: Maximum parallel workers for analysis
        """
        self.llm = llm_provider
        self.confidence_threshold = confidence_threshold
        self.enable_verification = enable_verification
        self.max_workers = max_workers

        # Initialize sub-modules (lazy loading)
        self._semantic_twin = None
        self._proactive_scanner = None
        self._taint_analyzer = None
        self._zero_day_hypothesizer = None
        self._sandbox_validator = None

        # Statistics
        self.total_tokens = 0
        self.total_cost = 0.0

        logger.info(f"AISLE Engine initialized (confidence threshold: {confidence_threshold})")

    @property
    def semantic_twin(self):
        """Lazy load Semantic Code Twin module"""
        if self._semantic_twin is None:
            try:
                from semantic_code_twin import SemanticCodeTwin
                self._semantic_twin = SemanticCodeTwin(llm_provider=self.llm)
                logger.info("Semantic Code Twin module loaded")
            except ImportError as e:
                logger.warning(f"Semantic Code Twin not available: {e}")
        return self._semantic_twin

    @property
    def proactive_scanner(self):
        """Lazy load Proactive AI Scanner module"""
        if self._proactive_scanner is None:
            try:
                from proactive_ai_scanner import ProactiveAIScanner
                self._proactive_scanner = ProactiveAIScanner(llm_provider=self.llm)
                logger.info("Proactive AI Scanner module loaded")
            except ImportError as e:
                logger.warning(f"Proactive AI Scanner not available: {e}")
        return self._proactive_scanner

    @property
    def taint_analyzer(self):
        """Lazy load Taint Analyzer module"""
        if self._taint_analyzer is None:
            try:
                from taint_analyzer import TaintAnalyzer
                self._taint_analyzer = TaintAnalyzer()
                logger.info("Taint Analyzer module loaded")
            except ImportError as e:
                logger.warning(f"Taint Analyzer not available: {e}")
        return self._taint_analyzer

    @property
    def zero_day_hypothesizer(self):
        """Lazy load Zero-Day Hypothesizer module"""
        if self._zero_day_hypothesizer is None:
            try:
                from zero_day_hypothesizer import ZeroDayHypothesizer
                self._zero_day_hypothesizer = ZeroDayHypothesizer(llm_provider=self.llm)
                logger.info("Zero-Day Hypothesizer module loaded")
            except ImportError as e:
                logger.warning(f"Zero-Day Hypothesizer not available: {e}")
        return self._zero_day_hypothesizer

    @property
    def sandbox_validator(self):
        """Lazy load Sandbox Validator"""
        if self._sandbox_validator is None:
            try:
                from sandbox_validator import SandboxValidator
                self._sandbox_validator = SandboxValidator()
                logger.info("Sandbox Validator loaded")
            except ImportError as e:
                logger.warning(f"Sandbox Validator not available: {e}")
        return self._sandbox_validator

    def analyze(
        self,
        files: List[str],
        project_type: str = "backend-api",
        existing_findings: Optional[List[Dict]] = None,
        phases: Optional[List[AISLEPhase]] = None
    ) -> AISLEAnalysisResult:
        """
        Run complete AISLE analysis on provided files

        Args:
            files: List of file paths to analyze
            project_type: Type of project (backend-api, frontend, library, etc.)
            existing_findings: Existing findings from other scanners (for deduplication)
            phases: Specific phases to run (default: all)

        Returns:
            AISLEAnalysisResult with all findings and statistics
        """
        start_time = time.time()
        all_findings: List[AISLEFinding] = []

        # Default to all phases
        if phases is None:
            phases = [
                AISLEPhase.SEMANTIC_ANALYSIS,
                AISLEPhase.PROACTIVE_SCAN,
                AISLEPhase.TAINT_ANALYSIS,
                AISLEPhase.ZERO_DAY_HYPOTHESIS
            ]

        logger.info(f"🚀 Starting AISLE analysis on {len(files)} files")
        logger.info(f"   Project type: {project_type}")
        logger.info(f"   Phases: {[p.value for p in phases]}")

        # Read file contents
        file_contents = self._read_files(files)

        # Track statistics
        stats = {
            "semantic_twins": 0,
            "proactive_findings": 0,
            "taint_flows": 0,
            "zero_day_hypotheses": 0,
            "functions_analyzed": 0
        }

        # Phase 1: Semantic Analysis (build code twins)
        code_twins = {}
        if AISLEPhase.SEMANTIC_ANALYSIS in phases and self.semantic_twin:
            logger.info("📊 Phase 1: Building Semantic Code Twins...")
            code_twins = self._run_semantic_analysis(file_contents)
            stats["semantic_twins"] = len(code_twins)
            logger.info(f"   Created {len(code_twins)} code twins")

        # Phase 2: Proactive AI Scanning
        if AISLEPhase.PROACTIVE_SCAN in phases and self.proactive_scanner:
            logger.info("🔍 Phase 2: Running Proactive AI Scanner...")
            proactive_findings = self._run_proactive_scan(
                file_contents,
                code_twins,
                project_type
            )
            all_findings.extend(proactive_findings)
            stats["proactive_findings"] = len(proactive_findings)
            logger.info(f"   Found {len(proactive_findings)} potential vulnerabilities")

        # Phase 3: Taint Analysis
        if AISLEPhase.TAINT_ANALYSIS in phases and self.taint_analyzer:
            logger.info("🔗 Phase 3: Running Cross-Function Taint Analysis...")
            taint_findings = self._run_taint_analysis(file_contents)
            all_findings.extend(taint_findings)
            stats["taint_flows"] = len(taint_findings)
            logger.info(f"   Found {len(taint_findings)} taint flow vulnerabilities")

        # Phase 4: Zero-Day Hypothesis Generation
        if AISLEPhase.ZERO_DAY_HYPOTHESIS in phases and self.zero_day_hypothesizer:
            logger.info("💡 Phase 4: Generating Zero-Day Hypotheses...")
            hypotheses = self._run_zero_day_hypothesizer(
                file_contents,
                code_twins,
                existing_findings or []
            )
            all_findings.extend(hypotheses)
            stats["zero_day_hypotheses"] = len(hypotheses)
            logger.info(f"   Generated {len(hypotheses)} zero-day hypotheses")

        # Filter by confidence threshold
        high_confidence_findings = [
            f for f in all_findings
            if f.confidence >= self.confidence_threshold
        ]

        # Deduplicate with existing findings
        if existing_findings:
            high_confidence_findings = self._deduplicate(
                high_confidence_findings,
                existing_findings
            )

        # Phase 5: Verification (if enabled)
        verified_count = 0
        if self.enable_verification and self.sandbox_validator:
            logger.info("✅ Phase 5: Verifying findings with sandbox...")
            verified_count = self._verify_findings(high_confidence_findings)
            logger.info(f"   Verified {verified_count} findings")

        # Calculate total time
        total_time = time.time() - start_time

        # Build result
        result = AISLEAnalysisResult(
            findings=high_confidence_findings,
            files_analyzed=len(files),
            functions_analyzed=stats["functions_analyzed"],
            total_time_seconds=total_time,
            semantic_twins_created=stats["semantic_twins"],
            proactive_findings=stats["proactive_findings"],
            taint_flows_detected=stats["taint_flows"],
            zero_day_hypotheses=stats["zero_day_hypotheses"],
            patches_verified=verified_count,
            llm_tokens_used=self.total_tokens,
            estimated_cost_usd=self.total_cost
        )

        logger.info(f"✨ AISLE analysis complete!")
        logger.info(f"   Total findings: {len(high_confidence_findings)}")
        logger.info(f"   Time: {total_time:.2f}s")

        return result

    def _read_files(self, files: List[str]) -> Dict[str, str]:
        """Read file contents"""
        contents = {}
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    contents[file_path] = f.read()
            except Exception as e:
                logger.warning(f"Could not read {file_path}: {e}")
        return contents

    def _run_semantic_analysis(
        self,
        file_contents: Dict[str, str]
    ) -> Dict[str, Any]:
        """Run semantic analysis to build code twins"""
        code_twins = {}

        for file_path, content in file_contents.items():
            try:
                twin = self.semantic_twin.build_twin(content, file_path)
                if twin:
                    code_twins[file_path] = twin
            except Exception as e:
                logger.debug(f"Could not build twin for {file_path}: {e}")

        return code_twins

    def _run_proactive_scan(
        self,
        file_contents: Dict[str, str],
        code_twins: Dict[str, Any],
        project_type: str
    ) -> List[AISLEFinding]:
        """Run proactive AI scanning"""
        findings = []

        try:
            scanner_results = self.proactive_scanner.scan(
                file_contents,
                context={
                    "project_type": project_type,
                    "code_twins": code_twins
                }
            )

            for result in scanner_results:
                finding = AISLEFinding(
                    id=self._generate_id("proactive", result),
                    source="proactive-scanner",
                    title=result.get("title", "Potential Vulnerability"),
                    description=result.get("description", ""),
                    severity=FindingSeverity(result.get("severity", "medium")),
                    confidence=result.get("confidence", 0.5),
                    file_path=result.get("file", "unknown"),
                    line_number=result.get("line", 0),
                    code_snippet=result.get("snippet", ""),
                    reasoning_chain=result.get("reasoning", []),
                    attack_scenario=result.get("attack_scenario"),
                    cwe_id=result.get("cwe_id"),
                    suggested_fix=result.get("suggested_fix")
                )
                findings.append(finding)

        except Exception as e:
            logger.error(f"Proactive scan failed: {e}")

        return findings

    def _run_taint_analysis(
        self,
        file_contents: Dict[str, str]
    ) -> List[AISLEFinding]:
        """Run cross-function taint analysis"""
        findings = []

        try:
            taint_results = self.taint_analyzer.analyze(file_contents)

            for flow in taint_results:
                if not flow.get("sanitized", True):
                    finding = AISLEFinding(
                        id=self._generate_id("taint", flow),
                        source="taint-analyzer",
                        title=f"Unsanitized Data Flow: {flow.get('source_type', 'unknown')} → {flow.get('sink_type', 'unknown')}",
                        description=self._build_taint_description(flow),
                        severity=self._taint_severity(flow),
                        confidence=flow.get("confidence", 0.7),
                        file_path=flow.get("sink_file", "unknown"),
                        line_number=flow.get("sink_line", 0),
                        code_snippet=flow.get("sink_code", ""),
                        reasoning_chain=self._build_taint_reasoning(flow),
                        attack_scenario=self._build_taint_attack(flow),
                        cwe_id=self._taint_to_cwe(flow)
                    )
                    findings.append(finding)

        except Exception as e:
            logger.error(f"Taint analysis failed: {e}")

        return findings

    def _run_zero_day_hypothesizer(
        self,
        file_contents: Dict[str, str],
        code_twins: Dict[str, Any],
        existing_findings: List[Dict]
    ) -> List[AISLEFinding]:
        """Run zero-day hypothesis generation"""
        findings = []

        try:
            hypotheses = self.zero_day_hypothesizer.hypothesize(
                file_contents,
                code_twins=code_twins,
                known_vulnerabilities=existing_findings
            )

            for hyp in hypotheses:
                if hyp.get("confidence", 0) >= 0.75:  # Higher threshold for hypotheses
                    finding = AISLEFinding(
                        id=self._generate_id("zeroday", hyp),
                        source="zero-day-hypothesizer",
                        title=f"[Hypothesis] {hyp.get('title', 'Potential Novel Vulnerability')}",
                        description=hyp.get("hypothesis", ""),
                        severity=FindingSeverity(hyp.get("severity", "medium")),
                        confidence=hyp.get("confidence", 0.5),
                        file_path=hyp.get("file", "unknown"),
                        line_number=hyp.get("line", 0),
                        code_snippet=hyp.get("snippet", ""),
                        reasoning_chain=hyp.get("reasoning", []),
                        attack_scenario=hyp.get("attack_scenario"),
                        cwe_id=hyp.get("cwe_id")
                    )
                    findings.append(finding)

        except Exception as e:
            logger.error(f"Zero-day hypothesizer failed: {e}")

        return findings

    def _verify_findings(self, findings: List[AISLEFinding]) -> int:
        """Verify findings with sandbox validation"""
        verified_count = 0

        for finding in findings:
            if finding.confidence >= self.HIGH_CONFIDENCE_THRESHOLD:
                try:
                    # Attempt sandbox verification
                    result = self.sandbox_validator.validate_finding(finding.to_dict())
                    finding.verified = result.get("exploitable", False)
                    finding.verification_result = result.get("status", "unknown")
                    if finding.verified:
                        verified_count += 1
                except Exception as e:
                    logger.debug(f"Could not verify finding {finding.id}: {e}")

        return verified_count

    def _deduplicate(
        self,
        findings: List[AISLEFinding],
        existing: List[Dict]
    ) -> List[AISLEFinding]:
        """Remove findings that duplicate existing scanner findings"""
        existing_signatures = set()

        for e in existing:
            sig = f"{e.get('path', '')}:{e.get('line_number', 0)}:{e.get('cwe', '')}"
            existing_signatures.add(sig)

        unique = []
        for f in findings:
            sig = f"{f.file_path}:{f.line_number}:{f.cwe_id or ''}"
            if sig not in existing_signatures:
                unique.append(f)

        return unique

    def _generate_id(self, source: str, data: Any) -> str:
        """Generate unique finding ID"""
        content = f"{source}:{json.dumps(data, sort_keys=True, default=str)}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _build_taint_description(self, flow: Dict) -> str:
        """Build description for taint flow finding"""
        return (
            f"Untrusted data from {flow.get('source_type', 'unknown source')} "
            f"flows to {flow.get('sink_type', 'unknown sink')} without proper sanitization. "
            f"Path: {' → '.join(flow.get('path', []))}"
        )

    def _taint_severity(self, flow: Dict) -> FindingSeverity:
        """Determine severity based on taint sink type"""
        sink = flow.get("sink_type", "").lower()
        if sink in ["sql", "command", "eval", "exec"]:
            return FindingSeverity.CRITICAL
        elif sink in ["file", "ssrf", "template"]:
            return FindingSeverity.HIGH
        elif sink in ["log", "response"]:
            return FindingSeverity.MEDIUM
        return FindingSeverity.LOW

    def _build_taint_reasoning(self, flow: Dict) -> List[str]:
        """Build reasoning chain for taint flow"""
        return [
            f"1. Tainted data enters at: {flow.get('source_file', '')}:{flow.get('source_line', '')}",
            f"2. Source type: {flow.get('source_type', 'unknown')}",
            f"3. Data flows through: {' → '.join(flow.get('path', []))}",
            f"4. No sanitization detected on path",
            f"5. Data reaches dangerous sink: {flow.get('sink_type', 'unknown')}"
        ]

    def _build_taint_attack(self, flow: Dict) -> str:
        """Build attack scenario for taint flow"""
        sink = flow.get("sink_type", "").lower()
        attacks = {
            "sql": "Attacker could inject SQL commands to read/modify/delete database records",
            "command": "Attacker could execute arbitrary system commands on the server",
            "eval": "Attacker could execute arbitrary code in the application context",
            "file": "Attacker could read/write arbitrary files on the system",
            "template": "Attacker could inject template code for server-side template injection",
            "ssrf": "Attacker could make the server send requests to internal services"
        }
        return attacks.get(sink, "Attacker could exploit this data flow for malicious purposes")

    def _taint_to_cwe(self, flow: Dict) -> str:
        """Map taint sink to CWE"""
        sink = flow.get("sink_type", "").lower()
        cwe_map = {
            "sql": "CWE-89",
            "command": "CWE-78",
            "eval": "CWE-94",
            "exec": "CWE-94",
            "file": "CWE-22",
            "template": "CWE-1336",
            "ssrf": "CWE-918",
            "xss": "CWE-79",
            "log": "CWE-117"
        }
        return cwe_map.get(sink, "CWE-20")


def run_aisle_analysis(
    target_path: str,
    project_type: str = "backend-api",
    output_file: Optional[str] = None,
    llm_provider: Optional[Any] = None
) -> AISLEAnalysisResult:
    """
    Convenience function to run AISLE analysis

    Args:
        target_path: Path to directory or file to analyze
        project_type: Type of project
        output_file: Optional path to write JSON results
        llm_provider: Optional LLM provider

    Returns:
        AISLEAnalysisResult
    """
    # Gather files
    target = Path(target_path)
    if target.is_file():
        files = [str(target)]
    else:
        extensions = [".py", ".js", ".ts", ".go", ".java", ".rb", ".php"]
        files = []
        for ext in extensions:
            files.extend([str(f) for f in target.rglob(f"*{ext}")])

    # Filter out test files and node_modules
    files = [
        f for f in files
        if "test" not in f.lower()
        and "node_modules" not in f
        and "__pycache__" not in f
    ]

    logger.info(f"Found {len(files)} files to analyze")

    # Run analysis
    engine = AISLEEngine(llm_provider=llm_provider)
    result = engine.analyze(files, project_type=project_type)

    # Write output if requested
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        logger.info(f"Results written to {output_file}")

    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="AISLE Engine - AI Security Learning Engine"
    )
    parser.add_argument("path", help="Path to analyze")
    parser.add_argument("--project-type", default="backend-api",
                       help="Project type (backend-api, frontend, library)")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--confidence", type=float, default=0.7,
                       help="Minimum confidence threshold")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Verbose output")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    print("=" * 60)
    print("AISLE Engine - AI Security Learning Engine")
    print("Inspired by AISLE (aisle.com)")
    print("=" * 60)

    result = run_aisle_analysis(
        args.path,
        project_type=args.project_type,
        output_file=args.output
    )

    # Print summary
    print(f"\n📊 Analysis Summary:")
    print(f"   Files analyzed: {result.files_analyzed}")
    print(f"   Total findings: {len(result.findings)}")
    print(f"   Time: {result.total_time_seconds:.2f}s")

    if result.findings:
        print(f"\n🔥 Findings by severity:")
        severity_counts = {}
        for f in result.findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for sev, count in sorted(severity_counts.items()):
            print(f"   {sev.upper()}: {count}")

        print(f"\n🎯 Top findings:")
        for i, finding in enumerate(sorted(result.findings, key=lambda x: x.confidence, reverse=True)[:5], 1):
            print(f"   {i}. [{finding.severity.value.upper()}] {finding.title}")
            print(f"      {finding.file_path}:{finding.line_number}")
            print(f"      Confidence: {finding.confidence:.0%}")
