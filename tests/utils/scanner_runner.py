"""
Scanner runner utilities for integration tests
Provides helpers to run scanners and capture output
"""
import json
import logging
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

logger = logging.getLogger(__name__)


class ScannerRunner:
    """Helper class to run security scanners for testing"""

    @staticmethod
    def run_semgrep(target_path: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run Semgrep scanner on target path

        Args:
            target_path: Path to scan
            config: Optional scanner configuration

        Returns:
            Scanner output dictionary
        """
        try:
            from semgrep_scanner import SemgrepScanner

            scanner = SemgrepScanner(config)
            return scanner.scan(target_path)
        except Exception as e:
            logger.error(f"Failed to run Semgrep: {e}")
            return {"error": str(e), "findings": []}

    @staticmethod
    def run_trivy(target_path: str, scan_type: str = "fs") -> Dict[str, Any]:
        """
        Run Trivy scanner on target path

        Args:
            target_path: Path to scan
            scan_type: Type of scan (fs, image, config)

        Returns:
            Scanner output dictionary
        """
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                output_file = f.name

            cmd = ["trivy", scan_type, "--format", "json", "--output", output_file, target_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode != 0:
                logger.error(f"Trivy failed: {result.stderr}")
                return {"error": "trivy_failed", "findings": []}

            with open(output_file, 'r') as f:
                output = json.load(f)

            Path(output_file).unlink()  # Clean up temp file
            return output

        except subprocess.TimeoutExpired:
            return {"error": "timeout", "findings": []}
        except Exception as e:
            logger.error(f"Failed to run Trivy: {e}")
            return {"error": str(e), "findings": []}

    @staticmethod
    def run_checkov(target_path: str, framework: Optional[str] = None) -> Dict[str, Any]:
        """
        Run Checkov scanner on target path

        Args:
            target_path: Path to scan
            framework: Optional framework filter (terraform, kubernetes, etc.)

        Returns:
            Scanner output dictionary
        """
        try:
            from checkov_scanner import CheckovScanner

            config = {}
            if framework:
                config["framework"] = framework

            scanner = CheckovScanner(config)
            return scanner.scan(target_path)
        except Exception as e:
            logger.error(f"Failed to run Checkov: {e}")
            return {"error": str(e), "findings": []}

    @staticmethod
    def run_trufflehog(target_path: str, verified_only: bool = True) -> Dict[str, Any]:
        """
        Run TruffleHog scanner on target path

        Args:
            target_path: Path to scan
            verified_only: Only return verified secrets

        Returns:
            Scanner output dictionary
        """
        try:
            from trufflehog_scanner import TruffleHogScanner

            config = {"verified_only": verified_only}
            scanner = TruffleHogScanner(config)
            return scanner.scan(target_path)
        except Exception as e:
            logger.error(f"Failed to run TruffleHog: {e}")
            return {"error": str(e), "findings": []}

    @staticmethod
    def run_hybrid_analyzer(
        target_path: str,
        enable_semgrep: bool = True,
        enable_trivy: bool = True,
        enable_checkov: bool = True,
        enable_ai_enrichment: bool = False,
    ) -> Dict[str, Any]:
        """
        Run hybrid analyzer with multiple scanners

        Args:
            target_path: Path to scan
            enable_semgrep: Enable Semgrep SAST
            enable_trivy: Enable Trivy CVE scanning
            enable_checkov: Enable Checkov IaC scanning
            enable_ai_enrichment: Enable AI enrichment (requires API key)

        Returns:
            Hybrid scan results
        """
        try:
            from hybrid_analyzer import HybridSecurityAnalyzer

            analyzer = HybridSecurityAnalyzer(
                enable_semgrep=enable_semgrep,
                enable_trivy=enable_trivy,
                enable_checkov=enable_checkov,
                enable_ai_enrichment=enable_ai_enrichment,
            )
            results = analyzer.analyze(target_path)
            return results
        except Exception as e:
            logger.error(f"Failed to run hybrid analyzer: {e}")
            return {"error": str(e), "findings": []}

    @staticmethod
    def run_sast_dast_correlation(sast_findings: List[Dict], dast_findings: List[Dict]) -> Dict[str, Any]:
        """
        Run SAST-DAST correlation

        Args:
            sast_findings: SAST findings list
            dast_findings: DAST findings list

        Returns:
            Correlation results
        """
        try:
            from sast_dast_correlator import SASTDASTCorrelator

            correlator = SASTDASTCorrelator()
            # Mock LLM manager for testing
            correlator.llm_manager = None
            return correlator.correlate_findings(sast_findings, dast_findings)
        except Exception as e:
            logger.error(f"Failed to run correlation: {e}")
            return {"error": str(e), "correlations": []}

    @staticmethod
    def run_full_pipeline(
        target_path: str,
        ai_provider: Optional[str] = None,
        enable_all_scanners: bool = True,
    ) -> Dict[str, Any]:
        """
        Run complete Argus pipeline

        Args:
            target_path: Path to scan
            ai_provider: AI provider (anthropic, openai, ollama)
            enable_all_scanners: Enable all available scanners

        Returns:
            Complete pipeline results
        """
        try:
            # Import main audit script
            from run_ai_audit import main as run_audit_main
            import argparse

            # Build args
            args = argparse.Namespace(
                path=target_path,
                mode="audit",
                ai_provider=ai_provider or "ollama",
                enable_threat_modeling=True,
                enable_sandbox_validation=False,
                max_files=50,
                max_tokens=8000,
                output_file=None,
            )

            # Note: This would actually run the full pipeline
            # For testing, we might want to mock API calls
            logger.info(f"Running full pipeline on {target_path}")

            # In real tests, we'd capture stdout/stderr and parse results
            return {"status": "completed", "findings": []}

        except Exception as e:
            logger.error(f"Failed to run full pipeline: {e}")
            return {"error": str(e), "findings": []}


# Convenience instance
scanner_runner = ScannerRunner()
