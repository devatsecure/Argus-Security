#!/usr/bin/env python3
"""SBOM (Software Bill of Materials) generator using Trivy.

Generates CycloneDX and SPDX format SBOMs for software composition analysis.
Supports filesystem scanning for dependencies and container image scanning.
"""

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Optional

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Supported SBOM formats
CYCLONEDX_FORMAT = "cyclonedx"
SPDX_FORMAT = "spdx-json"

# Supported scan types
SCAN_TYPE_FS = "fs"
SCAN_TYPE_IMAGE = "image"

# Default output filenames
CYCLONEDX_FILENAME = "sbom-cyclonedx.json"
SPDX_FILENAME = "sbom-spdx.json"


class SBOMGenerationError(Exception):
    """Raised when SBOM generation fails."""


class SBOMGenerator:
    """Generate CycloneDX and SPDX SBOMs using Trivy.

    Supports filesystem and container image scanning. Produces JSON-format
    SBOMs suitable for policy gate evaluation, supply chain analysis, and
    compliance reporting.
    """

    def __init__(self, trivy_path: str = "trivy", output_dir: str = "."):
        """Initialize SBOM generator.

        Args:
            trivy_path: Path to trivy binary.
            output_dir: Directory for SBOM output files.
        """
        self.trivy_path = trivy_path
        self.output_dir = output_dir

    def _build_command(
        self,
        target_path: str,
        sbom_format: str,
        output_path: str,
        scan_type: str,
    ) -> list[str]:
        """Build the Trivy command for SBOM generation.

        Args:
            target_path: Path to scan (directory or container image name).
            sbom_format: Trivy format string ("cyclonedx" or "spdx-json").
            output_path: Path where SBOM file will be written.
            scan_type: "fs" for filesystem, "image" for container image.

        Returns:
            List of command arguments suitable for subprocess.run().

        Raises:
            ValueError: If scan_type is not recognized.
        """
        if scan_type not in (SCAN_TYPE_FS, SCAN_TYPE_IMAGE):
            raise ValueError(
                f"Invalid scan_type: {scan_type!r}. "
                f"Must be '{SCAN_TYPE_FS}' or '{SCAN_TYPE_IMAGE}'."
            )

        return [
            self.trivy_path,
            scan_type,
            "--format",
            sbom_format,
            "--output",
            output_path,
            "--quiet",
            target_path,
        ]

    def _run_trivy(
        self, cmd: list[str], timeout: int = 300
    ) -> subprocess.CompletedProcess:
        """Execute a Trivy command safely.

        Args:
            cmd: Command argument list.
            timeout: Maximum seconds to wait.

        Returns:
            The CompletedProcess result.

        Raises:
            SBOMGenerationError: If Trivy is not installed, times out, or
                returns a non-zero exit code.
        """
        env = os.environ.copy()
        env["TRIVY_NO_PROGRESS"] = "true"

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, env=env
            )
        except FileNotFoundError:
            raise SBOMGenerationError(
                f"Trivy binary not found at '{self.trivy_path}'. "
                "Install Trivy: https://aquasecurity.github.io/trivy/"
            )
        except subprocess.TimeoutExpired:
            raise SBOMGenerationError(
                f"Trivy SBOM generation timed out after {timeout} seconds."
            )
        except subprocess.SubprocessError as e:
            raise SBOMGenerationError(f"Trivy subprocess error: {e}")

        if result.returncode != 0:
            stderr = result.stderr.strip() if result.stderr else "unknown error"
            raise SBOMGenerationError(
                f"Trivy exited with code {result.returncode}: {stderr}"
            )

        return result

    def _parse_sbom_file(self, sbom_path: str) -> dict[str, Any]:
        """Read and parse a generated SBOM JSON file.

        Args:
            sbom_path: Path to the SBOM file.

        Returns:
            Parsed JSON dict.

        Raises:
            SBOMGenerationError: If the file cannot be read or parsed.
        """
        try:
            with open(sbom_path) as f:
                return json.load(f)
        except FileNotFoundError:
            raise SBOMGenerationError(
                f"SBOM file not found at '{sbom_path}'. "
                "Trivy may not have produced output."
            )
        except json.JSONDecodeError as e:
            raise SBOMGenerationError(
                f"Failed to parse SBOM JSON at '{sbom_path}': {e}"
            )
        except OSError as e:
            raise SBOMGenerationError(
                f"Could not read SBOM file '{sbom_path}': {e}"
            )

    def _count_components(
        self, sbom_data: dict[str, Any], sbom_format: str
    ) -> int:
        """Count components in a parsed SBOM.

        Args:
            sbom_data: Parsed SBOM JSON.
            sbom_format: "cyclonedx" or "spdx-json".

        Returns:
            Number of components found.
        """
        if sbom_format == CYCLONEDX_FORMAT:
            return len(sbom_data.get("components", []))
        elif sbom_format == SPDX_FORMAT:
            return len(sbom_data.get("packages", []))
        return 0

    def generate_cyclonedx(
        self, target_path: str, scan_type: str = SCAN_TYPE_FS
    ) -> dict[str, Any]:
        """Generate CycloneDX 1.5 SBOM.

        Args:
            target_path: Path to scan (directory or container image).
            scan_type: "fs" for filesystem, "image" for container image.

        Returns:
            dict with keys: success, sbom_path, component_count, format.
            On failure: success=False with an error key.
        """
        output_path = str(Path(self.output_dir) / CYCLONEDX_FILENAME)

        try:
            Path(self.output_dir).mkdir(parents=True, exist_ok=True)

            cmd = self._build_command(
                target_path, CYCLONEDX_FORMAT, output_path, scan_type
            )
            logger.info(
                "Generating CycloneDX SBOM for %s (scan_type=%s)",
                target_path,
                scan_type,
            )

            self._run_trivy(cmd)

            sbom_data = self._parse_sbom_file(output_path)
            component_count = self._count_components(
                sbom_data, CYCLONEDX_FORMAT
            )

            logger.info(
                "CycloneDX SBOM generated: %s (%d components)",
                output_path,
                component_count,
            )

            return {
                "success": True,
                "sbom_path": output_path,
                "component_count": component_count,
                "format": "CycloneDX 1.5",
            }

        except SBOMGenerationError as e:
            logger.error("CycloneDX generation failed: %s", e)
            return {
                "success": False,
                "sbom_path": None,
                "component_count": 0,
                "format": "CycloneDX 1.5",
                "error": str(e),
            }
        except ValueError as e:
            logger.error("Invalid parameters: %s", e)
            return {
                "success": False,
                "sbom_path": None,
                "component_count": 0,
                "format": "CycloneDX 1.5",
                "error": str(e),
            }

    def generate_spdx(
        self, target_path: str, scan_type: str = SCAN_TYPE_FS
    ) -> dict[str, Any]:
        """Generate SPDX 2.3 SBOM.

        Args:
            target_path: Path to scan (directory or container image).
            scan_type: "fs" for filesystem, "image" for container image.

        Returns:
            dict with keys: success, sbom_path, component_count, format.
            On failure: success=False with an error key.
        """
        output_path = str(Path(self.output_dir) / SPDX_FILENAME)

        try:
            Path(self.output_dir).mkdir(parents=True, exist_ok=True)

            cmd = self._build_command(
                target_path, SPDX_FORMAT, output_path, scan_type
            )
            logger.info(
                "Generating SPDX SBOM for %s (scan_type=%s)",
                target_path,
                scan_type,
            )

            self._run_trivy(cmd)

            sbom_data = self._parse_sbom_file(output_path)
            component_count = self._count_components(sbom_data, SPDX_FORMAT)

            logger.info(
                "SPDX SBOM generated: %s (%d components)",
                output_path,
                component_count,
            )

            return {
                "success": True,
                "sbom_path": output_path,
                "component_count": component_count,
                "format": "SPDX 2.3",
            }

        except SBOMGenerationError as e:
            logger.error("SPDX generation failed: %s", e)
            return {
                "success": False,
                "sbom_path": None,
                "component_count": 0,
                "format": "SPDX 2.3",
                "error": str(e),
            }
        except ValueError as e:
            logger.error("Invalid parameters: %s", e)
            return {
                "success": False,
                "sbom_path": None,
                "component_count": 0,
                "format": "SPDX 2.3",
                "error": str(e),
            }

    def generate_all(
        self, target_path: str, scan_type: str = SCAN_TYPE_FS
    ) -> dict[str, Any]:
        """Generate both CycloneDX and SPDX SBOMs.

        Args:
            target_path: Path to scan (directory or container image).
            scan_type: "fs" for filesystem, "image" for container image.

        Returns:
            dict with keys: cyclonedx, spdx (each containing individual results).
        """
        cyclonedx_result = self.generate_cyclonedx(target_path, scan_type)
        spdx_result = self.generate_spdx(target_path, scan_type)

        return {
            "cyclonedx": cyclonedx_result,
            "spdx": spdx_result,
        }

    def get_component_summary(self, sbom_path: str) -> dict[str, Any]:
        """Parse an SBOM file and return a summary.

        Supports both CycloneDX and SPDX formats. Detects format by
        inspecting the JSON structure.

        Args:
            sbom_path: Path to a CycloneDX or SPDX JSON SBOM file.

        Returns:
            dict with keys: total_components, by_type, by_ecosystem, licenses.
            On failure: returns a dict with total_components=0 and an error key.
        """
        try:
            sbom_data = self._parse_sbom_file(sbom_path)
        except SBOMGenerationError as e:
            return {
                "total_components": 0,
                "by_type": {},
                "by_ecosystem": {},
                "licenses": [],
                "error": str(e),
            }

        # Detect format and extract components
        if "components" in sbom_data:
            return self._summarize_cyclonedx(sbom_data)
        elif "packages" in sbom_data:
            return self._summarize_spdx(sbom_data)
        else:
            return {
                "total_components": 0,
                "by_type": {},
                "by_ecosystem": {},
                "licenses": [],
                "error": (
                    "Unrecognized SBOM format: "
                    "no 'components' or 'packages' key found."
                ),
            }

    def _summarize_cyclonedx(
        self, sbom_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Summarize a CycloneDX SBOM.

        Args:
            sbom_data: Parsed CycloneDX JSON.

        Returns:
            Summary dict.
        """
        components = sbom_data.get("components", [])
        by_type: dict[str, int] = {}
        by_ecosystem: dict[str, int] = {}
        licenses: list[str] = []

        for comp in components:
            # Count by type (library, framework, application, etc.)
            comp_type = comp.get("type", "unknown")
            by_type[comp_type] = by_type.get(comp_type, 0) + 1

            # Count by ecosystem via purl
            purl = comp.get("purl", "")
            ecosystem = self._extract_ecosystem_from_purl(purl)
            if ecosystem:
                by_ecosystem[ecosystem] = (
                    by_ecosystem.get(ecosystem, 0) + 1
                )

            # Collect licenses
            for lic in comp.get("licenses", []):
                license_obj = lic.get("license", {})
                license_id = license_obj.get("id") or license_obj.get("name")
                if license_id and license_id not in licenses:
                    licenses.append(license_id)

        return {
            "total_components": len(components),
            "by_type": by_type,
            "by_ecosystem": by_ecosystem,
            "licenses": sorted(licenses),
        }

    def _summarize_spdx(
        self, sbom_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Summarize an SPDX SBOM.

        Args:
            sbom_data: Parsed SPDX JSON.

        Returns:
            Summary dict.
        """
        packages = sbom_data.get("packages", [])
        by_type: dict[str, int] = {}
        by_ecosystem: dict[str, int] = {}
        licenses: list[str] = []

        for pkg in packages:
            # SPDX uses 'primaryPackagePurpose' instead of 'type'
            pkg_type = pkg.get(
                "primaryPackagePurpose", "LIBRARY"
            ).lower()
            by_type[pkg_type] = by_type.get(pkg_type, 0) + 1

            # Extract ecosystem from externalRefs purl
            for ref in pkg.get("externalRefs", []):
                if ref.get("referenceType") == "purl":
                    ecosystem = self._extract_ecosystem_from_purl(
                        ref.get("referenceLocator", "")
                    )
                    if ecosystem:
                        by_ecosystem[ecosystem] = (
                            by_ecosystem.get(ecosystem, 0) + 1
                        )
                    break

            # Collect licenses
            license_concluded = pkg.get("licenseConcluded", "")
            if license_concluded and license_concluded not in (
                "NOASSERTION",
                "NONE",
            ):
                if license_concluded not in licenses:
                    licenses.append(license_concluded)

        return {
            "total_components": len(packages),
            "by_type": by_type,
            "by_ecosystem": by_ecosystem,
            "licenses": sorted(licenses),
        }

    @staticmethod
    def _extract_ecosystem_from_purl(purl: str) -> Optional[str]:
        """Extract the ecosystem/type from a package URL (purl).

        A purl looks like: pkg:pypi/requests@2.28.0
        This extracts 'pypi'.

        Args:
            purl: Package URL string.

        Returns:
            Ecosystem name or None.
        """
        if not purl or not purl.startswith("pkg:"):
            return None
        try:
            # Format: pkg:<type>/<namespace>/<name>@<version>
            type_and_rest = purl[4:]  # Remove 'pkg:'
            ecosystem = type_and_rest.split("/")[0]
            return ecosystem if ecosystem else None
        except (IndexError, ValueError):
            return None


def main():
    """CLI entry point for Trivy-based SBOM generation."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate Software Bill of Materials (SBOM) using Trivy"
    )
    parser.add_argument(
        "target", help="Target to scan (directory path or container image)"
    )
    parser.add_argument(
        "--scan-type",
        choices=["fs", "image"],
        default="fs",
        help="Type of scan: 'fs' for filesystem, 'image' for container",
    )
    parser.add_argument(
        "--format",
        choices=["cyclonedx", "spdx", "all"],
        default="all",
        help="SBOM format to generate (default: all)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=".",
        help="Output directory for SBOM files (default: current directory)",
    )
    parser.add_argument(
        "--trivy-path",
        default="trivy",
        help="Path to trivy binary (default: trivy)",
    )

    args = parser.parse_args()

    generator = SBOMGenerator(
        trivy_path=args.trivy_path, output_dir=args.output_dir
    )

    if args.format == "cyclonedx":
        result = generator.generate_cyclonedx(
            args.target, scan_type=args.scan_type
        )
        print(json.dumps(result, indent=2))
    elif args.format == "spdx":
        result = generator.generate_spdx(
            args.target, scan_type=args.scan_type
        )
        print(json.dumps(result, indent=2))
    else:
        result = generator.generate_all(
            args.target, scan_type=args.scan_type
        )
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
