#!/usr/bin/env python3
"""
SBOM Generator using Syft
Generates CycloneDX SBOM for codebases
"""

import hashlib
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional


class SBOMGenerator:
    """Generate Software Bill of Materials using Syft"""

    def __init__(self):
        self.format = "cyclonedx-json"

    def generate(self, path: str, output_file: Optional[str] = None) -> dict:
        """
        Generate SBOM for codebase

        Args:
            path: Directory or image to scan
            output_file: Optional output file path

        Returns:
            Dict: CycloneDX SBOM JSON
        """
        cmd = ["syft", "packages", path, "-o", self.format, "--quiet"]

        print(f"🔍 Generating SBOM for {path}...")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)  # 5 minute timeout

            sbom = json.loads(result.stdout)

            # Validate SBOM
            if not self.validate(sbom):
                raise ValueError("Generated SBOM is invalid")

            # Add metadata
            sbom = self._enrich_sbom(sbom, path)

            # Write to file if specified
            if output_file:
                # Create parent directory if needed
                Path(output_file).parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, "w") as f:
                    json.dump(sbom, f, indent=2)
                print(f"✅ SBOM written to {output_file}")

            # Print stats
            self._print_stats(sbom)

            return sbom

        except subprocess.CalledProcessError as e:
            print(f"❌ Syft failed: {e.stderr}")
            raise
        except subprocess.TimeoutExpired:
            print("❌ Syft timed out after 5 minutes")
            raise
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON output: {e}")
            raise

    def validate(self, sbom: dict) -> bool:
        """Validate SBOM completeness"""
        required_fields = ["bomFormat", "specVersion", "components"]

        for field in required_fields:
            if field not in sbom:
                print(f"❌ Missing required field: {field}")
                return False

        if sbom.get("bomFormat") != "CycloneDX":
            print(f"❌ Invalid bomFormat: {sbom.get('bomFormat')}")
            return False

        return True

    def _enrich_sbom(self, sbom: dict, path: str) -> dict:
        """Add Argus metadata to SBOM"""

        # Add metadata section if not present
        if "metadata" not in sbom:
            sbom["metadata"] = {}

        # Add generation timestamp
        sbom["metadata"]["timestamp"] = datetime.now().astimezone().isoformat()

        # Add tool info
        sbom["metadata"]["tools"] = [
            {"vendor": "Argus", "name": "Argus Security Control Plane", "version": "1.0.0"},
            {"vendor": "Anchore", "name": "Syft", "version": self._get_syft_version()},
        ]

        # Add component info
        if "component" not in sbom["metadata"]:
            sbom["metadata"]["component"] = {
                "type": "application",
                "name": Path(path).name,
                "bom-ref": hashlib.sha256(path.encode()).hexdigest()[:16],
            }

        return sbom

    def _get_syft_version(self) -> str:
        """Get Syft version"""
        try:
            result = subprocess.run(["syft", "version"], capture_output=True, text=True, timeout=5)
            # Parse version from output (format: "syft 1.37.0")
            for line in result.stdout.split("\n"):
                if "syft" in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
            return "unknown"
        except Exception:
            return "unknown"

    def _print_stats(self, sbom: dict):
        """Print SBOM statistics"""
        components = sbom.get("components", [])

        # Count by type
        by_type = {}
        for comp in components:
            comp_type = comp.get("type", "unknown")
            by_type[comp_type] = by_type.get(comp_type, 0) + 1

        print("\n📦 SBOM Statistics:")
        print(f"   Total Components: {len(components)}")
        for comp_type, count in sorted(by_type.items()):
            print(f"   - {comp_type}: {count}")

        # Count licenses
        licenses = set()
        for comp in components:
            if "licenses" in comp:
                for lic in comp["licenses"]:
                    if "license" in lic:
                        if "id" in lic["license"]:
                            licenses.add(lic["license"]["id"])
                        elif "name" in lic["license"]:
                            licenses.add(lic["license"]["name"])

        if licenses:
            print(f"   Unique Licenses: {len(licenses)}")

    def generate_for_release(self, repo_path: str, version: str, output_dir: str = "sboms") -> str:
        """
        Generate SBOM for a release

        Args:
            repo_path: Path to repository
            version: Release version (e.g., 'v1.0.0')
            output_dir: Directory to store SBOMs

        Returns:
            str: Path to generated SBOM file
        """
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Generate filename
        repo_name = Path(repo_path).name
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"sbom-{repo_name}-{version}-{timestamp}.json"
        output_file = output_path / filename

        # Generate SBOM
        self.generate(repo_path, str(output_file))

        return str(output_file)


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Generate Software Bill of Materials (SBOM)")
    parser.add_argument("path", help="Directory or image to scan")
    parser.add_argument("-o", "--output", help="Output file path (default: print to stdout)")
    parser.add_argument("--version", help="Release version (for release SBOMs)")
    parser.add_argument("--validate-only", action="store_true", help="Only validate existing SBOM file")

    args = parser.parse_args()

    generator = SBOMGenerator()

    if args.validate_only:
        # Validate existing SBOM
        with open(args.path) as f:
            sbom = json.load(f)

        if generator.validate(sbom):
            print("✅ SBOM is valid")
            exit(0)
        else:
            print("❌ SBOM is invalid")
            exit(1)
    else:
        # Generate new SBOM
        if args.version:
            output_file = generator.generate_for_release(args.path, args.version, output_dir="sboms")
            print(f"\n✅ Release SBOM generated: {output_file}")
        else:
            sbom = generator.generate(args.path, args.output)
            if not args.output:
                print(json.dumps(sbom, indent=2))


if __name__ == "__main__":
    main()
