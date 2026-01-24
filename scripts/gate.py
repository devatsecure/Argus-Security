#!/usr/bin/env python3
"""
Argus Policy Gate
Evaluates Rego policies to determine pass/fail for PR or release
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


class PolicyGate:
    """Policy engine for security gates"""

    def __init__(self, policy_dir: str = "policy/rego"):
        # Support both relative and absolute paths
        policy_path = Path(policy_dir)
        if not policy_path.is_absolute():
            # Try relative to current directory first
            if policy_path.exists():
                self.policy_dir = policy_path
            else:
                # Try relative to script directory
                script_dir = Path(__file__).parent.parent
                self.policy_dir = script_dir / policy_dir
        else:
            self.policy_dir = policy_path
        self._check_opa_installed()

    def _check_opa_installed(self):
        """Check if OPA is installed"""
        try:
            subprocess.run(["opa", "version"], capture_output=True, check=True)
            self.opa_available = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            # In test environments, make OPA optional
            import os

            if os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("TESTING"):
                self.opa_available = False
                return
            print("❌ Error: OPA not installed")
            print("\nInstall OPA:")
            print("  macOS:  brew install opa")
            print("  Linux:  curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64")
            print("          chmod +x opa && sudo mv opa /usr/local/bin/")
            sys.exit(2)

    def _fallback_policy_evaluation(self, stage, findings, metadata=None):
        """Fallback policy evaluation when OPA is not available (for testing)"""
        blocks = []
        warnings = []
        reasons = []

        if stage == "pr":
            # PR policy: Block verified secrets and critical public IAC
            for finding in findings:
                category = finding.get("category", "").upper()
                severity = finding.get("severity", "").lower()

                # Block verified secrets
                if category == "SECRETS" and finding.get("secret_verified") == "true":
                    blocks.append(finding)
                    reasons.append(f"Verified secret detected in {finding.get('path', 'unknown')}")

                # Warn on unverified secrets
                elif category == "SECRETS" and finding.get("secret_verified") == "false":
                    warnings.append(finding)

                # Block critical IAC with public exposure
                elif category == "IAC" and severity == "critical" and finding.get("service_tier") == "public":
                    blocks.append(finding)
                    reasons.append(f"Critical IAC issue with public exposure in {finding.get('path', 'unknown')}")

        elif stage == "release":
            # Release policy: Require SBOM, signature, and no critical findings
            if metadata:
                if not metadata.get("sbom_present", metadata.get("sbom_generated", False)):
                    blocks.append({"type": "missing_sbom"})
                    reasons.append("SBOM not generated")

                if not metadata.get("signature_verified", True):
                    blocks.append({"type": "missing_signature"})
                    reasons.append("Signature not verified")

            # Block any critical findings
            for finding in findings:
                if finding.get("severity", "").lower() == "critical":
                    blocks.append(finding)
                    reasons.append(f"Critical finding in {finding.get('path', 'unknown')}")

        decision = "fail" if blocks else "pass"
        return {"decision": decision, "reasons": reasons, "blocks": blocks, "warnings": warnings}

    def evaluate(self, stage: str, findings: list[dict], metadata: dict[str, bool] = None) -> dict[str, Any]:
        """
        Evaluate policy for given stage

        Args:
            stage: 'pr' or 'release'
            findings: List of Finding dicts
            metadata: Additional metadata (sbom_present, signature_verified, etc.)

        Returns:
            Decision dict: {decision, reasons, blocks, warnings}
        """
        if stage not in ["pr", "release"]:
            raise ValueError(f"Invalid stage: {stage}. Must be 'pr' or 'release'")

        # If OPA not available (e.g., in test environment), use fallback policy
        if not getattr(self, "opa_available", True):
            return self._fallback_policy_evaluation(stage, findings, metadata)

        policy_file = self.policy_dir / f"{stage}.rego"
        if not policy_file.exists():
            raise FileNotFoundError(f"Policy file not found: {policy_file}")

        # Prepare input
        policy_input = {"findings": findings, "stage": stage}

        # Add metadata for release stage
        if stage == "release" and metadata:
            policy_input.update(metadata)

        # Write input to temp file
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(policy_input, f, indent=2)
            input_file = f.name

        try:
            # Run OPA evaluation
            cmd = [
                "opa",
                "eval",
                "--data",
                str(policy_file),
                "--input",
                input_file,
                "--format",
                "json",
                f"data.argus.{stage}.decision",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            output = json.loads(result.stdout)
            decision = output["result"][0]["expressions"][0]["value"]

            return decision

        except subprocess.CalledProcessError as e:
            print(f"❌ OPA evaluation failed: {e.stderr}")
            sys.exit(2)
        except Exception as e:
            print(f"❌ Error evaluating policy: {e}")
            sys.exit(2)
        finally:
            # Clean up temp file
            Path(input_file).unlink(missing_ok=True)

    def print_decision(self, decision: dict):
        """Print decision in human-readable format"""
        status = decision["decision"]
        reasons = decision.get("reasons", [])
        blocks = decision.get("blocks", [])
        warnings = decision.get("warnings", [])

        print("\n" + "=" * 60)
        if status == "pass":
            print("✅ GATE: PASS")
        else:
            print("🔴 GATE: FAIL")
        print("=" * 60 + "\n")

        if reasons:
            print("Reasons:")
            for reason in reasons:
                print(f"  {reason}")
            print()

        if blocks:
            print(f"🔴 Blocking findings: {len(blocks)}")
            print(f"   Finding IDs: {', '.join(blocks[:5])}")
            if len(blocks) > 5:
                print(f"   ... and {len(blocks) - 5} more")
            print()

        if warnings:
            print(f"⚠️  Warnings: {len(warnings)}")
            print(f"   Finding IDs: {', '.join(warnings[:5])}")
            if len(warnings) > 5:
                print(f"   ... and {len(warnings) - 5} more")
            print()


def main():
    parser = argparse.ArgumentParser(description="Argus Policy Gate - Deterministic security gates")
    parser.add_argument("--stage", required=True, choices=["pr", "release"], help="Gate stage: pr or release")
    parser.add_argument("--input", required=True, help="Path to findings JSON file")
    parser.add_argument("--sbom-present", action="store_true", help="SBOM is present (release only)")
    parser.add_argument("--signature-verified", action="store_true", help="Signature is verified (release only)")
    parser.add_argument("--provenance-present", action="store_true", help="SLSA provenance is present (release only)")
    parser.add_argument("--policy-dir", default="policy/rego", help="Directory containing Rego policies")

    args = parser.parse_args()

    # Load findings
    try:
        with open(args.input) as f:
            data = json.load(f)

        # Handle both list of findings and dict with 'findings' key
        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict) and "findings" in data:
            findings = data["findings"]
        else:
            print(f"❌ Error: Invalid findings format in {args.input}")
            sys.exit(2)

    except Exception as e:
        print(f"❌ Error loading findings: {e}")
        sys.exit(2)

    # Prepare metadata for release stage
    metadata = None
    if args.stage == "release":
        metadata = {
            "sbom_present": args.sbom_present,
            "signature_verified": args.signature_verified,
            "provenance_present": args.provenance_present,
        }

    # Evaluate policy
    gate = PolicyGate(policy_dir=args.policy_dir)
    decision = gate.evaluate(args.stage, findings, metadata)

    # Print decision
    gate.print_decision(decision)

    # Exit with appropriate code
    if decision["decision"] == "fail":
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
