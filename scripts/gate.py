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

from resource_paths import resource_root


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
                self.policy_dir = resource_root() / policy_dir
        else:
            self.policy_dir = policy_path
        self._check_opa_installed()

    def _check_opa_installed(self):
        """Check if OPA is installed"""
        try:
            subprocess.run(["opa", "version"], capture_output=True, check=True, timeout=10)
        except (subprocess.SubprocessError, OSError) as exc:
            raise RuntimeError("OPA is required for policy evaluation; install the opa executable") from exc

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

            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)

            output = json.loads(result.stdout)
            decision = output["result"][0]["expressions"][0]["value"]

            if not isinstance(decision, dict) or decision.get("decision") not in {"pass", "fail"}:
                raise ValueError("OPA returned an invalid decision")
            for key in ("blocks", "warnings", "reasons"):
                if not isinstance(decision.get(key, []), list):
                    raise ValueError(f"OPA returned invalid {key}")
            return decision

        except (subprocess.SubprocessError, OSError, ValueError, KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("OPA policy evaluation failed") from exc
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
    try:
        gate = PolicyGate(policy_dir=args.policy_dir)
        decision = gate.evaluate(args.stage, findings, metadata)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"Policy error: {exc}", file=sys.stderr)
        sys.exit(2)

    # Print decision
    gate.print_decision(decision)

    # Exit with appropriate code
    if decision["decision"] == "fail":
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
