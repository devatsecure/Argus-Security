#!/usr/bin/env python3
"""
Release Signing and SLSA Provenance Generation
Uses open source tools: Cosign (Apache 2.0) + SLSA Framework (Apache 2.0)
"""

import hashlib
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional


class ReleaseSigner:
    """Sign releases using Cosign (keyless or key-based)"""

    def __init__(self, key_path: Optional[str] = None, password: Optional[str] = None):
        """
        Initialize signer

        Args:
            key_path: Path to Cosign private key (optional, uses keyless if not provided)
            password: Key password (from env var COSIGN_PASSWORD if not provided)
        """
        self.key_path = key_path
        self.password = password or os.environ.get("COSIGN_PASSWORD", "")
        self.keyless = key_path is None

    def generate_keypair(self, output_dir: str = "."):
        """Generate Cosign key pair (one-time setup)"""
        cmd = ["cosign", "generate-key-pair"]

        env = os.environ.copy()
        if self.password:
            env["COSIGN_PASSWORD"] = self.password

        print(f"🔑 Generating Cosign key pair in {output_dir}...")

        try:
            subprocess.run(cmd, cwd=output_dir, env=env, check=True)
            print("✅ Key pair generated:")
            print(f"   - Private: {output_dir}/cosign.key (keep secret!)")
            print(f"   - Public: {output_dir}/cosign.pub (distribute)")
            print("\n⚠️  Store cosign.key in GitHub Secrets as COSIGN_PRIVATE_KEY")
            print("⚠️  Store password in GitHub Secrets as COSIGN_PASSWORD")

        except subprocess.CalledProcessError as e:
            print(f"❌ Key generation failed: {e}")
            raise

    def sign_file(self, file_path: str) -> str:
        """
        Sign a file using Cosign

        Args:
            file_path: Path to file to sign

        Returns:
            str: Path to signature file
        """
        if self.keyless:
            return self._sign_keyless(file_path)
        else:
            return self._sign_with_key(file_path)

    def _sign_with_key(self, file_path: str) -> str:
        """Sign using key-based signing"""
        cmd = ["cosign", "sign-blob", "--key", self.key_path, "--output-signature", f"{file_path}.sig", file_path]

        env = os.environ.copy()
        if self.password:
            env["COSIGN_PASSWORD"] = self.password

        print(f"✍️  Signing {file_path}...")

        try:
            subprocess.run(cmd, env=env, check=True)
            sig_path = f"{file_path}.sig"
            print(f"✅ Signature created: {sig_path}")
            return sig_path

        except subprocess.CalledProcessError as e:
            print(f"❌ Signing failed: {e}")
            raise

    def _sign_keyless(self, file_path: str) -> str:
        """Sign using keyless signing (Fulcio + Rekor)"""
        # Keyless signing requires OIDC auth, which is automatic in GitHub Actions
        print("⚠️  Keyless signing requires GitHub Actions or OIDC authentication")
        print("   For local testing, use key-based signing instead")
        raise NotImplementedError("Keyless signing requires CI/CD environment")

    def verify_signature(self, file_path: str, public_key_path: str) -> bool:
        """
        Verify a signed file

        Args:
            file_path: Path to signed file
            public_key_path: Path to public key

        Returns:
            bool: True if signature is valid
        """
        sig_path = f"{file_path}.sig"

        if not Path(sig_path).exists():
            print(f"❌ Signature file not found: {sig_path}")
            return False

        cmd = ["cosign", "verify-blob", "--key", public_key_path, "--signature", sig_path, file_path]

        print(f"🔍 Verifying signature for {file_path}...")

        try:
            subprocess.run(cmd, check=True, capture_output=True)
            print("✅ Signature valid")
            return True

        except subprocess.CalledProcessError:
            print("❌ Signature invalid or verification failed")
            return False


class SLSAProvenanceGenerator:
    """Generate SLSA provenance attestations"""

    def __init__(self, level: str = "L1"):
        """
        Initialize provenance generator

        Args:
            level: SLSA level (L1, L2, or L3)
        """
        self.level = level

    def generate_provenance(
        self, artifact_path: str, repo: str, commit_sha: str, build_config: Optional[dict] = None
    ) -> dict:
        """
        Generate SLSA provenance for an artifact

        Args:
            artifact_path: Path to build artifact
            repo: Repository name (e.g., 'org/repo')
            commit_sha: Git commit SHA
            build_config: Build configuration details

        Returns:
            Dict: SLSA provenance JSON
        """
        # Calculate artifact digest
        with open(artifact_path, "rb") as f:
            artifact_digest = hashlib.sha256(f.read()).hexdigest()

        # Base provenance (SLSA v1.0 spec)
        provenance = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": Path(artifact_path).name, "digest": {"sha256": artifact_digest}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://argus.dev/build-types/default@v1",
                    "externalParameters": {"repository": f"https://github.com/{repo}", "ref": commit_sha},
                    "internalParameters": build_config or {},
                    "resolvedDependencies": [],
                },
                "runDetails": {
                    "builder": {"id": "https://argus.dev/builder@v1", "version": {"argus": "1.0.0"}},
                    "metadata": {
                        "invocationId": f"build-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                        "startedOn": datetime.now().astimezone().isoformat(),
                        "finishedOn": datetime.now().astimezone().isoformat(),
                    },
                },
            },
        }

        # Add SLSA level metadata
        provenance["predicate"]["runDetails"]["metadata"]["slsaLevel"] = self.level

        return provenance

    def save_provenance(self, provenance: dict, output_path: str):
        """Save provenance to file"""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(provenance, f, indent=2)

        print(f"✅ SLSA {self.level} provenance saved: {output_path}")

    def generate_and_save(
        self, artifact_path: str, repo: str, commit_sha: str, output_path: str, build_config: Optional[dict] = None
    ) -> str:
        """Generate and save provenance in one call"""
        provenance = self.generate_provenance(artifact_path, repo, commit_sha, build_config)
        self.save_provenance(provenance, output_path)
        return output_path


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Sign releases and generate SLSA provenance (open source tools)")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Generate keypair command
    gen_parser = subparsers.add_parser("generate-key", help="Generate Cosign key pair")
    gen_parser.add_argument("-o", "--output-dir", default=".", help="Output directory for keys")

    # Sign command
    sign_parser = subparsers.add_parser("sign", help="Sign a file")
    sign_parser.add_argument("file", help="File to sign")
    sign_parser.add_argument("--key", help="Path to Cosign private key (optional for keyless)")

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a signature")
    verify_parser.add_argument("file", help="File to verify")
    verify_parser.add_argument("--public-key", required=True, help="Path to public key")

    # Provenance command
    prov_parser = subparsers.add_parser("provenance", help="Generate SLSA provenance")
    prov_parser.add_argument("artifact", help="Artifact to generate provenance for")
    prov_parser.add_argument("--repo", required=True, help="Repository (org/repo)")
    prov_parser.add_argument("--commit", required=True, help="Commit SHA")
    prov_parser.add_argument("--level", default="L1", choices=["L1", "L2", "L3"])
    prov_parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "generate-key":
        signer = ReleaseSigner()
        signer.generate_keypair(args.output_dir)

    elif args.command == "sign":
        signer = ReleaseSigner(key_path=args.key)
        signer.sign_file(args.file)

    elif args.command == "verify":
        signer = ReleaseSigner()
        valid = signer.verify_signature(args.file, args.public_key)
        exit(0 if valid else 1)

    elif args.command == "provenance":
        generator = SLSAProvenanceGenerator(level=args.level)
        output = args.output or f"{args.artifact}.provenance.json"
        generator.generate_and_save(args.artifact, args.repo, args.commit, output)


if __name__ == "__main__":
    main()
