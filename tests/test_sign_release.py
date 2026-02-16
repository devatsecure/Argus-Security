"""Tests for the Release Signing and SLSA Provenance module.

Covers ReleaseSigner and SLSAProvenanceGenerator: initialization,
key pair generation, file signing (key-based and keyless), signature
verification, provenance generation/saving, and edge cases.

All subprocess calls, file I/O, and environment variables are mocked.
"""

import hashlib
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.sign_release import ReleaseSigner, SLSAProvenanceGenerator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def signer():
    """Key-based signer with a dummy key path."""
    return ReleaseSigner(key_path="/path/to/cosign.key", password="testpass")


@pytest.fixture
def keyless_signer():
    """Keyless signer (no key_path provided)."""
    return ReleaseSigner()


@pytest.fixture
def provenance_gen():
    """Default SLSA provenance generator at level L1."""
    return SLSAProvenanceGenerator()


@pytest.fixture
def l3_provenance_gen():
    """SLSA provenance generator at level L3."""
    return SLSAProvenanceGenerator(level="L3")


@pytest.fixture
def sample_artifact(tmp_path):
    """Create a sample artifact file for testing."""
    artifact = tmp_path / "release-v1.0.0.tar.gz"
    artifact.write_bytes(b"fake artifact content for testing")
    return str(artifact)


# ---------------------------------------------------------------------------
# 1. ReleaseSigner Initialisation
# ---------------------------------------------------------------------------

class TestReleaseSignerInit:
    def test_key_based_init(self, signer):
        assert signer.key_path == "/path/to/cosign.key"
        assert signer.password == "testpass"
        assert signer.keyless is False

    def test_keyless_init(self, keyless_signer):
        assert keyless_signer.key_path is None
        assert keyless_signer.keyless is True

    def test_password_from_env(self):
        with patch.dict(os.environ, {"COSIGN_PASSWORD": "envpass"}):
            s = ReleaseSigner(key_path="/key")
            assert s.password == "envpass"

    def test_password_explicit_overrides_env(self):
        with patch.dict(os.environ, {"COSIGN_PASSWORD": "envpass"}):
            s = ReleaseSigner(key_path="/key", password="explicit")
            assert s.password == "explicit"

    def test_no_password_no_env(self):
        env = os.environ.copy()
        env.pop("COSIGN_PASSWORD", None)
        with patch.dict(os.environ, env, clear=True):
            s = ReleaseSigner(key_path="/key")
            assert s.password == ""


# ---------------------------------------------------------------------------
# 2. generate_keypair
# ---------------------------------------------------------------------------

class TestGenerateKeypair:
    @patch("scripts.sign_release.subprocess.run")
    def test_success(self, mock_run, signer):
        mock_run.return_value = MagicMock(returncode=0)
        signer.generate_keypair(output_dir="/tmp/keys")
        mock_run.assert_called_once()
        cmd_args = mock_run.call_args
        assert cmd_args.args[0] == ["cosign", "generate-key-pair"]
        assert cmd_args.kwargs["cwd"] == "/tmp/keys"
        assert cmd_args.kwargs["env"]["COSIGN_PASSWORD"] == "testpass"

    @patch("scripts.sign_release.subprocess.run")
    def test_default_output_dir(self, mock_run, signer):
        mock_run.return_value = MagicMock(returncode=0)
        signer.generate_keypair()
        cmd_args = mock_run.call_args
        assert cmd_args.kwargs["cwd"] == "."

    @patch("scripts.sign_release.subprocess.run")
    def test_failure_raises(self, mock_run, signer):
        mock_run.side_effect = subprocess.CalledProcessError(1, "cosign")
        with pytest.raises(subprocess.CalledProcessError):
            signer.generate_keypair()

    @patch("scripts.sign_release.subprocess.run")
    def test_env_contains_cosign_password(self, mock_run, signer):
        mock_run.return_value = MagicMock(returncode=0)
        signer.generate_keypair()
        env_passed = mock_run.call_args.kwargs["env"]
        assert "COSIGN_PASSWORD" in env_passed
        assert env_passed["COSIGN_PASSWORD"] == "testpass"

    @patch("scripts.sign_release.subprocess.run")
    def test_no_password_env_not_forced(self, mock_run):
        env = os.environ.copy()
        env.pop("COSIGN_PASSWORD", None)
        with patch.dict(os.environ, env, clear=True):
            s = ReleaseSigner(key_path="/key")
            mock_run.return_value = MagicMock(returncode=0)
            s.generate_keypair()
            env_passed = mock_run.call_args.kwargs["env"]
            # Password is empty string, so COSIGN_PASSWORD should NOT be set
            # (the if self.password guard in the code prevents it)
            assert "COSIGN_PASSWORD" not in env_passed


# ---------------------------------------------------------------------------
# 3. sign_file
# ---------------------------------------------------------------------------

class TestSignFile:
    @patch("scripts.sign_release.subprocess.run")
    def test_key_based_signing(self, mock_run, signer):
        mock_run.return_value = MagicMock(returncode=0)
        result = signer.sign_file("/path/to/artifact.tar.gz")
        assert result == "/path/to/artifact.tar.gz.sig"
        mock_run.assert_called_once()
        cmd = mock_run.call_args.args[0]
        assert "cosign" in cmd
        assert "sign-blob" in cmd
        assert "--key" in cmd
        assert "/path/to/cosign.key" in cmd

    @patch("scripts.sign_release.subprocess.run")
    def test_key_based_signing_failure(self, mock_run, signer):
        mock_run.side_effect = subprocess.CalledProcessError(1, "cosign")
        with pytest.raises(subprocess.CalledProcessError):
            signer.sign_file("/path/to/artifact.tar.gz")

    def test_keyless_signing_raises(self, keyless_signer):
        with pytest.raises(NotImplementedError, match="Keyless signing"):
            keyless_signer.sign_file("/path/to/artifact.tar.gz")

    @patch("scripts.sign_release.subprocess.run")
    def test_sign_file_routes_to_key_based(self, mock_run, signer):
        mock_run.return_value = MagicMock(returncode=0)
        signer.sign_file("/artifact")
        cmd = mock_run.call_args.args[0]
        assert "--key" in cmd

    @patch("scripts.sign_release.subprocess.run")
    def test_sign_file_output_signature_flag(self, mock_run, signer):
        mock_run.return_value = MagicMock(returncode=0)
        signer.sign_file("/my/file.bin")
        cmd = mock_run.call_args.args[0]
        assert "--output-signature" in cmd
        sig_idx = cmd.index("--output-signature")
        assert cmd[sig_idx + 1] == "/my/file.bin.sig"

    @patch("scripts.sign_release.subprocess.run")
    def test_sign_passes_password_in_env(self, mock_run, signer):
        mock_run.return_value = MagicMock(returncode=0)
        signer.sign_file("/artifact")
        env_passed = mock_run.call_args.kwargs["env"]
        assert env_passed["COSIGN_PASSWORD"] == "testpass"


# ---------------------------------------------------------------------------
# 4. _sign_keyless
# ---------------------------------------------------------------------------

class TestSignKeyless:
    def test_raises_not_implemented(self, keyless_signer):
        with pytest.raises(NotImplementedError, match="Keyless signing requires CI/CD"):
            keyless_signer._sign_keyless("/path/to/file")


# ---------------------------------------------------------------------------
# 5. verify_signature
# ---------------------------------------------------------------------------

class TestVerifySignature:
    @patch("scripts.sign_release.subprocess.run")
    @patch("scripts.sign_release.Path.exists", return_value=True)
    def test_valid_signature(self, mock_exists, mock_run, signer):
        mock_run.return_value = MagicMock(returncode=0)
        result = signer.verify_signature("/path/to/artifact", "/path/to/cosign.pub")
        assert result is True
        cmd = mock_run.call_args.args[0]
        assert "cosign" in cmd
        assert "verify-blob" in cmd
        assert "--key" in cmd
        assert "/path/to/cosign.pub" in cmd

    @patch("scripts.sign_release.subprocess.run")
    @patch("scripts.sign_release.Path.exists", return_value=True)
    def test_invalid_signature(self, mock_exists, mock_run, signer):
        mock_run.side_effect = subprocess.CalledProcessError(1, "cosign")
        result = signer.verify_signature("/path/to/artifact", "/path/to/cosign.pub")
        assert result is False

    @patch("scripts.sign_release.Path.exists", return_value=False)
    def test_missing_signature_file(self, mock_exists, signer):
        result = signer.verify_signature("/path/to/artifact", "/path/to/cosign.pub")
        assert result is False

    @patch("scripts.sign_release.subprocess.run")
    @patch("scripts.sign_release.Path.exists", return_value=True)
    def test_signature_path_convention(self, mock_exists, mock_run, signer):
        """Verify the .sig path convention is used."""
        mock_run.return_value = MagicMock(returncode=0)
        signer.verify_signature("/myfile.tar.gz", "/pub.key")
        cmd = mock_run.call_args.args[0]
        assert "/myfile.tar.gz.sig" in cmd


# ---------------------------------------------------------------------------
# 6. SLSAProvenanceGenerator Initialisation
# ---------------------------------------------------------------------------

class TestSLSAProvenanceGeneratorInit:
    def test_default_level(self, provenance_gen):
        assert provenance_gen.level == "L1"

    def test_custom_level(self, l3_provenance_gen):
        assert l3_provenance_gen.level == "L3"

    def test_l2_level(self):
        gen = SLSAProvenanceGenerator(level="L2")
        assert gen.level == "L2"


# ---------------------------------------------------------------------------
# 7. generate_provenance
# ---------------------------------------------------------------------------

class TestGenerateProvenance:
    def test_basic_provenance_structure(self, provenance_gen, sample_artifact):
        prov = provenance_gen.generate_provenance(
            artifact_path=sample_artifact,
            repo="acme/webapp",
            commit_sha="abc123def456",
        )
        assert prov["_type"] == "https://in-toto.io/Statement/v1"
        assert prov["predicateType"] == "https://slsa.dev/provenance/v1"
        assert len(prov["subject"]) == 1

    def test_subject_digest(self, provenance_gen, sample_artifact):
        with open(sample_artifact, "rb") as f:
            expected_digest = hashlib.sha256(f.read()).hexdigest()

        prov = provenance_gen.generate_provenance(sample_artifact, "org/repo", "abc")
        assert prov["subject"][0]["digest"]["sha256"] == expected_digest

    def test_subject_name(self, provenance_gen, sample_artifact):
        prov = provenance_gen.generate_provenance(sample_artifact, "org/repo", "abc")
        assert prov["subject"][0]["name"] == Path(sample_artifact).name

    def test_repo_url_in_provenance(self, provenance_gen, sample_artifact):
        prov = provenance_gen.generate_provenance(sample_artifact, "acme/webapp", "sha1")
        ext_params = prov["predicate"]["buildDefinition"]["externalParameters"]
        assert ext_params["repository"] == "https://github.com/acme/webapp"
        assert ext_params["ref"] == "sha1"

    def test_slsa_level_in_metadata(self, provenance_gen, sample_artifact):
        prov = provenance_gen.generate_provenance(sample_artifact, "org/repo", "abc")
        metadata = prov["predicate"]["runDetails"]["metadata"]
        assert metadata["slsaLevel"] == "L1"

    def test_l3_level_in_metadata(self, l3_provenance_gen, sample_artifact):
        prov = l3_provenance_gen.generate_provenance(sample_artifact, "org/repo", "abc")
        metadata = prov["predicate"]["runDetails"]["metadata"]
        assert metadata["slsaLevel"] == "L3"

    def test_build_config_included(self, provenance_gen, sample_artifact):
        config = {"python_version": "3.13", "os": "ubuntu-22.04"}
        prov = provenance_gen.generate_provenance(
            sample_artifact, "org/repo", "abc", build_config=config
        )
        internal = prov["predicate"]["buildDefinition"]["internalParameters"]
        assert internal == config

    def test_build_config_default_empty(self, provenance_gen, sample_artifact):
        prov = provenance_gen.generate_provenance(sample_artifact, "org/repo", "abc")
        internal = prov["predicate"]["buildDefinition"]["internalParameters"]
        assert internal == {}

    def test_builder_info(self, provenance_gen, sample_artifact):
        prov = provenance_gen.generate_provenance(sample_artifact, "org/repo", "abc")
        builder = prov["predicate"]["runDetails"]["builder"]
        assert builder["id"] == "https://argus.dev/builder@v1"
        assert "argus" in builder["version"]

    def test_invocation_id_format(self, provenance_gen, sample_artifact):
        prov = provenance_gen.generate_provenance(sample_artifact, "org/repo", "abc")
        inv_id = prov["predicate"]["runDetails"]["metadata"]["invocationId"]
        assert inv_id.startswith("build-")

    def test_timestamps_present(self, provenance_gen, sample_artifact):
        prov = provenance_gen.generate_provenance(sample_artifact, "org/repo", "abc")
        metadata = prov["predicate"]["runDetails"]["metadata"]
        assert "startedOn" in metadata
        assert "finishedOn" in metadata

    def test_resolved_dependencies_empty_by_default(self, provenance_gen, sample_artifact):
        prov = provenance_gen.generate_provenance(sample_artifact, "org/repo", "abc")
        deps = prov["predicate"]["buildDefinition"]["resolvedDependencies"]
        assert deps == []


# ---------------------------------------------------------------------------
# 8. save_provenance
# ---------------------------------------------------------------------------

class TestSaveProvenance:
    def test_saves_json_file(self, provenance_gen, tmp_path):
        provenance = {"_type": "test", "subject": []}
        out = str(tmp_path / "provenance.json")
        provenance_gen.save_provenance(provenance, out)
        assert Path(out).exists()
        with open(out) as f:
            data = json.load(f)
        assert data == provenance

    def test_creates_parent_dirs(self, provenance_gen, tmp_path):
        out = str(tmp_path / "deep" / "nested" / "provenance.json")
        provenance_gen.save_provenance({"test": True}, out)
        assert Path(out).exists()

    def test_json_is_indented(self, provenance_gen, tmp_path):
        out = str(tmp_path / "prov.json")
        provenance_gen.save_provenance({"key": "value"}, out)
        content = Path(out).read_text()
        assert "  " in content  # indented with 2 spaces

    def test_overwrites_existing_file(self, provenance_gen, tmp_path):
        out = str(tmp_path / "prov.json")
        provenance_gen.save_provenance({"version": 1}, out)
        provenance_gen.save_provenance({"version": 2}, out)
        with open(out) as f:
            data = json.load(f)
        assert data["version"] == 2


# ---------------------------------------------------------------------------
# 9. generate_and_save
# ---------------------------------------------------------------------------

class TestGenerateAndSave:
    def test_returns_output_path(self, provenance_gen, sample_artifact, tmp_path):
        out = str(tmp_path / "prov.json")
        result = provenance_gen.generate_and_save(
            artifact_path=sample_artifact,
            repo="org/repo",
            commit_sha="abc123",
            output_path=out,
        )
        assert result == out

    def test_file_created(self, provenance_gen, sample_artifact, tmp_path):
        out = str(tmp_path / "prov.json")
        provenance_gen.generate_and_save(sample_artifact, "org/repo", "abc", out)
        assert Path(out).exists()
        with open(out) as f:
            data = json.load(f)
        assert data["_type"] == "https://in-toto.io/Statement/v1"

    def test_with_build_config(self, provenance_gen, sample_artifact, tmp_path):
        out = str(tmp_path / "prov.json")
        config = {"ci": "github-actions"}
        provenance_gen.generate_and_save(
            sample_artifact, "org/repo", "abc", out, build_config=config
        )
        with open(out) as f:
            data = json.load(f)
        assert data["predicate"]["buildDefinition"]["internalParameters"] == config

    def test_digest_matches_artifact(self, provenance_gen, sample_artifact, tmp_path):
        out = str(tmp_path / "prov.json")
        provenance_gen.generate_and_save(sample_artifact, "org/repo", "abc", out)

        with open(sample_artifact, "rb") as f:
            expected = hashlib.sha256(f.read()).hexdigest()

        with open(out) as f:
            data = json.load(f)
        assert data["subject"][0]["digest"]["sha256"] == expected


# ---------------------------------------------------------------------------
# 10. Integration: sign + provenance workflow
# ---------------------------------------------------------------------------

class TestIntegrationWorkflow:
    @patch("scripts.sign_release.subprocess.run")
    def test_sign_then_provenance(self, mock_run, sample_artifact, tmp_path):
        """Simulate a typical release workflow: sign artifact, then generate provenance."""
        mock_run.return_value = MagicMock(returncode=0)

        # Sign
        signer = ReleaseSigner(key_path="/key", password="pw")
        sig_path = signer.sign_file(sample_artifact)
        assert sig_path.endswith(".sig")

        # Generate provenance
        gen = SLSAProvenanceGenerator(level="L2")
        out = str(tmp_path / "provenance.json")
        gen.generate_and_save(sample_artifact, "acme/webapp", "deadbeef", out)

        with open(out) as f:
            prov = json.load(f)
        assert prov["predicate"]["runDetails"]["metadata"]["slsaLevel"] == "L2"

    @patch("scripts.sign_release.subprocess.run")
    @patch("scripts.sign_release.Path.exists", return_value=True)
    def test_sign_verify_roundtrip(self, mock_exists, mock_run, sample_artifact):
        """Sign then verify should succeed when cosign succeeds."""
        mock_run.return_value = MagicMock(returncode=0)

        signer = ReleaseSigner(key_path="/key", password="pw")
        sig = signer.sign_file(sample_artifact)
        assert sig.endswith(".sig")

        valid = signer.verify_signature(sample_artifact, "/key.pub")
        assert valid is True


# ---------------------------------------------------------------------------
# 11. Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_artifact_with_spaces_in_path(self, provenance_gen, tmp_path):
        artifact = tmp_path / "my release (1).tar.gz"
        artifact.write_bytes(b"content")
        prov = provenance_gen.generate_provenance(str(artifact), "org/repo", "abc")
        assert prov["subject"][0]["name"] == "my release (1).tar.gz"

    def test_empty_artifact(self, provenance_gen, tmp_path):
        artifact = tmp_path / "empty.tar.gz"
        artifact.write_bytes(b"")
        prov = provenance_gen.generate_provenance(str(artifact), "org/repo", "abc")
        expected = hashlib.sha256(b"").hexdigest()
        assert prov["subject"][0]["digest"]["sha256"] == expected

    @patch("scripts.sign_release.subprocess.run")
    def test_sign_large_path(self, mock_run, signer):
        mock_run.return_value = MagicMock(returncode=0)
        long_path = "/very/" + "long/" * 50 + "artifact.tar.gz"
        result = signer.sign_file(long_path)
        assert result == long_path + ".sig"

    def test_generate_provenance_file_not_found(self, provenance_gen):
        with pytest.raises(FileNotFoundError):
            provenance_gen.generate_provenance("/nonexistent/file.tar.gz", "org/repo", "abc")

    def test_signer_keyless_flag_true(self):
        s = ReleaseSigner()
        assert s.keyless is True

    def test_signer_keyless_flag_false(self):
        s = ReleaseSigner(key_path="/some/key")
        assert s.keyless is False

    @patch("scripts.sign_release.subprocess.run")
    def test_generate_keypair_preserves_existing_env(self, mock_run, signer):
        """Ensure generate_keypair copies the existing environment."""
        mock_run.return_value = MagicMock(returncode=0)
        with patch.dict(os.environ, {"MY_VAR": "my_value"}):
            signer.generate_keypair()
            env_passed = mock_run.call_args.kwargs["env"]
            assert env_passed.get("MY_VAR") == "my_value"

    def test_provenance_build_type(self, provenance_gen, sample_artifact):
        prov = provenance_gen.generate_provenance(sample_artifact, "org/repo", "abc")
        build_type = prov["predicate"]["buildDefinition"]["buildType"]
        assert build_type == "https://argus.dev/build-types/default@v1"
