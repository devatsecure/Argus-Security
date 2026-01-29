#!/usr/bin/env python3
"""
Test suite for File Metadata Validator
Tests metadata-driven file permission validation when files are not accessible
"""

import os
import tempfile
from pathlib import Path

import pytest

from scripts.file_metadata_validator import FileMetadataValidator, MetadataValidationResult


class TestFileMetadataValidator:
    """Test the FileMetadataValidator class"""

    @pytest.fixture
    def temp_repo(self):
        """Create a temporary repository structure for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)

            # Create basic directory structure
            (repo_path / ".git").mkdir()
            (repo_path / "src").mkdir()
            (repo_path / "tests").mkdir()
            (repo_path / ".github").mkdir()
            (repo_path / ".github" / "workflows").mkdir()

            yield repo_path

    def test_no_metadata_available(self, temp_repo):
        """Test validation when no metadata files exist"""
        validator = FileMetadataValidator(repo_root=str(temp_repo))

        result = validator.validate_from_metadata("some/file.py")

        assert result.has_metadata == False
        assert result.confidence == 0.0
        assert len(result.sources) == 0
        assert "No metadata available" in result.reasoning

    def test_gitattributes_secret_filter(self, temp_repo):
        """Test detection of secret filter in .gitattributes"""
        gitattributes = temp_repo / ".gitattributes"
        gitattributes.write_text("config/secrets.yml filter=secret\n")

        validator = FileMetadataValidator(repo_root=str(temp_repo))
        result = validator.validate_from_metadata("config/secrets.yml")

        assert result.has_metadata == True
        assert ".gitattributes" in result.sources
        assert any("secret" in indicator.lower() for indicator in result.permission_indicators)
        assert result.confidence > 0.0

    def test_gitattributes_encryption(self, temp_repo):
        """Test detection of encryption in .gitattributes"""
        gitattributes = temp_repo / ".gitattributes"
        gitattributes.write_text("*.key crypt\npasswords.txt diff=crypt\n")

        validator = FileMetadataValidator(repo_root=str(temp_repo))

        # Test encrypted file
        result = validator.validate_from_metadata("private.key")
        assert result.has_metadata == True
        assert any("crypt" in indicator.lower() for indicator in result.permission_indicators)

        # Test diff=crypt
        result = validator.validate_from_metadata("passwords.txt")
        assert result.has_metadata == True
        assert any("diff" in indicator.lower() for indicator in result.permission_indicators)

    def test_gitignore_exclusion(self, temp_repo):
        """Test detection of files in .gitignore"""
        gitignore = temp_repo / ".gitignore"
        gitignore.write_text("*.log\n.env\nnode_modules/\n")

        validator = FileMetadataValidator(repo_root=str(temp_repo))

        # Test ignored file
        result = validator.validate_from_metadata("debug.log")
        assert result.has_metadata == True
        assert ".gitignore/.dockerignore" in result.sources
        assert any("Excluded" in indicator for indicator in result.permission_indicators)

    def test_dockerignore_exclusion(self, temp_repo):
        """Test detection of files in .dockerignore"""
        dockerignore = temp_repo / ".dockerignore"
        dockerignore.write_text(".git\n*.md\ntests/\n")

        validator = FileMetadataValidator(repo_root=str(temp_repo))

        # Test ignored directory
        result = validator.validate_from_metadata("tests/test_file.py")
        assert result.has_metadata == True
        assert any("Excluded" in indicator for indicator in result.permission_indicators)

    def test_precommit_hooks_detection(self, temp_repo):
        """Test detection of pre-commit security hooks"""
        precommit = temp_repo / ".pre-commit-config.yaml"
        precommit.write_text("""
repos:
  - repo: https://github.com/trufflesecurity/trufflehog
    hooks:
      - id: trufflehog
  - repo: https://github.com/gitleaks/gitleaks
    hooks:
      - id: gitleaks
  - repo: https://github.com/Yelp/detect-secrets
    hooks:
      - id: detect-secrets
  - repo: local
    hooks:
      - id: check-added-large-files
""")

        validator = FileMetadataValidator(repo_root=str(temp_repo))
        result = validator.validate_from_metadata("config/database.yml")

        assert result.has_metadata == True
        assert ".pre-commit-config.yaml" in result.sources
        assert any("secret scanning" in indicator.lower() for indicator in result.permission_indicators)
        assert any("large files" in indicator.lower() for indicator in result.permission_indicators)
        assert result.confidence >= 0.20  # Pre-commit hooks add 0.20 confidence

    def test_deployment_config_chmod(self, temp_repo):
        """Test detection of chmod in deployment configs"""
        dockerfile = temp_repo / "Dockerfile"
        dockerfile.write_text("""
FROM python:3.9
COPY config/secrets.json /app/secrets.json
RUN chmod 600 /app/secrets.json
RUN chown app:app /app/secrets.json
""")

        validator = FileMetadataValidator(repo_root=str(temp_repo))
        result = validator.validate_from_metadata("config/secrets.json")

        assert result.has_metadata == True
        assert "deployment configs" in result.sources
        # Note: This would require the relative path to be in the Dockerfile
        # In this test, we're checking the pattern detection works

    def test_deployment_secrets_mounting(self, temp_repo):
        """Test detection of secrets mounting in docker-compose"""
        docker_compose = temp_repo / "docker-compose.yml"
        docker_compose.write_text("""
version: '3.8'
services:
  app:
    image: myapp
    secrets:
      - db_password
      - api_key
secrets:
  db_password:
    file: ./secrets/db_password.txt
  api_key:
    file: ./secrets/api_key.txt
""")

        validator = FileMetadataValidator(repo_root=str(temp_repo))
        result = validator.validate_from_metadata("./secrets/db_password.txt")

        assert result.has_metadata == True
        assert "deployment configs" in result.sources
        assert any("secret" in indicator.lower() for indicator in result.permission_indicators)

    def test_github_workflow_secrets(self, temp_repo):
        """Test detection of secrets in GitHub workflows"""
        workflow = temp_repo / ".github" / "workflows" / "deploy.yml"
        workflow.write_text("""
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy with secrets
        env:
          API_KEY: ${{ secrets.API_KEY }}
          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
        run: |
          chmod 600 config/prod.env
          ./deploy.sh
""")

        validator = FileMetadataValidator(repo_root=str(temp_repo))
        result = validator.validate_from_metadata("config/prod.env")

        assert result.has_metadata == True
        assert "deployment configs" in result.sources
        assert any("Permission setting" in indicator for indicator in result.permission_indicators)

    def test_security_policy_reference(self, temp_repo):
        """Test detection of files referenced in SECURITY.md"""
        security_md = temp_repo / "SECURITY.md"
        security_md.write_text("""
# Security Policy

## Sensitive Files

The following files contain sensitive data and should never be committed:
- config/database.yml
- .env
- secrets/api_keys.txt

Please ensure these files have proper permissions (600 or 400).
""")

        validator = FileMetadataValidator(repo_root=str(temp_repo))
        result = validator.validate_from_metadata("config/database.yml")

        assert result.has_metadata == True
        assert "security policies" in result.sources
        assert any("Referenced in" in indicator for indicator in result.permission_indicators)

    def test_multiple_sources_high_confidence(self, temp_repo):
        """Test validation with multiple metadata sources (high confidence)"""
        # Set up multiple metadata sources
        gitattributes = temp_repo / ".gitattributes"
        gitattributes.write_text("secrets.yml filter=secret\n")

        precommit = temp_repo / ".pre-commit-config.yaml"
        precommit.write_text("""
repos:
  - repo: https://github.com/gitleaks/gitleaks
    hooks:
      - id: gitleaks
""")

        dockerfile = temp_repo / "Dockerfile"
        dockerfile.write_text("RUN chmod 600 secrets.yml\n")

        validator = FileMetadataValidator(repo_root=str(temp_repo))
        result = validator.validate_from_metadata("secrets.yml")

        assert result.has_metadata == True
        assert len(result.sources) >= 2
        # 0.15 (gitattributes) + 0.20 (precommit) + 0.15 (deployment) = 0.50
        assert result.confidence >= 0.5
        assert "Strong metadata evidence" in result.reasoning

    def test_confidence_capped_at_070(self, temp_repo):
        """Test that metadata confidence is capped at 0.7"""
        # Set up all possible metadata sources
        gitattributes = temp_repo / ".gitattributes"
        gitattributes.write_text("secrets.yml filter=secret diff=crypt\n")

        gitignore = temp_repo / ".gitignore"
        gitignore.write_text("*.log\n")

        precommit = temp_repo / ".pre-commit-config.yaml"
        precommit.write_text("""
repos:
  - repo: https://github.com/gitleaks/gitleaks
  - repo: https://github.com/trufflesecurity/trufflehog
  - repo: https://github.com/Yelp/detect-secrets
""")

        dockerfile = temp_repo / "Dockerfile"
        dockerfile.write_text("RUN chmod 600 secrets.yml\n")

        security_md = temp_repo / "SECURITY.md"
        security_md.write_text("Protect secrets.yml\n")

        validator = FileMetadataValidator(repo_root=str(temp_repo))
        result = validator.validate_from_metadata("secrets.yml")

        # Should be capped at 0.7 even with all sources
        assert result.confidence <= 0.7
        assert result.has_metadata == True

    def test_path_normalization(self, temp_repo):
        """Test path normalization relative to repo root"""
        validator = FileMetadataValidator(repo_root=str(temp_repo))

        # Test absolute path normalization
        abs_path = str(temp_repo / "src" / "config.py")
        normalized = validator._normalize_path(abs_path)
        assert normalized == "src/config.py" or normalized == str(Path("src/config.py"))

        # Test relative path
        rel_path = "src/config.py"
        normalized = validator._normalize_path(rel_path)
        assert "config.py" in normalized

    def test_ignore_pattern_matching(self, temp_repo):
        """Test gitignore pattern matching"""
        gitignore = temp_repo / ".gitignore"
        gitignore.write_text("""
# Python
*.pyc
__pycache__/
.env

# Node
node_modules/
*.log

# IDE
.vscode/
.idea/
""")

        validator = FileMetadataValidator(repo_root=str(temp_repo))

        # Test direct file match
        result = validator.validate_from_metadata("app.pyc")
        assert result.has_metadata == True

        # Test directory match
        result = validator.validate_from_metadata("node_modules/package/file.js")
        assert result.has_metadata == True

    def test_confidence_levels_reasoning(self, temp_repo):
        """Test different confidence levels produce appropriate reasoning"""
        validator = FileMetadataValidator(repo_root=str(temp_repo))

        # No metadata (confidence 0.0)
        result = validator.validate_from_metadata("unknown.txt")
        assert "No metadata available" in result.reasoning

        # Low confidence (0.1-0.29)
        gitignore = temp_repo / ".gitignore"
        gitignore.write_text("*.log\n")
        result = validator.validate_from_metadata("debug.log")
        assert result.confidence < 0.3
        assert "Weak metadata evidence" in result.reasoning

        # Medium confidence (0.3-0.49)
        precommit = temp_repo / ".pre-commit-config.yaml"
        precommit.write_text("repos:\n  - repo: gitleaks\n")
        result = validator.validate_from_metadata("config.yml")
        if 0.3 <= result.confidence < 0.5:
            assert "Moderate metadata evidence" in result.reasoning

        # High confidence (0.5+)
        gitattributes = temp_repo / ".gitattributes"
        gitattributes.write_text("secrets.yml filter=secret\n")
        result = validator.validate_from_metadata("secrets.yml")
        if result.confidence >= 0.5:
            assert "Strong metadata evidence" in result.reasoning


class TestFileMetadataValidatorIntegration:
    """Integration tests with EnhancedFalsePositiveDetector"""

    @pytest.fixture
    def temp_repo(self):
        """Create a temporary repository structure for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            (repo_path / ".git").mkdir()
            yield repo_path

    def test_integration_with_enhanced_fp_detector(self, temp_repo):
        """Test that FileMetadataValidator integrates with EnhancedFalsePositiveDetector"""
        from scripts.enhanced_fp_detector import EnhancedFalsePositiveDetector

        # Set up metadata
        precommit = temp_repo / ".pre-commit-config.yaml"
        precommit.write_text("""
repos:
  - repo: https://github.com/gitleaks/gitleaks
    hooks:
      - id: gitleaks
""")

        # Change working directory to temp repo
        original_cwd = os.getcwd()
        try:
            os.chdir(temp_repo)

            detector = EnhancedFalsePositiveDetector()

            # Create a finding for a non-existent file
            finding = {
                "path": "config/secrets.yml",
                "file_path": "config/secrets.yml",
                "message": "Plaintext storage of sensitive data",
                "evidence": {
                    "snippet": "api_key: secret123"
                }
            }

            result = detector.analyze_file_permissions(finding)

            # Should use metadata validation since file doesn't exist
            assert result.category == "file_permissions_metadata"
            assert "metadata" in result.reasoning.lower() or "Sources checked" in str(result.evidence)

        finally:
            os.chdir(original_cwd)

    def test_fallback_when_file_not_accessible(self, temp_repo):
        """Test that metadata validation is used when file doesn't exist"""
        from scripts.enhanced_fp_detector import EnhancedFalsePositiveDetector

        gitattributes = temp_repo / ".gitattributes"
        gitattributes.write_text("remote/file.key filter=secret\n")

        original_cwd = os.getcwd()
        try:
            os.chdir(temp_repo)

            detector = EnhancedFalsePositiveDetector()

            # Finding for non-existent remote file
            finding = {
                "path": "remote/file.key",
                "file_path": "remote/file.key",
                "message": "Hardcoded encryption key",
            }

            result = detector.analyze_file_permissions(finding)

            # Should use metadata validation
            assert result.category == "file_permissions_metadata"
            assert result.confidence <= 0.7  # Metadata confidence capped
            assert len(result.evidence) > 0

        finally:
            os.chdir(original_cwd)

    def test_direct_file_check_preferred_over_metadata(self, temp_repo):
        """Test that direct file check is preferred when file exists"""
        from scripts.enhanced_fp_detector import EnhancedFalsePositiveDetector

        # Create an actual file with restricted permissions
        config_file = temp_repo / "config.yml"
        config_file.write_text("api_key: secret")
        config_file.chmod(0o600)

        original_cwd = os.getcwd()
        try:
            os.chdir(temp_repo)

            detector = EnhancedFalsePositiveDetector()

            finding = {
                "path": str(config_file),
                "file_path": str(config_file),
                "message": "Hardcoded API key",
            }

            result = detector.analyze_file_permissions(finding)

            # Should use direct file check, not metadata
            assert result.category == "file_permissions"
            assert "File permissions: 0o600" in result.evidence or "0o600" in str(result.evidence)

        finally:
            os.chdir(original_cwd)


class TestEdgeCases:
    """Test edge cases and error handling"""

    @pytest.fixture
    def temp_repo(self):
        """Create a temporary repository structure for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            (repo_path / ".git").mkdir()
            yield repo_path

    def test_malformed_gitattributes(self, temp_repo):
        """Test handling of malformed .gitattributes"""
        gitattributes = temp_repo / ".gitattributes"
        gitattributes.write_text("invalid syntax here\n????\n")

        validator = FileMetadataValidator(repo_root=str(temp_repo))
        result = validator.validate_from_metadata("any/file.txt")

        # Should not crash, just return no metadata
        assert isinstance(result, MetadataValidationResult)

    def test_empty_metadata_files(self, temp_repo):
        """Test handling of empty metadata files"""
        gitignore = temp_repo / ".gitignore"
        gitignore.write_text("")

        precommit = temp_repo / ".pre-commit-config.yaml"
        precommit.write_text("")

        validator = FileMetadataValidator(repo_root=str(temp_repo))
        result = validator.validate_from_metadata("file.txt")

        assert result.has_metadata == False
        assert result.confidence == 0.0

    def test_nonexistent_repo_root(self):
        """Test handling of non-existent repo root"""
        validator = FileMetadataValidator(repo_root="/nonexistent/path")
        result = validator.validate_from_metadata("file.txt")

        # Should not crash
        assert isinstance(result, MetadataValidationResult)
        assert result.has_metadata == False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
