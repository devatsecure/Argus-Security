"""
Whole-Repo LLM Security Review (Phase 2.8)

Sends source code directly to LLM for security review, independent of scanner
findings. This catches vulnerabilities that SAST scanners don't have rules for:
- Unsafe deserialization (torch.load, pickle)
- Supply chain risks (trust_remote_code)
- Missing authentication/authorization
- Business logic flaws
- Architecture-level security gaps

The source files are chunked to fit LLM context windows and reviewed in parallel.
Findings are deduplicated against existing scanner findings before merging.
"""

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Security-relevant file extensions
_SECURITY_RELEVANT_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb",
    ".yml", ".yaml", ".json", ".tf", ".hcl", ".sh", ".bash",
    ".dockerfile", ".toml", ".cfg", ".ini", ".env",
}

# Files to always skip
_SKIP_PATTERNS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "build", "dist", ".egg-info", ".tox", ".mypy_cache",
}

# Maximum chars per LLM chunk (~4K tokens)
MAX_CHUNK_CHARS = 16000

# Maximum files to review (prevent cost explosion on huge repos)
MAX_FILES = 100

REVIEW_PROMPT = """You are an expert security code reviewer. Analyze the following source code for security vulnerabilities.

For EACH vulnerability found, respond in this EXACT JSON format:
```json
[
  {{
    "file": "path/to/file.py",
    "line": 42,
    "cwe": "CWE-502",
    "severity": "high",
    "title": "Short title",
    "description": "Detailed description of the vulnerability",
    "recommendation": "How to fix it"
  }}
]
```

Focus on:
- Command injection (subprocess, shell=True, os.system)
- Deserialization attacks (pickle, torch.load, weights_only, yaml.load)
- Supply chain risks (trust_remote_code, downloading/executing remote code)
- Missing authentication/authorization on endpoints
- Missing security headers (CORS, CSP, HSTS)
- SSRF / URL injection
- Path traversal
- Hardcoded secrets/credentials
- Denial of service (no input size limits)
- Unsafe file operations

If no vulnerabilities found, respond with: []

Source code to review:

{code}"""


@dataclass
class LLMFinding:
    """A security finding discovered by whole-repo LLM review."""
    file_path: str
    line_number: int
    cwe_id: str
    severity: str
    title: str
    description: str
    recommendation: str


class WholeRepoReviewer:
    """Sends source code directly to LLM for security review."""

    def __init__(self, llm_manager, config: Optional[dict] = None):
        self.llm = llm_manager
        self.config = config or {}
        self.max_files = self.config.get("whole_repo_max_files", MAX_FILES)
        self.max_chunk_chars = self.config.get("whole_repo_chunk_size", MAX_CHUNK_CHARS)

    def _collect_files(self, target_path: str) -> list[dict]:
        """Collect security-relevant source files from the repo."""
        target = Path(target_path)
        files = []

        for fp in sorted(target.rglob("*")):
            if not fp.is_file():
                continue
            if any(skip in fp.parts for skip in _SKIP_PATTERNS):
                continue
            if fp.suffix.lower() not in _SECURITY_RELEVANT_EXTS:
                continue

            try:
                content = fp.read_text(errors="ignore")
                if not content.strip():
                    continue
                # Skip very large files (likely generated/vendored)
                if len(content) > 50000:
                    logger.debug("Skipping large file: %s (%d bytes)", fp, len(content))
                    continue

                rel_path = str(fp.relative_to(target))
                files.append({"path": rel_path, "content": content, "size": len(content)})
            except Exception:
                continue

            if len(files) >= self.max_files:
                logger.info("Reached max files limit (%d), stopping collection", self.max_files)
                break

        return files

    def _build_chunks(self, files: list[dict]) -> list[str]:
        """Group files into chunks that fit LLM context."""
        chunks = []
        current_chunk = ""

        for f in files:
            file_block = f"\n### {f['path']}\n```\n{f['content']}\n```\n"

            if len(current_chunk) + len(file_block) > self.max_chunk_chars:
                if current_chunk:
                    chunks.append(current_chunk)
                # If single file is larger than chunk size, truncate
                if len(file_block) > self.max_chunk_chars:
                    file_block = file_block[:self.max_chunk_chars] + "\n... [truncated]\n```\n"
                current_chunk = file_block
            else:
                current_chunk += file_block

        if current_chunk:
            chunks.append(current_chunk)

        return chunks

    def _parse_findings(self, response: str, chunk_index: int) -> list[LLMFinding]:
        """Parse LLM response into structured findings."""
        import json
        import re

        if not response:
            return []

        # Extract JSON from response (handle markdown code blocks)
        json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', response, re.DOTALL)
        json_str = json_match.group(1) if json_match else response.strip()

        # Try to find JSON array
        bracket_start = json_str.find('[')
        bracket_end = json_str.rfind(']')
        if bracket_start >= 0 and bracket_end > bracket_start:
            json_str = json_str[bracket_start:bracket_end + 1]

        try:
            data = json.loads(json_str)
            if not isinstance(data, list):
                data = [data]
        except json.JSONDecodeError:
            logger.debug("Chunk %d: Could not parse LLM response as JSON", chunk_index)
            return []

        findings = []
        for item in data:
            if not isinstance(item, dict):
                continue
            try:
                findings.append(LLMFinding(
                    file_path=item.get("file", "unknown"),
                    line_number=int(item.get("line", 0)),
                    cwe_id=item.get("cwe", ""),
                    severity=item.get("severity", "medium").lower(),
                    title=item.get("title", "LLM-discovered finding"),
                    description=item.get("description", ""),
                    recommendation=item.get("recommendation", ""),
                ))
            except (ValueError, TypeError) as e:
                logger.debug("Skipping malformed finding: %s", e)

        return findings

    def review(self, target_path: str) -> list[LLMFinding]:
        """Run whole-repo LLM security review.

        Args:
            target_path: Path to the repository to review

        Returns:
            List of LLM-discovered security findings
        """
        start = time.time()

        # Collect files
        files = self._collect_files(target_path)
        if not files:
            logger.info("No security-relevant files found for LLM review")
            return []

        logger.info("Whole-repo LLM review: %d files collected (%d bytes total)",
                     len(files), sum(f["size"] for f in files))

        # Build chunks
        chunks = self._build_chunks(files)
        logger.info("Split into %d chunks for LLM review", len(chunks))

        # Review each chunk
        all_findings: list[LLMFinding] = []
        for i, chunk in enumerate(chunks):
            try:
                prompt = REVIEW_PROMPT.format(code=chunk)
                response, _in, _out = self.llm.call_llm_api(
                    prompt, max_tokens=2000, phase="deep_analysis"
                )
                chunk_findings = self._parse_findings(response, i)
                all_findings.extend(chunk_findings)
                logger.info("  Chunk %d/%d: %d findings", i + 1, len(chunks), len(chunk_findings))
            except Exception as e:
                logger.warning("  Chunk %d/%d failed: %s", i + 1, len(chunks), e)

        duration = time.time() - start
        logger.info("Whole-repo LLM review complete: %d findings in %.1fs", len(all_findings), duration)

        return all_findings
