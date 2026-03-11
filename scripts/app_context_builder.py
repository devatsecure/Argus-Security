#!/usr/bin/env python3
"""
Application Context Builder for Argus Security Pipeline.

Builds a unified application context model by inspecting the target project's
file structure, dependency manifests, import patterns, and infrastructure
configuration.  The resulting ``ApplicationContext`` is consumed by all six
pipeline phases so that scanners, AI enrichment, and policy gates can tailor
their behaviour to the specific technology stack.

Detection methods are designed for speed: file-count caps, early exits, and
glob-based discovery keep wall-clock time under a few hundred milliseconds
even on large mono-repos.

Usage:
    builder = AppContextBuilder("/path/to/project")
    ctx = builder.build()
    print(ctx.to_prompt_context())
"""

from __future__ import annotations

import glob
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["ApplicationContext", "AppContextBuilder"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Limits – keep detection fast on large repositories
# ---------------------------------------------------------------------------

_MAX_FILES_FOR_IMPORTS = 100
_MAX_FILES_FOR_AUTH = 200

# ---------------------------------------------------------------------------
# File-extension-to-language mapping
# ---------------------------------------------------------------------------

_EXTENSION_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
}

# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------


@dataclass
class ApplicationContext:
    """Unified application context fed to all pipeline phases."""

    # Code structure
    framework: str = "unknown"
    language: str = "unknown"
    entry_points: list[str] = field(default_factory=list)
    auth_mechanism: str = "unknown"

    # API surface
    api_endpoints: list[dict] = field(default_factory=list)
    middleware_chain: list[str] = field(default_factory=list)

    # Infrastructure
    cloud_provider: str = "none"
    iac_files: list[str] = field(default_factory=list)
    has_dockerfile: bool = False
    has_k8s: bool = False

    # Dependencies
    dependency_files: list[str] = field(default_factory=list)

    # DAST context
    deployment_url: str | None = None
    openapi_spec_path: str | None = None

    def to_dict(self) -> dict:
        """Serialise the context to a plain dictionary."""
        return {
            "framework": self.framework,
            "language": self.language,
            "entry_points": self.entry_points,
            "auth_mechanism": self.auth_mechanism,
            "api_endpoints": self.api_endpoints,
            "middleware_chain": self.middleware_chain,
            "cloud_provider": self.cloud_provider,
            "iac_files": self.iac_files,
            "has_dockerfile": self.has_dockerfile,
            "has_k8s": self.has_k8s,
            "dependency_files": self.dependency_files,
            "deployment_url": self.deployment_url,
            "openapi_spec_path": self.openapi_spec_path,
        }

    def to_prompt_context(self) -> str:
        """Format as a string suitable for LLM prompt injection."""
        lines = [
            "Application Context:",
            f"- Language: {self.language}",
            f"- Framework: {self.framework}",
            f"- Auth mechanism: {self.auth_mechanism}",
            f"- Cloud: {self.cloud_provider}",
            f"- Entry points: {len(self.entry_points)} files",
        ]

        # Summarise IaC files by type rather than listing every path.
        if self.iac_files:
            tf_count = sum(1 for f in self.iac_files if f.endswith((".tf", ".tfvars")))
            docker_count = sum(
                1 for f in self.iac_files if "dockerfile" in os.path.basename(f).lower() or f.endswith((".dockerfile",))
            )
            compose_count = sum(1 for f in self.iac_files if "docker-compose" in os.path.basename(f).lower())
            k8s_count = sum(
                1
                for f in self.iac_files
                if f.endswith((".yml", ".yaml")) and "docker-compose" not in os.path.basename(f).lower()
            )
            parts: list[str] = []
            if tf_count:
                parts.append(f"{tf_count} terraform")
            if docker_count:
                parts.append(f"{docker_count} dockerfile")
            if compose_count:
                parts.append(f"{compose_count} compose")
            if k8s_count:
                parts.append(f"{k8s_count} k8s/helm")
            label = ", ".join(parts) if parts else f"{len(self.iac_files)} files"
            lines.append(f"- IaC: {label}")
        else:
            lines.append("- IaC: none")

        if self.middleware_chain:
            lines.append(f"- Middleware: {', '.join(self.middleware_chain)}")

        lines.append(f"- Has Dockerfile: {'yes' if self.has_dockerfile else 'no'}")
        lines.append(f"- Has Kubernetes: {'yes' if self.has_k8s else 'no'}")

        if self.openapi_spec_path:
            lines.append(f"- OpenAPI spec: {self.openapi_spec_path}")

        if self.dependency_files:
            lines.append(f"- Dependency files: {', '.join(self.dependency_files)}")

        if self.api_endpoints:
            lines.append(f"- API endpoints detected: {len(self.api_endpoints)}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class AppContextBuilder:
    """Inspect a project directory and assemble an ``ApplicationContext``.

    All detection methods are intentionally capped (file count limits, early
    exits) so that even very large repositories are processed quickly.
    """

    def __init__(self, project_path: str) -> None:
        self._root = Path(project_path).resolve()
        logger.debug("AppContextBuilder initialised for %s", self._root)

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def build(self) -> ApplicationContext:
        """Orchestrate all detection methods and return the assembled context."""
        logger.info("Building application context for %s", self._root)

        language = self._detect_language()
        framework = self._detect_framework(language)
        iac_files = self._find_iac_files()
        has_dockerfile = any("dockerfile" in os.path.basename(f).lower() for f in iac_files)

        ctx = ApplicationContext(
            language=language,
            framework=framework,
            entry_points=self._find_entry_points(),
            auth_mechanism=self._detect_auth(),
            middleware_chain=self._detect_middleware(),
            cloud_provider=self._detect_cloud(),
            iac_files=iac_files,
            has_dockerfile=has_dockerfile,
            has_k8s=self._has_k8s(),
            dependency_files=self._find_dependency_files(),
            openapi_spec_path=self._find_openapi_spec(),
        )

        logger.info(
            "Context built: language=%s framework=%s auth=%s cloud=%s",
            ctx.language,
            ctx.framework,
            ctx.auth_mechanism,
            ctx.cloud_provider,
        )
        return ctx

    # ------------------------------------------------------------------
    # Language detection
    # ------------------------------------------------------------------

    def _detect_language(self) -> str:
        """Count source files by extension and return the dominant language."""
        counts: dict[str, int] = {}
        for ext, lang in _EXTENSION_LANGUAGE.items():
            pattern = os.path.join(str(self._root), "**", f"*{ext}")
            # Use glob.iglob to avoid materialising huge lists; cap at a
            # reasonable number so we don't spend minutes on mono-repos.
            count = 0
            for _ in glob.iglob(pattern, recursive=True):
                count += 1
                if count >= 5000:
                    break
            if count:
                counts[lang] = counts.get(lang, 0) + count

        if not counts:
            logger.debug("No recognised source files found")
            return "unknown"

        dominant = max(counts, key=lambda k: counts[k])
        logger.debug("Language counts: %s -> dominant=%s", counts, dominant)
        return dominant

    # ------------------------------------------------------------------
    # Framework detection
    # ------------------------------------------------------------------

    def _detect_framework(self, language: str) -> str:
        """Check for framework indicators based on the detected language."""
        detectors: dict[str, callable] = {
            "python": self._detect_python_framework,
            "javascript": self._detect_js_framework,
            "typescript": self._detect_js_framework,
            "java": self._detect_java_framework,
            "go": self._detect_go_framework,
            "ruby": self._detect_ruby_framework,
        }
        detector = detectors.get(language)
        if detector:
            result = detector()
            if result != "unknown":
                return result

        # Fallback: run all detectors for polyglot repos.
        for lang, det in detectors.items():
            if lang == language:
                continue
            result = det()
            if result != "unknown":
                return result

        return "unknown"

    def _detect_python_framework(self) -> str:
        """Detect Python web frameworks."""
        # Django – presence of manage.py is a strong signal.
        if (self._root / "manage.py").is_file():
            logger.debug("Detected Django (manage.py)")
            return "django"

        # Scan a limited set of .py files for import patterns.
        py_files = self._collect_source_files("*.py", limit=_MAX_FILES_FOR_IMPORTS)
        for fpath in py_files:
            try:
                content = fpath.read_text(errors="replace")
            except OSError:
                continue
            if re.search(r"\bfrom\s+fastapi\b|\bimport\s+fastapi\b", content):
                logger.debug("Detected FastAPI in %s", fpath)
                return "fastapi"
            if re.search(r"\bfrom\s+flask\b|\bimport\s+flask\b", content, re.IGNORECASE):
                logger.debug("Detected Flask in %s", fpath)
                return "flask"

        return "unknown"

    def _detect_js_framework(self) -> str:
        """Detect JavaScript / TypeScript frameworks."""
        # File-based indicators (fast).
        if any((self._root / name).is_file() for name in ("next.config.js", "next.config.mjs", "next.config.ts")):
            return "nextjs"
        if any((self._root / name).is_file() for name in ("nuxt.config.js", "nuxt.config.ts")):
            return "nuxt"
        if (self._root / "angular.json").is_file():
            return "angular"

        # package.json dependency check.
        pkg_json = self._root / "package.json"
        if pkg_json.is_file():
            try:
                data = json.loads(pkg_json.read_text(errors="replace"))
            except (json.JSONDecodeError, OSError):
                data = {}
            all_deps = {
                **data.get("dependencies", {}),
                **data.get("devDependencies", {}),
            }
            if "express" in all_deps:
                return "express"
            if "koa" in all_deps:
                return "koa"
            if "hapi" in all_deps or "@hapi/hapi" in all_deps:
                return "hapi"
            if "next" in all_deps:
                return "nextjs"
            if "nuxt" in all_deps:
                return "nuxt"

        return "unknown"

    def _detect_java_framework(self) -> str:
        """Detect Java frameworks via build files."""
        for build_file in ("pom.xml", "build.gradle", "build.gradle.kts"):
            path = self._root / build_file
            if path.is_file():
                try:
                    content = path.read_text(errors="replace")
                except OSError:
                    continue
                if "spring-boot" in content or "spring" in content.lower():
                    return "spring"

        return "unknown"

    def _detect_go_framework(self) -> str:
        """Detect Go web frameworks via go.mod."""
        go_mod = self._root / "go.mod"
        if not go_mod.is_file():
            return "unknown"
        try:
            content = go_mod.read_text(errors="replace")
        except OSError:
            return "unknown"

        framework_patterns = {
            "gin": r"github\.com/gin-gonic/gin",
            "echo": r"github\.com/labstack/echo",
            "fiber": r"github\.com/gofiber/fiber",
        }
        for name, pattern in framework_patterns.items():
            if re.search(pattern, content):
                return name

        return "unknown"

    def _detect_ruby_framework(self) -> str:
        """Detect Ruby frameworks via Gemfile."""
        gemfile = self._root / "Gemfile"
        if not gemfile.is_file():
            return "unknown"
        try:
            content = gemfile.read_text(errors="replace")
        except OSError:
            return "unknown"

        if re.search(r"""gem\s+['"]rails['"]""", content):
            return "rails"
        if re.search(r"""gem\s+['"]sinatra['"]""", content):
            return "sinatra"

        return "unknown"

    # ------------------------------------------------------------------
    # Auth detection
    # ------------------------------------------------------------------

    def _detect_auth(self) -> str:
        """Detect the authentication mechanism used in the project."""
        # Check dependency manifests first (fast path).
        auth = self._detect_auth_from_deps()
        if auth != "unknown":
            return auth

        # Fall back to scanning source files for import / usage patterns.
        extensions = ("*.py", "*.js", "*.ts", "*.java", "*.go", "*.rb", "*.php")
        files: list[Path] = []
        for ext in extensions:
            files.extend(self._collect_source_files(ext, limit=_MAX_FILES_FOR_AUTH // len(extensions)))
            if len(files) >= _MAX_FILES_FOR_AUTH:
                break

        jwt_re = re.compile(r"\bjwt\b|\bjsonwebtoken\b|\bPyJWT\b", re.IGNORECASE)
        oauth_re = re.compile(r"\bpassport\b|\boauth\b|\bauth0\b|\boauth2\b", re.IGNORECASE)
        session_re = re.compile(
            r"\bexpress-session\b|\bflask[_-]session\b|\bsession\s*middleware\b",
            re.IGNORECASE,
        )
        apikey_re = re.compile(r"\bapikey\b|\bapi_key\b|\bx-api-key\b", re.IGNORECASE)
        basic_re = re.compile(r"\bBasicAuth\b|\bbasic_auth\b|\bBasicAuthentication\b", re.IGNORECASE)

        for fpath in files:
            try:
                content = fpath.read_text(errors="replace")
            except OSError:
                continue

            if jwt_re.search(content):
                return "jwt"
            if oauth_re.search(content):
                return "oauth2"
            if session_re.search(content):
                return "session"
            if apikey_re.search(content):
                return "api_key"
            if basic_re.search(content):
                return "basic"

        return "unknown"

    def _detect_auth_from_deps(self) -> str:
        """Quick check for auth libraries in dependency manifests."""
        # package.json
        pkg_json = self._root / "package.json"
        if pkg_json.is_file():
            try:
                data = json.loads(pkg_json.read_text(errors="replace"))
            except (json.JSONDecodeError, OSError):
                data = {}
            all_deps = " ".join(
                list(data.get("dependencies", {}).keys()) + list(data.get("devDependencies", {}).keys())
            )
            if "jsonwebtoken" in all_deps or "jose" in all_deps:
                return "jwt"
            if "passport" in all_deps or "auth0" in all_deps:
                return "oauth2"
            if "express-session" in all_deps:
                return "session"

        # requirements.txt / Pipfile
        for req_file in ("requirements.txt", "Pipfile"):
            path = self._root / req_file
            if path.is_file():
                try:
                    content = path.read_text(errors="replace").lower()
                except OSError:
                    continue
                if "pyjwt" in content or "python-jose" in content:
                    return "jwt"
                if "authlib" in content or "auth0" in content:
                    return "oauth2"
                if "flask-session" in content or "django-session" in content:
                    return "session"

        # go.mod
        go_mod = self._root / "go.mod"
        if go_mod.is_file():
            try:
                content = go_mod.read_text(errors="replace").lower()
            except OSError:
                content = ""
            if "golang-jwt" in content or "jwt-go" in content:
                return "jwt"
            if "oauth2" in content:
                return "oauth2"

        return "unknown"

    # ------------------------------------------------------------------
    # Infrastructure detection
    # ------------------------------------------------------------------

    def _detect_cloud(self) -> str:
        """Detect the primary cloud provider from dependency files."""
        indicators: list[tuple[str, str]] = []

        # package.json
        pkg_json = self._root / "package.json"
        if pkg_json.is_file():
            try:
                data = json.loads(pkg_json.read_text(errors="replace"))
            except (json.JSONDecodeError, OSError):
                data = {}
            deps_str = " ".join(
                list(data.get("dependencies", {}).keys()) + list(data.get("devDependencies", {}).keys())
            )
            if "aws-sdk" in deps_str or "@aws-sdk" in deps_str:
                indicators.append(("aws", deps_str))
            if "@google-cloud" in deps_str:
                indicators.append(("gcp", deps_str))
            if "@azure" in deps_str:
                indicators.append(("azure", deps_str))

        # requirements.txt / Pipfile
        for req_file in ("requirements.txt", "Pipfile"):
            path = self._root / req_file
            if path.is_file():
                try:
                    content = path.read_text(errors="replace").lower()
                except OSError:
                    continue
                if "boto3" in content or "botocore" in content:
                    indicators.append(("aws", content))
                if "google-cloud" in content:
                    indicators.append(("gcp", content))
                if "azure" in content:
                    indicators.append(("azure", content))

        # go.mod
        go_mod = self._root / "go.mod"
        if go_mod.is_file():
            try:
                content = go_mod.read_text(errors="replace").lower()
            except OSError:
                content = ""
            if "aws-sdk-go" in content:
                indicators.append(("aws", content))
            if "cloud.google.com" in content:
                indicators.append(("gcp", content))
            if "azure-sdk" in content:
                indicators.append(("azure", content))

        # pom.xml / build.gradle
        for build_file in ("pom.xml", "build.gradle", "build.gradle.kts"):
            path = self._root / build_file
            if path.is_file():
                try:
                    content = path.read_text(errors="replace").lower()
                except OSError:
                    continue
                if "aws" in content or "amazonaws" in content:
                    indicators.append(("aws", content))
                if "google-cloud" in content or "gcloud" in content:
                    indicators.append(("gcp", content))
                if "azure" in content:
                    indicators.append(("azure", content))

        if not indicators:
            return "none"

        # Return the most frequently signalled provider.
        provider_counts: dict[str, int] = {}
        for provider, _ in indicators:
            provider_counts[provider] = provider_counts.get(provider, 0) + 1
        return max(provider_counts, key=lambda k: provider_counts[k])

    def _find_iac_files(self) -> list[str]:
        """Glob for infrastructure-as-code and container configuration files."""
        patterns = [
            "**/*.tf",
            "**/*.tfvars",
            "k8s/**/*.yml",
            "k8s/**/*.yaml",
            "kubernetes/**/*.yml",
            "kubernetes/**/*.yaml",
            "helm/**/*.yaml",
            "helm/**/*.yml",
            "**/*.dockerfile",
            "**/Dockerfile",
            "**/Dockerfile.*",
            "**/docker-compose*.yml",
            "**/docker-compose*.yaml",
        ]
        results: list[str] = []
        seen: set[str] = set()
        for pattern in patterns:
            full_pattern = os.path.join(str(self._root), pattern)
            for match in glob.iglob(full_pattern, recursive=True):
                real = os.path.realpath(match)
                if real not in seen:
                    seen.add(real)
                    results.append(os.path.relpath(match, self._root))
        return sorted(results)

    def _has_k8s(self) -> bool:
        """Check whether the project contains Kubernetes manifests."""
        # Dedicated k8s / kubernetes directories.
        for dir_name in ("k8s", "kubernetes", "helm"):
            if (self._root / dir_name).is_dir():
                return True

        # Look for k8s-indicative YAML content in .yml/.yaml at the root or
        # in common sub-directories.  Cap the search to stay fast.
        yaml_patterns = ["*.yml", "*.yaml", "deploy/**/*.yml", "deploy/**/*.yaml"]
        checked = 0
        for pattern in yaml_patterns:
            full = os.path.join(str(self._root), pattern)
            for match in glob.iglob(full, recursive=True):
                try:
                    head = Path(match).read_text(errors="replace")[:2048]
                except OSError:
                    continue
                if re.search(r"apiVersion:\s|kind:\s+(Deployment|Service|Pod|StatefulSet|Ingress)", head):
                    return True
                checked += 1
                if checked >= 50:
                    return False
        return False

    def _find_openapi_spec(self) -> str | None:
        """Look for OpenAPI / Swagger specification files."""
        candidates = [
            "openapi.json",
            "openapi.yaml",
            "openapi.yml",
            "swagger.json",
            "swagger.yaml",
            "swagger.yml",
            "api-spec.json",
            "api-spec.yaml",
            "api-spec.yml",
        ]
        search_dirs = [".", "docs", "api"]
        for search_dir in search_dirs:
            for candidate in candidates:
                path = self._root / search_dir / candidate
                if path.is_file():
                    return os.path.relpath(str(path), self._root)
        return None

    # ------------------------------------------------------------------
    # Entry points
    # ------------------------------------------------------------------

    def _find_entry_points(self) -> list[str]:
        """Find main entry files and route definition modules."""
        entry_names = {
            "main.py",
            "app.py",
            "server.py",
            "wsgi.py",
            "asgi.py",
            "manage.py",
            "index.js",
            "index.ts",
            "server.js",
            "server.ts",
            "app.js",
            "app.ts",
            "main.go",
            "cmd/main.go",
            "Application.java",
        }
        found: list[str] = []

        # Direct name matches in project root and one level down.
        for name in entry_names:
            full = self._root / name
            if full.is_file():
                found.append(os.path.relpath(str(full), self._root))

        # Route / controller directories.
        route_patterns = [
            "routes/**/*.py",
            "routes/**/*.js",
            "routes/**/*.ts",
            "controllers/**/*.py",
            "controllers/**/*.js",
            "controllers/**/*.ts",
            "controllers/**/*.java",
            "**/urls.py",
            "**/router.py",
            "**/router.js",
            "**/router.ts",
        ]
        for pattern in route_patterns:
            full_pattern = os.path.join(str(self._root), pattern)
            for match in glob.iglob(full_pattern, recursive=True):
                rel = os.path.relpath(match, self._root)
                if rel not in found:
                    found.append(rel)

        return sorted(found)

    # ------------------------------------------------------------------
    # Middleware detection
    # ------------------------------------------------------------------

    def _detect_middleware(self) -> list[str]:
        """Detect common middleware usage across all recognised languages."""
        middleware_patterns: dict[str, re.Pattern] = {
            "cors": re.compile(r"\bcors\b|\bCORS\b|\baccess-control-allow-origin\b", re.IGNORECASE),
            "rate_limiting": re.compile(r"\brate.?limit\b|\bthrottle\b|\bRateLimit\b", re.IGNORECASE),
            "auth": re.compile(r"\bauth.?middleware\b|\bauthenticate\b|\bisAuthenticated\b", re.IGNORECASE),
            "helmet": re.compile(r"\bhelmet\b", re.IGNORECASE),
            "csrf": re.compile(r"\bcsrf\b|\bcsurf\b|\bCSRFMiddleware\b", re.IGNORECASE),
            "logging": re.compile(r"\blogging.?middleware\b|\bmorgan\b|\brequest.?log\b", re.IGNORECASE),
            "compression": re.compile(r"\bcompression\b|\bgzip\b|\bGZipMiddleware\b", re.IGNORECASE),
            "body_parser": re.compile(r"\bbody-parser\b|\bbodyParser\b", re.IGNORECASE),
        }

        detected: set[str] = set()
        extensions = ("*.py", "*.js", "*.ts", "*.java", "*.go", "*.rb")
        files: list[Path] = []
        for ext in extensions:
            files.extend(self._collect_source_files(ext, limit=_MAX_FILES_FOR_IMPORTS // len(extensions)))

        for fpath in files:
            try:
                content = fpath.read_text(errors="replace")
            except OSError:
                continue
            for name, pattern in middleware_patterns.items():
                if name not in detected and pattern.search(content):
                    detected.add(name)
            # Early exit if we already found everything.
            if len(detected) == len(middleware_patterns):
                break

        return sorted(detected)

    # ------------------------------------------------------------------
    # Dependency files
    # ------------------------------------------------------------------

    def _find_dependency_files(self) -> list[str]:
        """Find dependency manifest files at the project root."""
        candidates = [
            "requirements.txt",
            "Pipfile",
            "pyproject.toml",
            "setup.py",
            "package.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "go.mod",
            "Gemfile",
            "composer.json",
            "Cargo.toml",
        ]
        found: list[str] = []
        for name in candidates:
            if (self._root / name).is_file():
                found.append(name)
        return found

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _collect_source_files(self, pattern: str, limit: int) -> list[Path]:
        """Collect source files matching *pattern*, skipping common vendor dirs.

        Returns at most *limit* paths.  Hidden directories, ``node_modules``,
        ``vendor``, ``venv``, and ``__pycache__`` are excluded to avoid noise.
        """
        full_pattern = os.path.join(str(self._root), "**", pattern)
        skip_dirs = {"node_modules", "vendor", "venv", ".venv", "__pycache__", ".git", "dist", "build"}
        results: list[Path] = []
        for match in glob.iglob(full_pattern, recursive=True):
            parts = Path(match).relative_to(self._root).parts
            if any(p in skip_dirs for p in parts):
                continue
            results.append(Path(match))
            if len(results) >= limit:
                break
        return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    path = sys.argv[1] if len(sys.argv) > 1 else "."
    builder = AppContextBuilder(path)
    ctx = builder.build()
    print(ctx.to_prompt_context())
    print()
    print(json.dumps(ctx.to_dict(), indent=2))
