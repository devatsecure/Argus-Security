#!/usr/bin/env python3
"""
Project Context Detection System

Automatically detects project type, runtime, framework, and output destinations
by analyzing project files (package.json, pyproject.toml, pom.xml, etc.).

This module helps identify whether a project is a CLI tool, web application, library,
or mobile app, and what runtime environment it uses (Node.js, Python, Java, Go, Rust).

Usage:
    from project_context_detector import detect_project_context

    context = detect_project_context("/path/to/repo")
    if context.is_cli_tool:
        print(f"Detected CLI tool using {context.runtime}")
    elif context.is_web_app:
        print(f"Detected web app using {context.framework}")
"""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # Fallback for Python <3.11
    except ImportError:
        tomllib = None  # type: ignore

logger = logging.getLogger(__name__)


@dataclass
class ProjectContext:
    """
    Represents the detected context of a project.

    Attributes:
        type: Project category (cli-tool, web-application, library, mobile-app, unknown)
        runtime: Programming language/runtime (nodejs, python, java, go, rust, unknown)
        output_destinations: Where the application sends output (terminal, browser, etc.)
        framework: Optional framework name (express, django, flask, fastapi, react, etc.)
        confidence: Detection confidence score (0.0-1.0)
        detection_details: Dict of details about what was detected and why
    """

    type: str = "unknown"
    runtime: str = "unknown"
    output_destinations: list[str] = field(default_factory=list)
    framework: Optional[str] = None
    confidence: float = 0.0
    detection_details: dict = field(default_factory=dict)

    @property
    def is_cli_tool(self) -> bool:
        """Returns True if project is detected as a CLI tool."""
        return self.type == "cli-tool"

    @property
    def is_web_app(self) -> bool:
        """Returns True if project is detected as a web application."""
        return self.type == "web-application"

    @property
    def is_library(self) -> bool:
        """Returns True if project is detected as a library."""
        return self.type == "library"

    @property
    def is_mobile_app(self) -> bool:
        """Returns True if project is detected as a mobile application."""
        return self.type == "mobile-app"


class ProjectContextDetector:
    """
    Detects project type, runtime, and framework by analyzing project files.
    """

    # Web framework markers
    WEB_FRAMEWORKS = {
        "nodejs": {
            "express": ["express"],
            "fastify": ["fastify"],
            "next": ["next"],
            "nuxt": ["nuxt"],
            "react": ["react", "react-dom"],
            "vue": ["vue"],
            "angular": ["@angular/core"],
            "svelte": ["svelte"],
            "nest": ["@nestjs/core"],
            "koa": ["koa"],
            "hapi": ["@hapi/hapi"],
        },
        "python": {
            "django": ["django"],
            "flask": ["flask"],
            "fastapi": ["fastapi"],
            "tornado": ["tornado"],
            "pyramid": ["pyramid"],
            "bottle": ["bottle"],
            "sanic": ["sanic"],
            "aiohttp": ["aiohttp"],
            "starlette": ["starlette"],
        },
        "java": {
            "spring": ["spring-boot", "spring-web", "org.springframework"],
            "quarkus": ["quarkus"],
            "micronaut": ["micronaut"],
            "dropwizard": ["dropwizard"],
            "play": ["play-java"],
        },
        "go": {
            "gin": ["github.com/gin-gonic/gin"],
            "echo": ["github.com/labstack/echo"],
            "fiber": ["github.com/gofiber/fiber"],
            "chi": ["github.com/go-chi/chi"],
            "gorilla": ["github.com/gorilla/mux"],
        },
        "rust": {
            "actix": ["actix-web"],
            "rocket": ["rocket"],
            "axum": ["axum"],
            "warp": ["warp"],
        },
    }

    # CLI framework markers
    CLI_FRAMEWORKS = {
        "nodejs": ["commander", "yargs", "oclif", "inquirer", "chalk", "ora"],
        "python": ["click", "typer", "argparse", "fire", "docopt"],
        "go": ["cobra", "urfave/cli"],
        "rust": ["clap"],
    }

    # Mobile framework markers
    MOBILE_FRAMEWORKS = {
        "react-native": ["react-native"],
        "flutter": ["flutter"],
        "ionic": ["@ionic/angular", "@ionic/react", "@ionic/vue"],
        "xamarin": ["xamarin"],
    }

    def __init__(self, repo_path: str):
        """
        Initialize detector with repository path.

        Args:
            repo_path: Absolute path to repository root
        """
        self.repo_path = Path(repo_path)
        self.detection_details: dict = {}

    def detect(self) -> ProjectContext:
        """
        Detect project context by analyzing project files.

        Returns:
            ProjectContext with detected information
        """
        # Detect runtime first
        runtime = self._detect_runtime()

        # Detect project type and framework based on runtime
        if runtime == "nodejs":
            return self._detect_nodejs_context()
        elif runtime == "python":
            return self._detect_python_context()
        elif runtime == "java":
            return self._detect_java_context()
        elif runtime == "go":
            return self._detect_go_context()
        elif runtime == "rust":
            return self._detect_rust_context()
        else:
            # Unknown runtime, return basic context
            return ProjectContext(
                runtime=runtime,
                confidence=0.1,
                detection_details=self.detection_details,
            )

    def _detect_runtime(self) -> str:
        """Detect programming language/runtime environment."""
        # Check for Node.js
        if (self.repo_path / "package.json").exists():
            self.detection_details["runtime_marker"] = "package.json"
            return "nodejs"

        # Check for Python
        if ((self.repo_path / "setup.py").exists() or
            (self.repo_path / "pyproject.toml").exists() or
            (self.repo_path / "requirements.txt").exists()):
            self.detection_details["runtime_marker"] = "python project files"
            return "python"

        # Check for Java
        if ((self.repo_path / "pom.xml").exists() or
            (self.repo_path / "build.gradle").exists() or
            (self.repo_path / "build.gradle.kts").exists()):
            self.detection_details["runtime_marker"] = "java build files"
            return "java"

        # Check for Go
        if (self.repo_path / "go.mod").exists():
            self.detection_details["runtime_marker"] = "go.mod"
            return "go"

        # Check for Rust
        if (self.repo_path / "Cargo.toml").exists():
            self.detection_details["runtime_marker"] = "Cargo.toml"
            return "rust"

        return "unknown"

    def _detect_nodejs_context(self) -> ProjectContext:
        """Detect Node.js project context from package.json."""
        package_json_path = self.repo_path / "package.json"

        try:
            with open(package_json_path, encoding="utf-8") as f:
                package_data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to parse package.json: {e}")
            return ProjectContext(runtime="nodejs", confidence=0.3)

        # Extract dependencies
        dependencies = set(package_data.get("dependencies", {}).keys())
        dev_dependencies = set(package_data.get("devDependencies", {}).keys())
        all_deps = dependencies | dev_dependencies

        # Check for CLI tool markers
        has_bin = "bin" in package_data
        keywords = package_data.get("keywords", [])
        has_cli_keyword = any(kw in ["cli", "terminal", "command-line"] for kw in keywords)
        has_cli_deps = any(dep in all_deps for dep in self.CLI_FRAMEWORKS["nodejs"])

        # Check for web framework markers
        detected_framework = None
        for framework, markers in self.WEB_FRAMEWORKS["nodejs"].items():
            if any(marker in all_deps for marker in markers):
                detected_framework = framework
                break

        # Check for mobile framework markers
        is_mobile = any(dep in all_deps for mobile_deps in self.MOBILE_FRAMEWORKS.values() for dep in mobile_deps)
        if is_mobile:
            detected_mobile = next(
                (name for name, deps in self.MOBILE_FRAMEWORKS.items() if any(d in all_deps for d in deps)),
                "unknown-mobile"
            )
            return ProjectContext(
                type="mobile-app",
                runtime="nodejs",
                framework=detected_mobile,
                output_destinations=["mobile-device"],
                confidence=0.9,
                detection_details={
                    **self.detection_details,
                    "mobile_framework": detected_mobile,
                },
            )

        # Determine project type
        if has_bin or has_cli_keyword or (has_cli_deps and not detected_framework):
            project_type = "cli-tool"
            output_destinations = ["terminal"]
            confidence = 0.9 if has_bin else 0.7
            self.detection_details["cli_markers"] = {
                "has_bin": has_bin,
                "has_cli_keyword": has_cli_keyword,
                "has_cli_deps": has_cli_deps,
            }
        elif detected_framework:
            project_type = "web-application"
            output_destinations = ["browser", "http-response"]
            confidence = 0.9
            self.detection_details["web_framework"] = detected_framework
        else:
            # Assume library if no clear markers
            project_type = "library"
            output_destinations = []
            confidence = 0.5

        return ProjectContext(
            type=project_type,
            runtime="nodejs",
            framework=detected_framework,
            output_destinations=output_destinations,
            confidence=confidence,
            detection_details=self.detection_details,
        )

    def _detect_python_context(self) -> ProjectContext:
        """Detect Python project context from setup.py, pyproject.toml, requirements.txt."""
        # Try to read dependencies from various sources
        dependencies: set = set()
        has_console_scripts = False

        # Check pyproject.toml
        pyproject_path = self.repo_path / "pyproject.toml"
        if pyproject_path.exists() and tomllib:
            try:
                with open(pyproject_path, "rb") as f:
                    pyproject_data = tomllib.load(f)

                # Extract dependencies
                poetry_deps = pyproject_data.get("tool", {}).get("poetry", {}).get("dependencies", {})
                dependencies.update(poetry_deps.keys())

                # Check for console scripts
                scripts = pyproject_data.get("project", {}).get("scripts", {})
                entry_points = pyproject_data.get("project", {}).get("entry-points", {})
                console_scripts = entry_points.get("console_scripts", {}) if isinstance(entry_points, dict) else {}

                has_console_scripts = bool(scripts or console_scripts)

                if has_console_scripts:
                    self.detection_details["console_scripts_source"] = "pyproject.toml"
            except Exception as e:
                logger.warning(f"Failed to parse pyproject.toml: {e}")

        # Check requirements.txt
        requirements_path = self.repo_path / "requirements.txt"
        if requirements_path.exists():
            try:
                with open(requirements_path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Extract package name (before ==, >=, etc.)
                            pkg_name = re.split(r"[=<>!]", line)[0].strip()
                            dependencies.add(pkg_name)
            except OSError as e:
                logger.warning(f"Failed to read requirements.txt: {e}")

        # Check setup.py for console_scripts
        setup_py_path = self.repo_path / "setup.py"
        if setup_py_path.exists() and not has_console_scripts:
            try:
                with open(setup_py_path, encoding="utf-8") as f:
                    setup_content = f.read()
                    if "console_scripts" in setup_content or "entry_points" in setup_content:
                        has_console_scripts = True
                        self.detection_details["console_scripts_source"] = "setup.py"
            except OSError as e:
                logger.warning(f"Failed to read setup.py: {e}")

        # Check for web framework markers
        detected_framework = None
        for framework, markers in self.WEB_FRAMEWORKS["python"].items():
            if any(marker.lower() in dep.lower() for dep in dependencies for marker in markers):
                detected_framework = framework
                break

        # Check for CLI framework markers
        has_cli_deps = any(dep.lower() in marker.lower() or marker.lower() in dep.lower()
                          for dep in dependencies for marker in self.CLI_FRAMEWORKS["python"])

        # Determine project type
        if has_console_scripts or (has_cli_deps and not detected_framework):
            project_type = "cli-tool"
            output_destinations = ["terminal"]
            confidence = 0.9 if has_console_scripts else 0.7
            self.detection_details["cli_markers"] = {
                "has_console_scripts": has_console_scripts,
                "has_cli_deps": has_cli_deps,
            }
        elif detected_framework:
            project_type = "web-application"
            output_destinations = ["browser", "http-response"]
            confidence = 0.9
            self.detection_details["web_framework"] = detected_framework
        else:
            # Assume library if no clear markers
            project_type = "library"
            output_destinations = []
            confidence = 0.5

        return ProjectContext(
            type=project_type,
            runtime="python",
            framework=detected_framework,
            output_destinations=output_destinations,
            confidence=confidence,
            detection_details=self.detection_details,
        )

    def _detect_java_context(self) -> ProjectContext:
        """Detect Java project context from pom.xml or build.gradle."""
        dependencies: set = set()

        # Check pom.xml
        pom_path = self.repo_path / "pom.xml"
        if pom_path.exists():
            try:
                with open(pom_path, encoding="utf-8") as f:
                    pom_content = f.read()
                    # Simple regex to extract artifact IDs
                    artifact_ids = re.findall(r"<artifactId>(.*?)</artifactId>", pom_content)
                    dependencies.update(artifact_ids)
            except OSError as e:
                logger.warning(f"Failed to read pom.xml: {e}")

        # Check build.gradle
        gradle_paths = [
            self.repo_path / "build.gradle",
            self.repo_path / "build.gradle.kts",
        ]
        for gradle_path in gradle_paths:
            if gradle_path.exists():
                try:
                    with open(gradle_path, encoding="utf-8") as f:
                        gradle_content = f.read()
                        # Extract dependencies from implementation/compile lines
                        dep_lines = re.findall(r"['\"]([^:]+:[^:]+)(?::[^'\"]+)?['\"]", gradle_content)
                        dependencies.update(dep.split(":")[1] for dep in dep_lines if ":" in dep)
                except OSError as e:
                    logger.warning(f"Failed to read {gradle_path.name}: {e}")

        # Check for web framework markers
        detected_framework = None
        for framework, markers in self.WEB_FRAMEWORKS["java"].items():
            if any(marker in dep for dep in dependencies for marker in markers):
                detected_framework = framework
                break

        # Determine project type
        if detected_framework:
            project_type = "web-application"
            output_destinations = ["browser", "http-response"]
            confidence = 0.9
        else:
            # Default to library for Java
            project_type = "library"
            output_destinations = []
            confidence = 0.5

        return ProjectContext(
            type=project_type,
            runtime="java",
            framework=detected_framework,
            output_destinations=output_destinations,
            confidence=confidence,
            detection_details=self.detection_details,
        )

    def _detect_go_context(self) -> ProjectContext:
        """Detect Go project context from go.mod and main.go."""
        dependencies: set = set()

        # Check go.mod
        go_mod_path = self.repo_path / "go.mod"
        if go_mod_path.exists():
            try:
                with open(go_mod_path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("require"):
                            continue
                        # Extract module name from require lines
                        match = re.match(r"^\s*([^\s]+)", line)
                        if match:
                            dependencies.add(match.group(1))
            except OSError as e:
                logger.warning(f"Failed to read go.mod: {e}")

        # Check for web framework markers
        detected_framework = None
        for framework, markers in self.WEB_FRAMEWORKS["go"].items():
            if any(marker in dep for dep in dependencies for marker in markers):
                detected_framework = framework
                break

        # Check for main.go (indicator of CLI tool)
        main_go_path = self.repo_path / "main.go"
        has_main = main_go_path.exists()

        # Determine project type
        if detected_framework:
            project_type = "web-application"
            output_destinations = ["browser", "http-response"]
            confidence = 0.9
        elif has_main and not detected_framework:
            project_type = "cli-tool"
            output_destinations = ["terminal"]
            confidence = 0.7
        else:
            project_type = "library"
            output_destinations = []
            confidence = 0.5

        return ProjectContext(
            type=project_type,
            runtime="go",
            framework=detected_framework,
            output_destinations=output_destinations,
            confidence=confidence,
            detection_details=self.detection_details,
        )

    def _detect_rust_context(self) -> ProjectContext:
        """Detect Rust project context from Cargo.toml."""
        dependencies: set = set()

        # Check Cargo.toml
        cargo_path = self.repo_path / "Cargo.toml"
        if cargo_path.exists() and tomllib:
            try:
                with open(cargo_path, "rb") as f:
                    cargo_data = tomllib.load(f)

                # Extract dependencies
                deps = cargo_data.get("dependencies", {})
                dependencies.update(deps.keys())
            except Exception as e:
                logger.warning(f"Failed to parse Cargo.toml: {e}")

        # Check for web framework markers
        detected_framework = None
        for framework, markers in self.WEB_FRAMEWORKS["rust"].items():
            if any(marker in dependencies for marker in markers):
                detected_framework = framework
                break

        # Determine project type
        if detected_framework:
            project_type = "web-application"
            output_destinations = ["browser", "http-response"]
            confidence = 0.9
        else:
            # Default to library for Rust
            project_type = "library"
            output_destinations = []
            confidence = 0.5

        return ProjectContext(
            type=project_type,
            runtime="rust",
            framework=detected_framework,
            output_destinations=output_destinations,
            confidence=confidence,
            detection_details=self.detection_details,
        )


def detect_project_context(repo_path: str) -> ProjectContext:
    """
    Detect project context from repository files.

    Args:
        repo_path: Absolute path to repository root

    Returns:
        ProjectContext with detected type, runtime, framework, and output destinations

    Example:
        >>> context = detect_project_context("/path/to/express-api")
        >>> print(f"Type: {context.type}, Runtime: {context.runtime}, Framework: {context.framework}")
        Type: web-application, Runtime: nodejs, Framework: express
    """
    detector = ProjectContextDetector(repo_path)
    return detector.detect()


if __name__ == "__main__":
    # Simple CLI for testing
    import sys

    if len(sys.argv) < 2:
        print("Usage: python project_context_detector.py <repo_path>")
        sys.exit(1)

    repo_path = sys.argv[1]
    context = detect_project_context(repo_path)

    print(f"Project Type: {context.type}")
    print(f"Runtime: {context.runtime}")
    print(f"Framework: {context.framework or 'None'}")
    print(f"Output Destinations: {', '.join(context.output_destinations) or 'None'}")
    print(f"Confidence: {context.confidence:.2f}")
    print(f"Is CLI Tool: {context.is_cli_tool}")
    print(f"Is Web App: {context.is_web_app}")
    print(f"\nDetection Details: {json.dumps(context.detection_details, indent=2)}")
