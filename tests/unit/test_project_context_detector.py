#!/usr/bin/env python3
"""
Unit tests for project_context_detector.py

Tests detection of project type, runtime, framework, and output destinations
for various project configurations (Node.js, Python, Java, Go, Rust).
"""

import json
import tempfile
from pathlib import Path

import pytest

from scripts.project_context_detector import (
    ProjectContext,
    ProjectContextDetector,
    detect_project_context,
)

# Import the tomllib reference from the source module to check availability.
# The source already handles the tomllib/tomli fallback; we just need to know
# if TOML parsing is available at all (tomllib is None when neither is installed).
from scripts.project_context_detector import tomllib as _tomllib

# Skip marker for tests that require TOML parsing (tomllib or tomli)
needs_toml = pytest.mark.skipif(
    _tomllib is None,
    reason="Neither tomllib (Python 3.11+) nor tomli is available",
)


class TestProjectContext:
    """Test ProjectContext dataclass properties and methods."""

    def test_is_cli_tool_true(self):
        """Test is_cli_tool property returns True for CLI tools."""
        context = ProjectContext(type="cli-tool")
        assert context.is_cli_tool is True

    def test_is_cli_tool_false(self):
        """Test is_cli_tool property returns False for non-CLI tools."""
        context = ProjectContext(type="web-application")
        assert context.is_cli_tool is False

    def test_is_web_app_true(self):
        """Test is_web_app property returns True for web applications."""
        context = ProjectContext(type="web-application")
        assert context.is_web_app is True

    def test_is_web_app_false(self):
        """Test is_web_app property returns False for non-web apps."""
        context = ProjectContext(type="cli-tool")
        assert context.is_web_app is False

    def test_is_library_true(self):
        """Test is_library property returns True for libraries."""
        context = ProjectContext(type="library")
        assert context.is_library is True

    def test_is_library_false(self):
        """Test is_library property returns False for non-libraries."""
        context = ProjectContext(type="web-application")
        assert context.is_library is False

    def test_is_mobile_app_true(self):
        """Test is_mobile_app property returns True for mobile apps."""
        context = ProjectContext(type="mobile-app")
        assert context.is_mobile_app is True

    def test_is_mobile_app_false(self):
        """Test is_mobile_app property returns False for non-mobile apps."""
        context = ProjectContext(type="cli-tool")
        assert context.is_mobile_app is False

    def test_default_values(self):
        """Test ProjectContext defaults."""
        context = ProjectContext()
        assert context.type == "unknown"
        assert context.runtime == "unknown"
        assert context.output_destinations == []
        assert context.framework is None
        assert context.confidence == 0.0
        assert context.detection_details == {}


class TestNodeJSDetection:
    """Test Node.js project detection."""

    def test_nodejs_cli_tool_with_bin(self):
        """Test detection of Node.js CLI tool with bin field in package.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            package_json = {
                "name": "my-cli",
                "version": "1.0.0",
                "bin": {
                    "my-cli": "./bin/cli.js"
                },
                "dependencies": {
                    "commander": "^9.0.0"
                }
            }

            package_path = Path(tmpdir) / "package.json"
            with open(package_path, "w") as f:
                json.dump(package_json, f)

            context = detect_project_context(tmpdir)

            assert context.runtime == "nodejs"
            assert context.type == "cli-tool"
            assert "terminal" in context.output_destinations
            assert context.confidence >= 0.9

    def test_nodejs_cli_tool_with_keyword(self):
        """Test detection of Node.js CLI tool with cli keyword."""
        with tempfile.TemporaryDirectory() as tmpdir:
            package_json = {
                "name": "my-cli",
                "version": "1.0.0",
                "keywords": ["cli", "terminal"],
                "dependencies": {
                    "yargs": "^17.0.0"
                }
            }

            package_path = Path(tmpdir) / "package.json"
            with open(package_path, "w") as f:
                json.dump(package_json, f)

            context = detect_project_context(tmpdir)

            assert context.runtime == "nodejs"
            assert context.type == "cli-tool"
            assert "terminal" in context.output_destinations

    def test_nodejs_cli_tool_with_cli_deps(self):
        """Test detection of Node.js CLI tool with CLI dependencies."""
        with tempfile.TemporaryDirectory() as tmpdir:
            package_json = {
                "name": "my-cli",
                "version": "1.0.0",
                "dependencies": {
                    "chalk": "^4.0.0",
                    "ora": "^5.0.0",
                    "inquirer": "^8.0.0"
                }
            }

            package_path = Path(tmpdir) / "package.json"
            with open(package_path, "w") as f:
                json.dump(package_json, f)

            context = detect_project_context(tmpdir)

            assert context.runtime == "nodejs"
            assert context.type == "cli-tool"
            assert "terminal" in context.output_destinations

    def test_nodejs_web_app_express(self):
        """Test detection of Node.js web app with Express."""
        with tempfile.TemporaryDirectory() as tmpdir:
            package_json = {
                "name": "my-api",
                "version": "1.0.0",
                "dependencies": {
                    "express": "^4.18.0",
                    "body-parser": "^1.19.0"
                }
            }

            package_path = Path(tmpdir) / "package.json"
            with open(package_path, "w") as f:
                json.dump(package_json, f)

            context = detect_project_context(tmpdir)

            assert context.runtime == "nodejs"
            assert context.type == "web-application"
            assert context.framework == "express"
            assert "browser" in context.output_destinations or "http-response" in context.output_destinations
            assert context.confidence >= 0.9

    def test_nodejs_web_app_fastify(self):
        """Test detection of Node.js web app with Fastify."""
        with tempfile.TemporaryDirectory() as tmpdir:
            package_json = {
                "name": "my-api",
                "version": "1.0.0",
                "dependencies": {
                    "fastify": "^4.0.0"
                }
            }

            package_path = Path(tmpdir) / "package.json"
            with open(package_path, "w") as f:
                json.dump(package_json, f)

            context = detect_project_context(tmpdir)

            assert context.runtime == "nodejs"
            assert context.type == "web-application"
            assert context.framework == "fastify"

    def test_nodejs_web_app_nextjs(self):
        """Test detection of Next.js web app."""
        with tempfile.TemporaryDirectory() as tmpdir:
            package_json = {
                "name": "my-nextjs-app",
                "version": "1.0.0",
                "dependencies": {
                    "next": "^13.0.0",
                    "react": "^18.0.0",
                    "react-dom": "^18.0.0"
                }
            }

            package_path = Path(tmpdir) / "package.json"
            with open(package_path, "w") as f:
                json.dump(package_json, f)

            context = detect_project_context(tmpdir)

            assert context.runtime == "nodejs"
            assert context.type == "web-application"
            assert context.framework == "next"

    def test_nodejs_web_app_react(self):
        """Test detection of React web app."""
        with tempfile.TemporaryDirectory() as tmpdir:
            package_json = {
                "name": "my-react-app",
                "version": "1.0.0",
                "dependencies": {
                    "react": "^18.0.0",
                    "react-dom": "^18.0.0"
                }
            }

            package_path = Path(tmpdir) / "package.json"
            with open(package_path, "w") as f:
                json.dump(package_json, f)

            context = detect_project_context(tmpdir)

            assert context.runtime == "nodejs"
            assert context.type == "web-application"
            assert context.framework == "react"

    def test_nodejs_mobile_app_react_native(self):
        """Test detection of React Native mobile app."""
        with tempfile.TemporaryDirectory() as tmpdir:
            package_json = {
                "name": "my-mobile-app",
                "version": "1.0.0",
                "dependencies": {
                    "react-native": "^0.71.0",
                    "react": "^18.0.0"
                }
            }

            package_path = Path(tmpdir) / "package.json"
            with open(package_path, "w") as f:
                json.dump(package_json, f)

            context = detect_project_context(tmpdir)

            assert context.runtime == "nodejs"
            assert context.type == "mobile-app"
            assert context.framework == "react-native"
            assert "mobile-device" in context.output_destinations

    def test_nodejs_library(self):
        """Test detection of Node.js library (no clear CLI or web markers)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            package_json = {
                "name": "my-library",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "^4.17.0"
                }
            }

            package_path = Path(tmpdir) / "package.json"
            with open(package_path, "w") as f:
                json.dump(package_json, f)

            context = detect_project_context(tmpdir)

            assert context.runtime == "nodejs"
            assert context.type == "library"
            assert context.output_destinations == []

    def test_nodejs_invalid_package_json(self):
        """Test handling of invalid package.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            package_path = Path(tmpdir) / "package.json"
            with open(package_path, "w") as f:
                f.write("{ invalid json }")

            context = detect_project_context(tmpdir)

            assert context.runtime == "nodejs"
            assert context.confidence == 0.3


class TestPythonDetection:
    """Test Python project detection."""

    @needs_toml
    def test_python_cli_tool_with_console_scripts_pyproject(self):
        """Test detection of Python CLI tool with console_scripts in pyproject.toml."""

        with tempfile.TemporaryDirectory() as tmpdir:
            pyproject_content = """
[project]
name = "my-cli"
version = "1.0.0"

[project.scripts]
my-cli = "my_cli.main:cli"

[tool.poetry.dependencies]
python = "^3.9"
click = "^8.0.0"
"""

            pyproject_path = Path(tmpdir) / "pyproject.toml"
            with open(pyproject_path, "w") as f:
                f.write(pyproject_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "python"
            assert context.type == "cli-tool"
            assert "terminal" in context.output_destinations
            assert context.confidence >= 0.9

    @needs_toml
    def test_python_cli_tool_with_entry_points_pyproject(self):
        """Test detection of Python CLI tool with entry-points in pyproject.toml."""

        with tempfile.TemporaryDirectory() as tmpdir:
            pyproject_content = """
[project]
name = "my-cli"
version = "1.0.0"

[project.entry-points.console_scripts]
my-cli = "my_cli.main:cli"

[tool.poetry.dependencies]
python = "^3.9"
typer = "^0.7.0"
"""

            pyproject_path = Path(tmpdir) / "pyproject.toml"
            with open(pyproject_path, "w") as f:
                f.write(pyproject_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "python"
            assert context.type == "cli-tool"
            assert "terminal" in context.output_destinations

    def test_python_cli_tool_with_setup_py(self):
        """Test detection of Python CLI tool with console_scripts in setup.py."""
        with tempfile.TemporaryDirectory() as tmpdir:
            setup_content = """
from setuptools import setup

setup(
    name='my-cli',
    version='1.0.0',
    entry_points={
        'console_scripts': [
            'my-cli=my_cli.main:cli',
        ],
    },
    install_requires=['click>=8.0.0'],
)
"""

            setup_path = Path(tmpdir) / "setup.py"
            with open(setup_path, "w") as f:
                f.write(setup_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "python"
            assert context.type == "cli-tool"
            assert "terminal" in context.output_destinations
            assert context.confidence >= 0.9

    def test_python_cli_tool_with_cli_deps(self):
        """Test detection of Python CLI tool with CLI dependencies."""
        with tempfile.TemporaryDirectory() as tmpdir:
            requirements_content = """
click==8.0.0
typer==0.7.0
rich==13.0.0
"""

            requirements_path = Path(tmpdir) / "requirements.txt"
            with open(requirements_path, "w") as f:
                f.write(requirements_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "python"
            assert context.type == "cli-tool"
            assert "terminal" in context.output_destinations

    def test_python_web_app_django(self):
        """Test detection of Python web app with Django."""
        with tempfile.TemporaryDirectory() as tmpdir:
            requirements_content = """
Django==4.2.0
djangorestframework==3.14.0
"""

            requirements_path = Path(tmpdir) / "requirements.txt"
            with open(requirements_path, "w") as f:
                f.write(requirements_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "python"
            assert context.type == "web-application"
            assert context.framework == "django"
            assert "browser" in context.output_destinations or "http-response" in context.output_destinations
            assert context.confidence >= 0.9

    def test_python_web_app_flask(self):
        """Test detection of Python web app with Flask."""
        with tempfile.TemporaryDirectory() as tmpdir:
            requirements_content = """
Flask==2.3.0
Flask-SQLAlchemy==3.0.0
"""

            requirements_path = Path(tmpdir) / "requirements.txt"
            with open(requirements_path, "w") as f:
                f.write(requirements_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "python"
            assert context.type == "web-application"
            assert context.framework == "flask"

    def test_python_web_app_fastapi(self):
        """Test detection of Python web app with FastAPI."""
        with tempfile.TemporaryDirectory() as tmpdir:
            requirements_content = """
fastapi==0.100.0
uvicorn[standard]==0.23.0
pydantic==2.0.0
"""

            requirements_path = Path(tmpdir) / "requirements.txt"
            with open(requirements_path, "w") as f:
                f.write(requirements_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "python"
            assert context.type == "web-application"
            assert context.framework == "fastapi"

    def test_python_library(self):
        """Test detection of Python library (no clear CLI or web markers)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            requirements_content = """
requests==2.31.0
pydantic==2.0.0
"""

            requirements_path = Path(tmpdir) / "requirements.txt"
            with open(requirements_path, "w") as f:
                f.write(requirements_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "python"
            assert context.type == "library"
            assert context.output_destinations == []

    @needs_toml
    def test_python_pyproject_with_poetry_deps(self):
        """Test parsing Poetry dependencies from pyproject.toml."""

        with tempfile.TemporaryDirectory() as tmpdir:
            pyproject_content = """
[tool.poetry]
name = "my-web-app"
version = "1.0.0"

[tool.poetry.dependencies]
python = "^3.9"
flask = "^2.3.0"
"""

            pyproject_path = Path(tmpdir) / "pyproject.toml"
            with open(pyproject_path, "w") as f:
                f.write(pyproject_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "python"
            assert context.type == "web-application"
            assert context.framework == "flask"

    def test_python_requirements_with_version_specifiers(self):
        """Test parsing requirements.txt with various version specifiers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            requirements_content = """
Django>=4.2.0,<5.0.0
flask~=2.3.0
fastapi!=0.99.0
requests>=2.31.0
# Comment line
pydantic==2.0.0
"""

            requirements_path = Path(tmpdir) / "requirements.txt"
            with open(requirements_path, "w") as f:
                f.write(requirements_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "python"
            # Should detect Django first (first web framework in list)
            assert context.type == "web-application"


class TestJavaDetection:
    """Test Java project detection."""

    def test_java_web_app_spring_pom(self):
        """Test detection of Java Spring web app from pom.xml."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>my-spring-app</artifactId>
    <version>1.0.0</version>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
    </dependencies>
</project>
"""

            pom_path = Path(tmpdir) / "pom.xml"
            with open(pom_path, "w") as f:
                f.write(pom_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "java"
            assert context.type == "web-application"
            assert context.framework == "spring"
            assert "browser" in context.output_destinations or "http-response" in context.output_destinations
            assert context.confidence >= 0.9

    def test_java_web_app_spring_gradle(self):
        """Test detection of Java Spring web app from build.gradle."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gradle_content = """
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.1.0'
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    testImplementation 'junit:junit:4.13.2'
}
"""

            gradle_path = Path(tmpdir) / "build.gradle"
            with open(gradle_path, "w") as f:
                f.write(gradle_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "java"
            assert context.type == "web-application"
            assert context.framework == "spring"

    def test_java_library(self):
        """Test detection of Java library (no web framework markers)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>my-library</artifactId>
    <version>1.0.0</version>

    <dependencies>
        <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava</artifactId>
        </dependency>
    </dependencies>
</project>
"""

            pom_path = Path(tmpdir) / "pom.xml"
            with open(pom_path, "w") as f:
                f.write(pom_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "java"
            assert context.type == "library"
            assert context.output_destinations == []


class TestGoDetection:
    """Test Go project detection."""

    def test_go_web_app_gin(self):
        """Test detection of Go web app with Gin framework."""
        with tempfile.TemporaryDirectory() as tmpdir:
            go_mod_content = """module github.com/example/my-api

go 1.21

require (
    github.com/gin-gonic/gin v1.9.0
    github.com/joho/godotenv v1.5.0
)
"""

            go_mod_path = Path(tmpdir) / "go.mod"
            with open(go_mod_path, "w") as f:
                f.write(go_mod_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "go"
            assert context.type == "web-application"
            assert context.framework == "gin"
            assert "browser" in context.output_destinations or "http-response" in context.output_destinations
            assert context.confidence >= 0.9

    def test_go_cli_tool_with_main(self):
        """Test detection of Go CLI tool with main.go."""
        with tempfile.TemporaryDirectory() as tmpdir:
            go_mod_content = """module github.com/example/my-cli

go 1.21

require (
    github.com/spf13/cobra v1.7.0
)
"""

            go_mod_path = Path(tmpdir) / "go.mod"
            with open(go_mod_path, "w") as f:
                f.write(go_mod_content)

            # Create main.go
            main_go_path = Path(tmpdir) / "main.go"
            with open(main_go_path, "w") as f:
                f.write("package main\n\nfunc main() {}\n")

            context = detect_project_context(tmpdir)

            assert context.runtime == "go"
            assert context.type == "cli-tool"
            assert "terminal" in context.output_destinations

    def test_go_library(self):
        """Test detection of Go library (no main.go or web framework)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            go_mod_content = """module github.com/example/my-lib

go 1.21
"""

            go_mod_path = Path(tmpdir) / "go.mod"
            with open(go_mod_path, "w") as f:
                f.write(go_mod_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "go"
            assert context.type == "library"
            assert context.output_destinations == []


class TestRustDetection:
    """Test Rust project detection."""

    @needs_toml
    def test_rust_web_app_actix(self):
        """Test detection of Rust web app with Actix framework."""

        with tempfile.TemporaryDirectory() as tmpdir:
            cargo_content = """[package]
name = "my-api"
version = "1.0.0"
edition = "2021"

[dependencies]
actix-web = "4.0"
tokio = { version = "1", features = ["full"] }
"""

            cargo_path = Path(tmpdir) / "Cargo.toml"
            with open(cargo_path, "w") as f:
                f.write(cargo_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "rust"
            assert context.type == "web-application"
            assert context.framework == "actix"
            assert "browser" in context.output_destinations or "http-response" in context.output_destinations
            assert context.confidence >= 0.9

    @needs_toml
    def test_rust_library(self):
        """Test detection of Rust library (no web framework markers)."""

        with tempfile.TemporaryDirectory() as tmpdir:
            cargo_content = """[package]
name = "my-lib"
version = "1.0.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
"""

            cargo_path = Path(tmpdir) / "Cargo.toml"
            with open(cargo_path, "w") as f:
                f.write(cargo_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "rust"
            assert context.type == "library"
            assert context.output_destinations == []


class TestUnknownProjects:
    """Test detection of unknown/unsupported project types."""

    def test_unknown_runtime_empty_directory(self):
        """Test handling of empty directory with no project files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            context = detect_project_context(tmpdir)

            assert context.runtime == "unknown"
            assert context.type == "unknown"
            assert context.confidence == 0.1

    def test_unknown_runtime_no_recognized_files(self):
        """Test handling of directory with unrecognized files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a random file
            random_file = Path(tmpdir) / "README.md"
            with open(random_file, "w") as f:
                f.write("# My Project\n")

            context = detect_project_context(tmpdir)

            assert context.runtime == "unknown"
            assert context.type == "unknown"


class TestDetectorClass:
    """Test ProjectContextDetector class methods."""

    def test_detector_initialization(self):
        """Test detector initialization with repo path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            detector = ProjectContextDetector(tmpdir)
            assert detector.repo_path == Path(tmpdir)
            assert detector.detection_details == {}

    def test_detect_runtime_nodejs(self):
        """Test _detect_runtime method for Node.js."""
        with tempfile.TemporaryDirectory() as tmpdir:
            package_path = Path(tmpdir) / "package.json"
            with open(package_path, "w") as f:
                json.dump({"name": "test"}, f)

            detector = ProjectContextDetector(tmpdir)
            runtime = detector._detect_runtime()

            assert runtime == "nodejs"
            assert "runtime_marker" in detector.detection_details

    def test_detect_runtime_python(self):
        """Test _detect_runtime method for Python."""
        with tempfile.TemporaryDirectory() as tmpdir:
            requirements_path = Path(tmpdir) / "requirements.txt"
            with open(requirements_path, "w") as f:
                f.write("requests==2.31.0\n")

            detector = ProjectContextDetector(tmpdir)
            runtime = detector._detect_runtime()

            assert runtime == "python"

    def test_detect_runtime_java(self):
        """Test _detect_runtime method for Java."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pom_path = Path(tmpdir) / "pom.xml"
            with open(pom_path, "w") as f:
                f.write("<project></project>")

            detector = ProjectContextDetector(tmpdir)
            runtime = detector._detect_runtime()

            assert runtime == "java"

    def test_detect_runtime_go(self):
        """Test _detect_runtime method for Go."""
        with tempfile.TemporaryDirectory() as tmpdir:
            go_mod_path = Path(tmpdir) / "go.mod"
            with open(go_mod_path, "w") as f:
                f.write("module example.com/myapp\n")

            detector = ProjectContextDetector(tmpdir)
            runtime = detector._detect_runtime()

            assert runtime == "go"

    def test_detect_runtime_rust(self):
        """Test _detect_runtime method for Rust."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cargo_path = Path(tmpdir) / "Cargo.toml"
            with open(cargo_path, "w") as f:
                f.write("[package]\nname = \"test\"\n")

            detector = ProjectContextDetector(tmpdir)
            runtime = detector._detect_runtime()

            assert runtime == "rust"


class TestCLIEntryPoint:
    """Test command-line interface functionality."""

    def test_detect_project_context_function(self):
        """Test the standalone detect_project_context function."""
        with tempfile.TemporaryDirectory() as tmpdir:
            package_json = {
                "name": "test-app",
                "dependencies": {
                    "express": "^4.18.0"
                }
            }

            package_path = Path(tmpdir) / "package.json"
            with open(package_path, "w") as f:
                json.dump(package_json, f)

            context = detect_project_context(tmpdir)

            assert isinstance(context, ProjectContext)
            assert context.runtime == "nodejs"
            assert context.type == "web-application"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_nodejs_bin_as_string(self):
        """Test handling of bin field as string (not dict) in package.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            package_json = {
                "name": "my-cli",
                "bin": "./bin/cli.js"
            }

            package_path = Path(tmpdir) / "package.json"
            with open(package_path, "w") as f:
                json.dump(package_json, f)

            context = detect_project_context(tmpdir)

            assert context.type == "cli-tool"
            assert context.confidence >= 0.9

    def test_mixed_cli_and_web_dependencies_nodejs(self):
        """Test handling of projects with both CLI and web dependencies (web wins)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            package_json = {
                "name": "my-app",
                "dependencies": {
                    "express": "^4.18.0",
                    "commander": "^9.0.0"
                }
            }

            package_path = Path(tmpdir) / "package.json"
            with open(package_path, "w") as f:
                json.dump(package_json, f)

            context = detect_project_context(tmpdir)

            # Web framework should take precedence
            assert context.type == "web-application"
            assert context.framework == "express"

    def test_multiple_web_frameworks_nodejs(self):
        """Test handling of multiple web frameworks (first detected wins)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            package_json = {
                "name": "my-app",
                "dependencies": {
                    "express": "^4.18.0",
                    "fastify": "^4.0.0"
                }
            }

            package_path = Path(tmpdir) / "package.json"
            with open(package_path, "w") as f:
                json.dump(package_json, f)

            context = detect_project_context(tmpdir)

            assert context.type == "web-application"
            assert context.framework in ["express", "fastify"]

    def test_python_setup_py_without_console_scripts(self):
        """Test Python project with setup.py but no console_scripts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            setup_content = """
from setuptools import setup

setup(
    name='my-lib',
    version='1.0.0',
)
"""

            setup_path = Path(tmpdir) / "setup.py"
            with open(setup_path, "w") as f:
                f.write(setup_content)

            context = detect_project_context(tmpdir)

            assert context.runtime == "python"
            assert context.type == "library"

    def test_python_invalid_pyproject_toml(self):
        """Test handling of invalid pyproject.toml."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pyproject_path = Path(tmpdir) / "pyproject.toml"
            with open(pyproject_path, "w") as f:
                f.write("[invalid toml syntax")

            # Should fall back to library type
            context = detect_project_context(tmpdir)

            assert context.runtime == "python"

    def test_case_insensitive_dependency_matching(self):
        """Test case-insensitive matching of Python dependencies."""
        with tempfile.TemporaryDirectory() as tmpdir:
            requirements_content = """
DJANGO==4.2.0
Flask==2.3.0
"""

            requirements_path = Path(tmpdir) / "requirements.txt"
            with open(requirements_path, "w") as f:
                f.write(requirements_content)

            context = detect_project_context(tmpdir)

            # Should still detect Django despite uppercase
            assert context.type == "web-application"
