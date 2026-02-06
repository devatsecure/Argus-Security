#!/usr/bin/env python3
"""
Docker Manager for Argus Sandbox
Adapted from Strix's docker_runtime.py for safe exploit validation

Provides isolated Docker containers with:
- Multi-language support (Python, JS, Java, Go)
- Resource limits (CPU, memory)
- Network isolation
- Safe cleanup
"""

import contextlib
import logging
import os
import secrets
import shlex
import socket
import time
from pathlib import Path
from typing import Optional, cast

try:
    from docker.errors import DockerException, ImageNotFound, NotFound
    from docker.models.containers import Container

    import docker

    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    Container = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DockerManager:
    """Manages Docker containers for safe exploit validation"""

    # Default image (will be built from our Dockerfile)
    DEFAULT_IMAGE = os.getenv("ARGUS_SANDBOX_IMAGE", "argus-sandbox:latest")

    def __init__(self, image: Optional[str] = None):
        """
        Initialize Docker manager

        Args:
            image: Docker image to use (defaults to DEFAULT_IMAGE)
        """
        if not DOCKER_AVAILABLE:
            raise RuntimeError("Docker Python SDK not available. Install with: pip install docker")

        try:
            # Try to connect using environment variables first
            self.client = docker.from_env()
            self.client.ping()
        except DockerException as e:
            # Fall back to common Docker socket paths (macOS Docker Desktop uses ~/.docker/run/docker.sock)
            logger.info("Failed to connect with from_env(), trying alternative socket paths...")
            socket_paths = [
                f"{Path.home()}/.docker/run/docker.sock",  # macOS Docker Desktop
                "/var/run/docker.sock",  # Linux default
                "/run/user/1000/docker.sock",  # Rootless Docker
            ]

            connected = False
            for socket_path in socket_paths:
                if Path(socket_path).exists():
                    try:
                        logger.info(f"Trying Docker socket at: {socket_path}")
                        self.client = docker.DockerClient(base_url=f"unix://{socket_path}")
                        self.client.ping()
                        logger.info(f"✅ Connected to Docker via {socket_path}")
                        connected = True
                        break
                    except Exception as sock_err:
                        logger.debug(f"Failed to connect to {socket_path}: {sock_err}")
                        continue

            if not connected:
                logger.exception("Failed to connect to Docker daemon")
                raise RuntimeError(
                    "Docker is not available or not running. Please ensure Docker is installed and running."
                ) from e

        self.image = image or self.DEFAULT_IMAGE
        self._containers: dict[str, Container] = {}

    def _generate_token(self) -> str:
        """Generate a secure random token"""
        return secrets.token_urlsafe(32)

    def _find_available_port(self) -> int:
        """Find an available port on the host"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Bind to localhost only for security (not 0.0.0.0)
            s.bind(("127.0.0.1", 0))
            return cast(int, s.getsockname()[1])

    def _verify_image_available(self, max_retries: int = 3) -> None:
        """
        Verify that the Docker image is available

        Args:
            max_retries: Maximum number of retry attempts
        """
        for attempt in range(max_retries):
            try:
                image = self.client.images.get(self.image)
                if not image.id or not image.attrs:
                    raise ImageNotFound(f"Image {self.image} metadata incomplete")
                logger.debug(f"Image {self.image} verified as available")
                return
            except ImageNotFound:
                if attempt == max_retries - 1:
                    logger.error(
                        f"Image {self.image} not found. "
                        f"Build it with: docker build -f docker/security-sandbox.dockerfile "
                        f"-t {self.image} ."
                    )
                    raise
                logger.warning(f"Image {self.image} not ready, attempt {attempt + 1}/{max_retries}")
                time.sleep(2**attempt)
            except DockerException:
                if attempt == max_retries - 1:
                    logger.exception(f"Failed to verify image {self.image}")
                    raise
                logger.warning(f"Docker error verifying image, attempt {attempt + 1}/{max_retries}")
                time.sleep(2**attempt)

    def create_container(
        self,
        name: Optional[str] = None,
        cpu_limit: float = 1.0,
        memory_limit: str = "512m",
        network_disabled: bool = True,
        timeout: int = 300,
        environment: Optional[dict[str, str]] = None,
    ) -> str:
        """
        Create a new isolated Docker container

        Args:
            name: Container name (auto-generated if not provided)
            cpu_limit: CPU limit (e.g., 1.0 = 1 CPU core)
            memory_limit: Memory limit (e.g., "512m", "1g")
            network_disabled: Disable network access for security
            timeout: Container execution timeout in seconds
            environment: Additional environment variables

        Returns:
            Container ID
        """
        if not name:
            name = f"argus-sandbox-{secrets.token_hex(8)}"

        # Clean up any existing container with the same name
        try:
            existing = self.client.containers.get(name)
            logger.warning(f"Container {name} already exists, removing it")
            with contextlib.suppress(Exception):
                existing.stop(timeout=5)
            existing.remove(force=True)
            time.sleep(1)
        except NotFound:
            pass
        except DockerException as e:
            logger.warning(f"Error checking/removing existing container: {e}")

        # Verify image is available
        self._verify_image_available()

        # Prepare environment variables
        env = {
            "PYTHONUNBUFFERED": "1",
            "SANDBOX_MODE": "true",
            "EXECUTION_TIMEOUT": str(timeout),
        }
        if environment:
            env.update(environment)

        try:
            # Create container with resource limits
            container = self.client.containers.run(
                self.image,
                command="sleep infinity",
                detach=True,
                name=name,
                hostname=name,
                network_mode="none" if network_disabled else "bridge",
                cpu_quota=int(cpu_limit * 100000),
                cpu_period=100000,
                mem_limit=memory_limit,
                memswap_limit=memory_limit,  # No swap
                pids_limit=100,  # Limit number of processes
                read_only=True,  # Read-only root filesystem
                tmpfs={"/tmp": "noexec,size=100m,mode=1777"},  # Temporary filesystem (noexec)
                cap_drop=["ALL"],  # Drop all Linux capabilities
                security_opt=["no-new-privileges:true"],  # Prevent privilege escalation
                environment=env,
                labels={
                    "argus-sandbox": "true",
                    "created_at": str(int(time.time())),
                },
                remove=False,  # Don't auto-remove (we'll do it explicitly)
            )

            container_id = container.id
            self._containers[container_id] = container
            logger.info(f"Created container {name} (ID: {container_id[:12]})")

            return container_id

        except DockerException as e:
            logger.exception(f"Failed to create container {name}")
            raise RuntimeError(f"Failed to create Docker container: {e}") from e

    def execute_code(
        self,
        container_id: str,
        code: str,
        language: str = "python",
        timeout: int = 30,
        working_dir: str = "/workspace",
    ) -> dict[str, any]:
        """
        Execute code in a container

        Args:
            container_id: Container ID
            code: Code to execute
            language: Programming language (python, javascript, java, go)
            timeout: Execution timeout in seconds (must be positive integer)
            working_dir: Working directory for execution (must be valid path)

        Returns:
            Dict with stdout, stderr, exit_code, and success
        """
        if container_id not in self._containers:
            raise ValueError(f"Container {container_id} not found")

        # Input validation
        if not isinstance(timeout, int) or timeout <= 0:
            raise ValueError(f"Timeout must be a positive integer, got: {timeout}")

        if not working_dir or not isinstance(working_dir, str):
            raise ValueError(f"Working directory must be a non-empty string, got: {working_dir}")

        container = self._containers[container_id]

        # Build command list safely without shell injection vulnerabilities
        # Each element is a separate argument, preventing injection
        cmd_list = [
            "timeout",
            str(timeout),
        ]

        if language == "python":
            cmd_list.extend(["python3", "-c", code])
        elif language in ("javascript", "js", "node"):
            cmd_list.extend(["node", "-e", code])
        elif language == "java":
            # For Java, code should be a filename
            cmd_list.extend(["java", code])
        elif language == "go":
            # For Go, code should be a filename
            cmd_list.extend(["go", "run", code])
        elif language == "bash":
            # For bash, wrap the code in bash -c with the code as a single argument
            cmd_list.extend(["bash", "-c", code])
        else:
            raise ValueError(f"Unsupported language: {language}")

        try:
            result = container.exec_run(
                cmd=cmd_list,
                demux=True,
                workdir=working_dir,
            )

            stdout = result.output[0].decode("utf-8") if result.output[0] else ""
            stderr = result.output[1].decode("utf-8") if result.output[1] else ""
            exit_code = result.exit_code

            return {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "success": exit_code == 0,
            }

        except DockerException as e:
            logger.exception(f"Failed to execute code in container {container_id}")
            return {
                "stdout": "",
                "stderr": f"Execution failed: {e}",
                "exit_code": -1,
                "success": False,
            }

    def copy_to_container(
        self,
        container_id: str,
        local_path: str,
        container_path: str = "/workspace",
        allowed_base: Optional[Path] = None,
    ) -> bool:
        """
        Copy files from local filesystem to container with path traversal protection.

        This method validates all paths to prevent directory traversal attacks,
        symbolic link escapes, and other path-based security issues.

        Args:
            container_id: Container ID
            local_path: Local file or directory path
            container_path: Destination path in container
            allowed_base: Base directory for path validation (defaults to cwd)

        Returns:
            True if successful

        Raises:
            ValueError: If container not found or path validation fails
        """
        if container_id not in self._containers:
            raise ValueError(f"Container {container_id} not found")

        container = self._containers[container_id]

        try:
            import tarfile
            from io import BytesIO

            # Validate the local path to prevent directory traversal attacks
            local_path_obj = Path(local_path)
            try:
                validated_path = self._validate_path(local_path_obj, allowed_base)
            except ValueError as e:
                logger.error(f"Path validation failed for {local_path}: {e}")
                raise

            if not validated_path.exists():
                logger.error(f"Local path does not exist: {validated_path}")
                return False

            tar_buffer = BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
                if validated_path.is_file():
                    tar.add(validated_path, arcname=validated_path.name)
                else:
                    # When adding directory contents, validate each file path
                    for item in validated_path.rglob("*"):
                        if item.is_file():
                            # Verify each item is still within allowed bounds
                            try:
                                self._validate_path(item, allowed_base)
                            except ValueError as e:
                                logger.error(
                                    f"Path validation failed for file in archive {item}: {e}"
                                )
                                raise
                            rel_path = item.relative_to(validated_path)
                            tar.add(item, arcname=rel_path)

            tar_buffer.seek(0)
            container.put_archive(container_path, tar_buffer.getvalue())

            logger.info(
                f"Copied {validated_path} to container {container_id[:12]}:{container_path}"
            )
            return True

        except ValueError as e:
            # Path validation errors should be raised, not caught
            logger.error(f"Path validation error in copy_to_container: {e}")
            raise
        except (OSError, DockerException) as e:
            logger.exception(f"Failed to copy files to container {container_id}: {e}")
            return False

    def get_container_logs(self, container_id: str, tail: int = 100) -> str:
        """
        Get container logs

        Args:
            container_id: Container ID
            tail: Number of lines to return from end

        Returns:
            Log output
        """
        if container_id not in self._containers:
            raise ValueError(f"Container {container_id} not found")

        container = self._containers[container_id]

        try:
            logs = container.logs(tail=tail).decode("utf-8")
            return logs
        except DockerException as e:
            logger.exception(f"Failed to get logs for container {container_id}")
            return f"Failed to get logs: {e}"

    def stop_container(self, container_id: str, timeout: int = 10) -> bool:
        """
        Stop a container

        Args:
            container_id: Container ID
            timeout: Timeout for graceful shutdown

        Returns:
            True if successful
        """
        if container_id not in self._containers:
            logger.warning(f"Container {container_id} not found in managed containers")
            return False

        container = self._containers[container_id]

        try:
            container.stop(timeout=timeout)
            logger.info(f"Stopped container {container_id[:12]}")
            return True
        except DockerException:
            logger.exception(f"Failed to stop container {container_id}")
            return False

    def remove_container(self, container_id: str, force: bool = True) -> bool:
        """
        Remove a container

        Args:
            container_id: Container ID
            force: Force removal even if running

        Returns:
            True if successful
        """
        if container_id not in self._containers:
            logger.warning(f"Container {container_id} not found in managed containers")
            return False

        container = self._containers[container_id]

        try:
            container.remove(force=force)
            del self._containers[container_id]
            logger.info(f"Removed container {container_id[:12]}")
            return True
        except DockerException:
            logger.exception(f"Failed to remove container {container_id}")
            return False

    def cleanup_all(self) -> None:
        """Clean up all managed containers"""
        container_ids = list(self._containers.keys())
        for container_id in container_ids:
            try:
                self.stop_container(container_id, timeout=5)
                self.remove_container(container_id, force=True)
            except Exception as e:
                logger.warning(f"Failed to clean up container {container_id}: {e}")

        logger.info(f"Cleaned up {len(container_ids)} containers")

    def list_containers(self) -> list[dict[str, any]]:
        """
        List all argus sandbox containers

        Returns:
            List of container info dicts
        """
        try:
            containers = self.client.containers.list(all=True, filters={"label": "argus-sandbox=true"})

            return [
                {
                    "id": c.id[:12],
                    "name": c.name,
                    "status": c.status,
                    "created": c.attrs.get("Created", "unknown"),
                }
                for c in containers
            ]
        except DockerException:
            logger.exception("Failed to list containers")
            return []

    def _validate_path(self, path: Path, allowed_base: Optional[Path] = None) -> Path:
        """
        Validate a path to prevent directory traversal attacks.

        This method ensures that the resolved path:
        - Does not contain symbolic links pointing outside allowed directories
        - Does not escape the allowed base directory using ../ or similar tricks
        - Resolves to a real path within the allowed boundaries

        Args:
            path: Path object to validate
            allowed_base: Base directory path must be relative to (defaults to cwd)

        Returns:
            Resolved Path object if validation passes

        Raises:
            ValueError: If path traversal or symbolic link escape detected
        """
        if allowed_base is None:
            allowed_base = Path.cwd()

        # Resolve the path to absolute and eliminate symbolic links
        try:
            resolved_path = path.resolve(strict=False)
        except (OSError, ValueError) as e:
            logger.error(f"Failed to resolve path {path}: {e}")
            raise ValueError(f"Invalid path {path}: {e}") from e

        # Ensure resolved path is relative to allowed base
        try:
            resolved_path.relative_to(allowed_base)
        except ValueError:
            logger.error(
                f"Path traversal attempt detected: {path} resolves to {resolved_path} "
                f"which is outside allowed base {allowed_base}"
            )
            raise ValueError(
                f"Path {path} escapes allowed directory {allowed_base}. "
                "Path traversal attacks are not allowed."
            )

        # Check for symbolic links that might escape the allowed directory
        current = resolved_path
        while current != current.parent:
            try:
                if current.is_symlink():
                    link_target = current.resolve(strict=False)
                    try:
                        link_target.relative_to(allowed_base)
                    except ValueError:
                        logger.error(
                            f"Symbolic link escape attempt detected: {current} -> {link_target} "
                            f"which is outside allowed base {allowed_base}"
                        )
                        raise ValueError(
                            f"Symbolic link {current} points outside allowed directory. "
                            "Symbolic link escapes are not allowed."
                        )
            except (OSError, ValueError) as e:
                if isinstance(e, ValueError) and "points outside" in str(e):
                    raise
                logger.warning(f"Could not check symlink for {current}: {e}")

            current = current.parent

        logger.debug(f"Path validation successful for {resolved_path}")
        return resolved_path

    def _quote(self, s: str) -> str:
        """
        Quote a string for safe shell execution.

        DEPRECATED: Use list-based command construction with exec_run(cmd=[...])
        instead of building shell command strings.

        This method uses single-quote escaping which is safe for single-quoted
        strings in POSIX shells, but shell-based command construction is inherently
        more error-prone than list-based subprocess calls.

        Args:
            s: String to quote

        Returns:
            Properly single-quoted string safe for shell execution
        """
        # Replace single quotes with '\'' (end quote, escaped quote, start quote)
        # This is the standard POSIX shell escaping mechanism
        return f"'{s.replace(chr(39), chr(39) + chr(92) + chr(39) + chr(39))}'"

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup all containers"""
        self.cleanup_all()


if __name__ == "__main__":
    # Example usage
    print("Docker Manager - Example Usage")
    print("=" * 50)

    try:
        with DockerManager() as manager:
            # Create container
            container_id = manager.create_container(
                name="test-sandbox",
                memory_limit="256m",
                cpu_limit=0.5,
            )
            print(f"Created container: {container_id[:12]}")

            # Execute Python code
            result = manager.execute_code(
                container_id,
                "print('Hello from sandbox!')",
                language="python",
            )
            print(f"Execution result: {result}")

            # List containers
            containers = manager.list_containers()
            print(f"Active containers: {len(containers)}")

    except Exception as e:
        print(f"Error: {e}")
