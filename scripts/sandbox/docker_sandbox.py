#!/usr/bin/env python3
"""
Docker Sandbox for Fuzzing Engine
Provides safe execution of untrusted code in isolated Docker containers

This module wraps DockerManager to provide specialized fuzzing sandbox capabilities:
- Execute Python functions from untrusted modules
- Resource limits (CPU, memory, time)
- Network isolation
- Automatic cleanup
- Result capture and analysis
"""

import json
import logging

# Import the existing Docker infrastructure
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from docker_manager import DockerManager

    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    logging.warning("DockerManager not available - sandbox disabled")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class SandboxConfig:
    """Configuration for sandbox execution"""

    cpu_limit: float = 1.0  # CPU cores
    memory_limit: str = "512m"  # Memory limit
    timeout: int = 60  # Execution timeout in seconds
    network_disabled: bool = True  # Disable network access
    enable_coverage: bool = False  # Track code coverage


@dataclass
class SandboxResult:
    """Result from sandbox execution"""

    success: bool
    output: str
    error: str
    exit_code: int
    execution_time_ms: int
    crashed: bool
    crash_type: Optional[str] = None
    stack_trace: str = ""
    lines_executed: Optional[set[int]] = None


class DockerSandbox:
    """
    Docker-based sandbox for safe execution of untrusted code

    This sandbox provides isolation for fuzzing operations, preventing
    untrusted code from:
    - Accessing the host filesystem
    - Making network connections
    - Consuming excessive resources
    - Affecting other processes

    Usage:
        sandbox = DockerSandbox(cpu_limit=1.0, memory_limit="512m", timeout=60)
        result = sandbox.execute_python(code, function_name, test_input)
        sandbox.cleanup()
    """

    def __init__(self, config: Optional[SandboxConfig] = None):
        """
        Initialize Docker sandbox

        Args:
            config: Sandbox configuration (uses defaults if None)

        Raises:
            RuntimeError: If Docker is not available
        """
        if not DOCKER_AVAILABLE:
            raise RuntimeError("Docker support not available. Install with: pip install docker")

        self.config = config or SandboxConfig()
        self.docker_manager = DockerManager()
        self.container_id: Optional[str] = None
        self._execution_count = 0

        logger.info(
            f"Initialized DockerSandbox: CPU={self.config.cpu_limit}, "
            f"Memory={self.config.memory_limit}, Timeout={self.config.timeout}s"
        )

    def create_container(self) -> str:
        """
        Create a new sandbox container

        Returns:
            Container ID

        Raises:
            RuntimeError: If container creation fails
        """
        try:
            self.container_id = self.docker_manager.create_container(
                name=f"fuzzing-sandbox-{int(time.time())}",
                cpu_limit=self.config.cpu_limit,
                memory_limit=self.config.memory_limit,
                network_disabled=self.config.network_disabled,
                timeout=self.config.timeout,
                environment={"PYTHONUNBUFFERED": "1", "FUZZING_MODE": "true"},
            )
            logger.info(f"Created sandbox container: {self.container_id[:12]}")
            return self.container_id

        except Exception as e:
            logger.error(f"Failed to create sandbox container: {e}")
            raise RuntimeError(f"Container creation failed: {e}") from e

    def execute_python(
        self, code: str, function_name: str, test_input: Any, timeout: Optional[int] = None
    ) -> SandboxResult:
        """
        Execute a Python function with test input in the sandbox

        This is the main method for safe fuzzing execution. It:
        1. Wraps the function code in a safe execution wrapper
        2. Serializes the test input
        3. Executes in isolated Docker container
        4. Captures all output and errors
        5. Returns structured result

        Args:
            code: Python source code containing the function
            function_name: Name of function to call
            test_input: Input to pass to the function
            timeout: Optional execution timeout (uses config default if None)

        Returns:
            SandboxResult with execution details
        """
        start_time = time.time()
        self._execution_count += 1

        # Create container if needed
        if not self.container_id:
            self.create_container()

        # Build safe execution wrapper
        wrapped_code = self._build_execution_wrapper(code, function_name, test_input)

        # Execute in sandbox
        exec_timeout = timeout or self.config.timeout

        try:
            result = self.docker_manager.execute_code(
                self.container_id, wrapped_code, language="python", timeout=exec_timeout, working_dir="/tmp"
            )

            execution_time_ms = int((time.time() - start_time) * 1000)

            # Parse result
            return self._parse_result(result, execution_time_ms)

        except Exception as e:
            execution_time_ms = int((time.time() - start_time) * 1000)
            logger.error(f"Sandbox execution failed: {e}")

            return SandboxResult(
                success=False,
                output="",
                error=str(e),
                exit_code=-1,
                execution_time_ms=execution_time_ms,
                crashed=True,
                crash_type="sandbox_error",
                stack_trace=str(e),
            )

    def execute_python_module(
        self, module_path: str, function_name: str, test_input: Any, timeout: Optional[int] = None
    ) -> SandboxResult:
        """
        Execute a function from a Python module file in the sandbox

        Args:
            module_path: Path to Python module file
            function_name: Name of function to call
            test_input: Input to pass to the function
            timeout: Optional execution timeout

        Returns:
            SandboxResult with execution details
        """
        # Read the module code
        try:
            with open(module_path) as f:
                code = f.read()
        except Exception as e:
            logger.error(f"Failed to read module {module_path}: {e}")
            return SandboxResult(
                success=False,
                output="",
                error=f"Failed to read module: {e}",
                exit_code=-1,
                execution_time_ms=0,
                crashed=True,
                crash_type="file_read_error",
                stack_trace=str(e),
            )

        # Execute the code
        return self.execute_python(code, function_name, test_input, timeout)

    def _build_execution_wrapper(self, code: str, function_name: str, test_input: Any) -> str:
        """
        Build a safe execution wrapper for the target code

        The wrapper:
        - Imports the function code as a module
        - Calls the function with the test input
        - Captures output and errors
        - Returns structured JSON result

        Args:
            code: Source code containing the function
            function_name: Function to call
            test_input: Input to pass

        Returns:
            Wrapped Python code as string
        """
        # Serialize test input to JSON
        try:
            input_json = json.dumps(test_input)
        except (TypeError, ValueError):
            # If input isn't JSON-serializable, use repr
            input_json = json.dumps(repr(test_input))

        # Build wrapper code
        wrapper = f'''
import sys
import json
import traceback
import inspect

# Function code to test
CODE = {repr(code)}

# Test input
TEST_INPUT = {input_json}
FUNCTION_NAME = {repr(function_name)}

def run_test():
    """Execute the test in isolated namespace"""
    try:
        # Create a clean namespace for execution
        namespace = {{'__name__': '__main__'}}

        # Execute the code
        exec(CODE, namespace)

        # Get the function
        if FUNCTION_NAME not in namespace:
            print(json.dumps({{
                "success": False,
                "error": f"Function {{FUNCTION_NAME}} not found in code",
                "crashed": True,
                "crash_type": "function_not_found"
            }}))
            return

        func = namespace[FUNCTION_NAME]

        # Inspect function signature
        sig = inspect.signature(func)
        params = list(sig.parameters.values())

        # Call function with appropriate arguments
        if len(params) == 0:
            result = func()
        elif len(params) == 1:
            result = func(TEST_INPUT)
        else:
            # Multiple parameters - try to unpack if input is list/tuple
            if isinstance(TEST_INPUT, (list, tuple)):
                result = func(*TEST_INPUT[:len(params)])
            else:
                # Pass same input to all parameters
                result = func(*[TEST_INPUT] * len(params))

        # Success
        print(json.dumps({{
            "success": True,
            "output": str(result),
            "error": "",
            "crashed": False
        }}))

    except TimeoutError:
        print(json.dumps({{
            "success": False,
            "error": "Execution timeout",
            "crashed": True,
            "crash_type": "timeout",
            "stack_trace": traceback.format_exc()
        }}))

    except AssertionError as e:
        print(json.dumps({{
            "success": False,
            "error": str(e),
            "crashed": True,
            "crash_type": "assertion",
            "stack_trace": traceback.format_exc()
        }}))

    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as e:
        # Check if it's a severe error
        error_str = str(e).lower()
        if "buffer" in error_str or "overflow" in error_str:
            print(json.dumps({{
                "success": False,
                "error": str(e),
                "crashed": True,
                "crash_type": "exception",
                "stack_trace": traceback.format_exc()
            }}))
        else:
            # Might be expected for bad inputs
            print(json.dumps({{
                "success": False,
                "error": str(e),
                "crashed": False,
                "stack_trace": traceback.format_exc()
            }}))

    except Exception as e:
        print(json.dumps({{
            "success": False,
            "error": str(e),
            "crashed": True,
            "crash_type": "exception",
            "stack_trace": traceback.format_exc()
        }}))

if __name__ == "__main__":
    run_test()
'''
        return wrapper

    def _parse_result(self, docker_result: dict, execution_time_ms: int) -> SandboxResult:
        """
        Parse Docker execution result into SandboxResult

        Args:
            docker_result: Result from docker_manager.execute_code
            execution_time_ms: Execution time in milliseconds

        Returns:
            SandboxResult
        """
        stdout = docker_result.get("stdout", "")
        stderr = docker_result.get("stderr", "")
        exit_code = docker_result.get("exit_code", -1)

        # Try to parse JSON output from wrapper
        try:
            # The wrapper outputs JSON to stdout
            result_data = json.loads(stdout.strip())

            return SandboxResult(
                success=result_data.get("success", False),
                output=result_data.get("output", ""),
                error=result_data.get("error", ""),
                exit_code=exit_code,
                execution_time_ms=execution_time_ms,
                crashed=result_data.get("crashed", False),
                crash_type=result_data.get("crash_type"),
                stack_trace=result_data.get("stack_trace", ""),
            )

        except (json.JSONDecodeError, ValueError) as e:
            # Failed to parse JSON - execution likely crashed hard
            logger.warning(f"Failed to parse sandbox result: {e}")

            # Determine crash type from stderr
            crash_type = "unknown"
            if "timeout" in stderr.lower() or exit_code == 124:
                crash_type = "timeout"
            elif "segmentation fault" in stderr.lower():
                crash_type = "segfault"
            elif "killed" in stderr.lower():
                crash_type = "killed"

            return SandboxResult(
                success=False,
                output=stdout,
                error=stderr,
                exit_code=exit_code,
                execution_time_ms=execution_time_ms,
                crashed=True,
                crash_type=crash_type,
                stack_trace=stderr,
            )

    def cleanup(self):
        """
        Clean up sandbox resources

        Stops and removes the container. Should be called when done with the sandbox.
        """
        if self.container_id:
            try:
                logger.info(
                    f"Cleaning up sandbox container {self.container_id[:12]} ({self._execution_count} executions)"
                )
                self.docker_manager.stop_container(self.container_id, timeout=5)
                self.docker_manager.remove_container(self.container_id, force=True)
                self.container_id = None
            except Exception as e:
                logger.warning(f"Failed to cleanup sandbox: {e}")

    def __enter__(self):
        """Context manager entry"""
        self.create_container()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup"""
        self.cleanup()


def test_sandbox():
    """Test the DockerSandbox functionality"""
    print("Testing DockerSandbox...")
    print("=" * 50)

    # Test code
    test_code = '''
def vulnerable_function(user_input):
    """Intentionally vulnerable function for testing"""
    # This would be unsafe outside sandbox
    result = eval(user_input)
    return result
'''

    # Test with sandbox
    try:
        with DockerSandbox() as sandbox:
            # Safe input
            print("\n1. Testing with safe input...")
            result = sandbox.execute_python(test_code, "vulnerable_function", "1 + 1")
            print(f"Result: {result}")
            print(f"Success: {result.success}")
            print(f"Output: {result.output}")

            # Malicious input (would be dangerous outside sandbox)
            print("\n2. Testing with malicious input (safely contained)...")
            result = sandbox.execute_python(test_code, "vulnerable_function", "__import__('os').system('ls')")
            print(f"Result: {result}")
            print(f"Crashed: {result.crashed}")

            print("\n✓ Sandbox test completed successfully")

    except Exception as e:
        print(f"\n✗ Sandbox test failed: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    test_sandbox()
