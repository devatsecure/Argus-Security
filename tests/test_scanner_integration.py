"""Integration tests for scanner module wiring.

These tests verify that hybrid_analyzer.py and scanner_runners.py
reference correct constructors and methods, preventing Docker runtime failures.

The #1 recurring bug has been constructor/method mismatches between
hybrid_analyzer.py and the actual scanner modules. Unit tests pass because
everything is mocked, but Docker runs fail. These tests catch mismatches at
PR time by importing real modules and inspecting real signatures.
"""

import importlib
import inspect
import sys
from pathlib import Path

import pytest

# Ensure scripts/ is on sys.path (also handled by conftest.py)
_scripts_dir = str(Path(__file__).resolve().parent.parent / "scripts")
if _scripts_dir not in sys.path:
    sys.path.insert(0, _scripts_dir)

# ---------------------------------------------------------------------------
# Scanner Registry -- source of truth derived from hybrid_analyzer.py
# constructor calls and scanner_runners.py method calls.
#
# Format: (module_path, class_name, init_kwargs, runner_method)
#   module_path  : importable module name (relative to scripts/)
#   class_name   : class instantiated in hybrid_analyzer.py
#   init_kwargs  : list of keyword argument names passed to __init__
#   runner_method: method invoked by scanner_runners.py (or hybrid_analyzer.py
#                  directly for scanners without a dedicated runner function)
# ---------------------------------------------------------------------------
SCANNER_REGISTRY = [
    ("semgrep_scanner", "SemgrepScanner", [], "scan"),
    ("trufflehog_scanner", "TruffleHogScanner", [], "scan"),
    (
        "trivy_scanner",
        "TrivyScanner",
        ["foundation_sec_enabled", "foundation_sec_model"],
        "scan_filesystem",
    ),
    ("checkov_scanner", "CheckovScanner", [], "scan"),
    ("api_security_scanner", "APISecurityScanner", [], "scan"),
    (
        "dast_scanner",
        "DASTScanner",
        ["target_url", "openapi_spec"],
        "scan",
    ),
    ("supply_chain_analyzer", "SupplyChainAnalyzer", [], "analyze_dependency_diff"),
    ("fuzzing_engine", "FuzzingEngine", ["llm_manager"], "fuzz_function"),
    ("threat_intel_enricher", "ThreatIntelEnricher", [], "enrich_cve"),
    ("remediation_engine", "RemediationEngine", ["llm_manager"], "suggest_fix"),
    ("runtime_security_monitor", "RuntimeSecurityMonitor", [], "monitor_realtime"),
    ("regression_tester", "RegressionTester", [], "run_all_tests"),
]

# Readable IDs for pytest parametrize output
_IDS = [entry[1] for entry in SCANNER_REGISTRY]


@pytest.mark.parametrize(
    "module_path,class_name,init_kwargs,method_name",
    SCANNER_REGISTRY,
    ids=_IDS,
)
class TestScannerWiring:
    """Verify that hybrid_analyzer.py and scanner_runners.py reference
    correct module paths, class names, constructor kwargs, and runner methods.
    """

    def test_module_imports(self, module_path, class_name, init_kwargs, method_name):
        """Verify scanner module can be imported."""
        mod = importlib.import_module(module_path)
        assert mod is not None, f"Failed to import {module_path}"

    def test_class_exists(self, module_path, class_name, init_kwargs, method_name):
        """Verify expected class exists in module."""
        mod = importlib.import_module(module_path)
        assert hasattr(mod, class_name), (
            f"{class_name} not found in {module_path}. "
            f"Available names: {[n for n in dir(mod) if not n.startswith('_')]}"
        )

    def test_constructor_accepts_kwargs(
        self, module_path, class_name, init_kwargs, method_name
    ):
        """Verify constructor accepts the kwargs that hybrid_analyzer.py passes.

        A kwarg is considered accepted if it appears as a named parameter
        in __init__, OR if __init__ has a **kwargs catch-all.
        """
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        sig = inspect.signature(cls.__init__)
        params = sig.parameters

        has_var_keyword = any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
        )

        named_params = set(params.keys()) - {"self"}

        for kwarg in init_kwargs:
            assert kwarg in named_params or has_var_keyword, (
                f"{class_name}.__init__ does not accept kwarg '{kwarg}'. "
                f"Accepted params: {sorted(named_params)}"
            )

    def test_runner_method_exists(
        self, module_path, class_name, init_kwargs, method_name
    ):
        """Verify the method called by scanner_runners.py (or hybrid_analyzer.py)
        exists on the class."""
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        assert hasattr(cls, method_name), (
            f"{class_name}.{method_name}() not found. "
            f"Available methods: {[m for m in dir(cls) if not m.startswith('_')]}"
        )

    def test_runner_method_is_callable(
        self, module_path, class_name, init_kwargs, method_name
    ):
        """Verify the runner method is actually callable (not just an attribute)."""
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        method = getattr(cls, method_name)
        assert callable(method), (
            f"{class_name}.{method_name} exists but is not callable"
        )
