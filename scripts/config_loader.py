"""
Configuration Loader for Argus Security Pipeline.

Implements a layered configuration system:
    hardcoded defaults < profile YAML < .argus.yml < env vars < CLI args

Usage:
    from config_loader import build_unified_config, load_profile
    config = build_unified_config(profile="standard", cli_args=args)
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Project root detection
# ---------------------------------------------------------------------------

def _find_project_root() -> Path:
    """Find the Argus project root by looking for known markers."""
    # Walk up from this file's directory
    current = Path(__file__).resolve().parent
    for ancestor in [current, *current.parents]:
        if (ancestor / "profiles").is_dir() and (ancestor / "scripts").is_dir():
            return ancestor
        if (ancestor / "action.yml").is_file():
            return ancestor
    return current.parent


PROJECT_ROOT = _find_project_root()

# ---------------------------------------------------------------------------
# Default configuration (all 47+ parameters)
# ---------------------------------------------------------------------------

def get_default_config() -> Dict[str, Any]:
    """Return all configuration parameters with sensible defaults.

    This is the lowest-priority layer.  Every configurable key must appear
    here so that downstream code never needs to guard against missing keys.
    """
    return {
        # -- AI --
        "ai_provider": "auto",
        "model": "auto",
        "multi_agent_mode": "single",
        "anthropic_api_key": "",
        "openai_api_key": "",
        "ollama_endpoint": "",

        # -- Scanner toggles --
        "enable_semgrep": True,
        "enable_trivy": True,
        "enable_checkov": True,
        "enable_api_security": True,
        "enable_dast": False,
        "enable_supply_chain": True,
        "enable_fuzzing": False,
        "enable_threat_intel": True,
        "enable_remediation": True,
        "enable_runtime_security": False,
        "enable_regression_testing": True,

        # -- MCP Server --
        "enable_mcp_server": False,

        # -- DAST auth --
        "dast_auth_config_path": "",
        "dast_enable_totp": True,

        # -- Feature toggles --
        "enable_multi_agent": True,
        "enable_spontaneous_discovery": True,
        "enable_collaborative_reasoning": False,
        "enable_ai_enrichment": True,
        "enable_threat_modeling": True,
        "enable_sandbox_validation": True,
        "enable_heuristics": True,
        "enable_consensus": True,
        "enable_iris": True,
        "enable_exploit_analysis": True,
        "enable_proof_by_exploitation": False,  # opt-in: LLM-powered PoC generation + sandbox validation
        "max_exploit_attempts": 10,
        "generate_security_tests": True,

        # -- Audit Trail --
        "enable_audit_trail": True,
        "audit_save_prompts": True,

        # -- Smart Retry --
        "enable_smart_retry": True,
        "retry_max_attempts": 3,
        "retry_billing_delay": 60,

        # -- Limits --
        "max_files": 50,
        "max_file_size": 50000,
        "max_tokens": 8000,
        "cost_limit": 1.0,
        "consensus_threshold": 0.5,
        "exploitability_threshold": "moderate",
        "fuzzing_duration": 300,
        "runtime_monitoring_duration": 60,

        # -- Files --
        "only_changed": False,
        "include_paths": "",
        "exclude_paths": ".github/**,node_modules/**,*.lock,package-lock.json",

        # -- Deep analysis --
        "deep_analysis_mode": "off",
        "deep_analysis_max_files": 50,
        "deep_analysis_timeout": 300,
        "deep_analysis_cost_ceiling": 5.0,

        # -- Output --
        "review_type": "audit",
        "project_type": "auto",
        "fail_on": "",

        # -- Parallel agents --
        "enable_parallel_agents": True,
        "parallel_agent_workers": 3,

        # -- Phase gating --
        "enable_phase_gating": True,
        "phase_gate_strict": False,  # True = stop on failure, False = warn and continue

        # -- Agent profile --
        "agent_profile": "default",

        # -- Temporal orchestration --
        "enable_temporal": False,
        "temporal_server": "localhost:7233",
        "temporal_namespace": "argus",
        "temporal_retry_mode": "production",

        # -- DAST auth --
        "dast_auth_config_path": "",      # path to YAML auth config
        "dast_enable_totp": True,

        # -- Vulnerability enrichment & compliance --
        "enable_license_risk_scoring": True,
        "enable_epss_scoring": True,
        "epss_cache_ttl_hours": 24,
        "enable_fix_version_tracking": True,
        "enable_vex": True,
        "vex_paths": "",                 # comma-separated paths to VEX docs
        "vex_auto_discover_dir": ".argus/vex",
        "enable_vuln_deduplication": True,
        "deduplication_strategy": "auto",  # auto, strict, standard, relaxed
        "enable_advanced_suppression": True,
        "suppression_auto_expire_days": 90,
        "enable_compliance_mapping": True,
        "compliance_frameworks": "",     # comma-separated: nist_800_53,pci_dss_4,owasp_top10_2021,soc2,cis_kubernetes,iso_27001
    }

# ---------------------------------------------------------------------------
# Profile loading
# ---------------------------------------------------------------------------

def _profile_search_paths(profile_name: str) -> List[Path]:
    """Return candidate YAML paths for *profile_name*, in priority order.

    Later entries take precedence (project-local overrides user overrides
    built-in).
    """
    return [
        PROJECT_ROOT / "profiles" / f"{profile_name}.yml",          # built-in
        Path.home() / ".argus" / "profiles" / f"{profile_name}.yml",  # user
        Path(".argus") / "profiles" / f"{profile_name}.yml",          # project-local
    ]


def _load_raw_profile(profile_name: str, _chain: Optional[List[str]] = None) -> dict:
    """Load raw YAML dict for *profile_name*, resolving ``_extends``.

    Parameters
    ----------
    profile_name:
        Name of the profile to load (without ``.yml`` extension).
    _chain:
        Internal recursion guard tracking the inheritance chain.

    Returns
    -------
    dict
        The merged (nested) profile dict with parent values as base.

    Raises
    ------
    FileNotFoundError
        If the profile YAML cannot be found in any search path.
    ValueError
        If a circular ``_extends`` chain is detected.
    """
    if _chain is None:
        _chain = []

    if profile_name in _chain:
        raise ValueError(
            f"Circular profile inheritance detected: "
            f"{' -> '.join(_chain)} -> {profile_name}"
        )
    _chain.append(profile_name)

    # Search for the profile YAML
    raw: Optional[dict] = None
    loaded_path: Optional[Path] = None
    for candidate in _profile_search_paths(profile_name):
        if candidate.is_file():
            loaded_path = candidate
            break

    if loaded_path is None:
        raise FileNotFoundError(
            f"Profile '{profile_name}' not found.  Searched: "
            + ", ".join(str(p) for p in _profile_search_paths(profile_name))
        )

    logger.info("Loading profile '%s' from %s", profile_name, loaded_path)
    with open(loaded_path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    # Handle inheritance
    parent_name = raw.pop("_extends", None)
    if parent_name:
        parent = _load_raw_profile(parent_name, _chain=_chain)
        raw = _deep_merge_nested(parent, raw)

    return raw


def _deep_merge_nested(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base* (nested dicts)."""
    merged = dict(base)
    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _deep_merge_nested(merged[key], value)
        else:
            merged[key] = value
    return merged

# ---------------------------------------------------------------------------
# Flatten nested YAML -> flat config dict
# ---------------------------------------------------------------------------

_SECTION_PREFIX_MAP = {
    "scanners": "enable_",
    "features": "enable_",
}


def flatten_profile(nested: dict) -> Dict[str, Any]:
    """Convert a nested profile YAML dict to a flat config dict.

    Mapping rules:
    - ``nested["ai"]["provider"]``    -> ``ai_provider``
    - ``nested["ai"]["model"]``       -> ``model``
    - ``nested["ai"]["multi_agent_mode"]`` -> ``multi_agent_mode``
    - ``nested["scanners"][key]``     -> ``enable_{key}``
    - ``nested["features"][key]``     -> ``enable_{key}``
    - ``nested["limits"][key]``       -> key (directly)
    - ``nested["files"][key]``        -> key (directly)
    - ``nested["deep_analysis"][key]``-> ``deep_analysis_{key}``
      (special case: ``mode`` -> ``deep_analysis_mode``)
    - ``nested["output"][key]``       -> key (directly)
    - Top-level scalar keys (``name``, ``description``, ``agent_profile``,
      ``secrets_scanners_only``) are passed through as-is.

    Only non-None values are included.
    """
    flat: Dict[str, Any] = {}

    # -- ai section --
    ai = nested.get("ai")
    if isinstance(ai, dict):
        if ai.get("provider") is not None:
            flat["ai_provider"] = ai["provider"]
        if ai.get("model") is not None:
            flat["model"] = ai["model"]
        if ai.get("multi_agent_mode") is not None:
            flat["multi_agent_mode"] = ai["multi_agent_mode"]

    # -- scanners / features (prefixed) --
    for section, prefix in _SECTION_PREFIX_MAP.items():
        block = nested.get(section)
        if isinstance(block, dict):
            for key, value in block.items():
                if value is not None:
                    flat[f"{prefix}{key}"] = value

    # -- limits (direct) --
    limits = nested.get("limits")
    if isinstance(limits, dict):
        for key, value in limits.items():
            if value is not None:
                flat[key] = value

    # -- files (direct) --
    files = nested.get("files")
    if isinstance(files, dict):
        for key, value in files.items():
            if value is not None:
                flat[key] = value

    # -- deep_analysis (prefixed) --
    deep = nested.get("deep_analysis")
    if isinstance(deep, dict):
        for key, value in deep.items():
            if value is not None:
                if key == "mode":
                    flat["deep_analysis_mode"] = value
                else:
                    flat[f"deep_analysis_{key}"] = value

    # -- output (direct) --
    output = nested.get("output")
    if isinstance(output, dict):
        for key, value in output.items():
            if value is not None:
                flat[key] = value

    # -- top-level scalars --
    for scalar_key in (
        "name", "description", "agent_profile", "secrets_scanners_only",
        "dast_auth_config_path", "dast_enable_totp",
    ):
        if nested.get(scalar_key) is not None:
            flat[scalar_key] = nested[scalar_key]

    return flat


def load_profile(profile_name: str) -> Dict[str, Any]:
    """Load a profile by name and return a flat config dict.

    Search order (first match wins per path):
      1. ``{PROJECT_ROOT}/profiles/{name}.yml``   (built-in)
      2. ``~/.argus/profiles/{name}.yml``          (user)
      3. ``.argus/profiles/{name}.yml``            (project-local)

    The ``_extends`` key enables profile inheritance: the parent profile is
    loaded first and the child values are overlaid on top.

    Parameters
    ----------
    profile_name:
        The profile name (without ``.yml`` extension).

    Returns
    -------
    dict
        Flat configuration dict ready to merge into the config chain.
    """
    raw = _load_raw_profile(profile_name)
    return flatten_profile(raw)

# ---------------------------------------------------------------------------
# Environment variable overrides
# ---------------------------------------------------------------------------

# Mapping: (env_var_name, ...) -> (config_key, type)
# Types: "str", "bool", "int", "float"
_ENV_MAPPINGS: List[tuple] = [
    # AI
    (("AI_PROVIDER", "INPUT_AI_PROVIDER"),          "ai_provider",          "str"),
    (("MODEL", "INPUT_MODEL"),                      "model",                "str"),
    (("MULTI_AGENT_MODE", "INPUT_MULTI_AGENT_MODE"),"multi_agent_mode",     "str"),
    (("ANTHROPIC_API_KEY",),                        "anthropic_api_key",    "str"),
    (("OPENAI_API_KEY",),                           "openai_api_key",       "str"),
    (("OLLAMA_ENDPOINT",),                          "ollama_endpoint",      "str"),

    # Limits
    (("MAX_FILES", "INPUT_MAX_FILES"),              "max_files",            "int"),
    (("MAX_FILE_SIZE", "INPUT_MAX_FILE_SIZE"),       "max_file_size",        "int"),
    (("MAX_TOKENS", "INPUT_MAX_TOKENS"),            "max_tokens",           "int"),
    (("COST_LIMIT", "INPUT_COST_LIMIT"),            "cost_limit",           "float"),

    # Files
    (("ONLY_CHANGED", "INPUT_ONLY_CHANGED"),        "only_changed",         "bool"),
    (("INCLUDE_PATHS", "INPUT_INCLUDE_PATHS"),       "include_paths",        "str"),
    (("EXCLUDE_PATHS", "INPUT_EXCLUDE_PATHS"),       "exclude_paths",        "str"),

    # Scanner toggles
    (("ENABLE_SEMGREP", "SEMGREP_ENABLED"),         "enable_semgrep",       "bool"),
    (("ENABLE_TRIVY",),                             "enable_trivy",         "bool"),
    (("ENABLE_CHECKOV",),                           "enable_checkov",       "bool"),
    (("ENABLE_API_SECURITY",),                      "enable_api_security",  "bool"),
    (("ENABLE_DAST",),                              "enable_dast",          "bool"),
    (("ENABLE_SUPPLY_CHAIN",),                      "enable_supply_chain",  "bool"),
    (("ENABLE_FUZZING",),                           "enable_fuzzing",       "bool"),
    (("ENABLE_THREAT_INTEL",),                      "enable_threat_intel",  "bool"),
    (("ENABLE_REMEDIATION",),                       "enable_remediation",   "bool"),
    (("ENABLE_RUNTIME_SECURITY",),                  "enable_runtime_security", "bool"),
    (("ENABLE_REGRESSION_TESTING",),                "enable_regression_testing", "bool"),

    # MCP Server
    (("ENABLE_MCP_SERVER",),                        "enable_mcp_server",    "bool"),

    # Feature toggles
    (("ENABLE_MULTI_AGENT", "INPUT_ENABLE_MULTI_AGENT"), "enable_multi_agent", "bool"),
    (("ENABLE_SPONTANEOUS_DISCOVERY",),             "enable_spontaneous_discovery", "bool"),
    (("ENABLE_COLLABORATIVE_REASONING",),           "enable_collaborative_reasoning", "bool"),
    (("ENABLE_THREAT_MODELING",),                   "enable_threat_modeling", "bool"),
    (("ENABLE_SANDBOX_VALIDATION",),                "enable_sandbox_validation", "bool"),
    (("ENABLE_HEURISTICS",),                        "enable_heuristics",    "bool"),
    (("ENABLE_CONSENSUS",),                         "enable_consensus",     "bool"),
    (("ENABLE_EXPLOIT_ANALYSIS",),                  "enable_exploit_analysis", "bool"),
    (("ENABLE_PROOF_BY_EXPLOITATION",),             "enable_proof_by_exploitation", "bool"),
    (("MAX_EXPLOIT_ATTEMPTS",),                     "max_exploit_attempts", "int"),
    (("GENERATE_SECURITY_TESTS",),                  "generate_security_tests", "bool"),
    (("ENABLE_SMART_RETRY",),                       "enable_smart_retry",   "bool"),
    (("RETRY_MAX_ATTEMPTS",),                       "retry_max_attempts",   "int"),
    (("RETRY_BILLING_DELAY",),                      "retry_billing_delay",  "int"),
    (("CONSENSUS_THRESHOLD",),                      "consensus_threshold",  "float"),
    (("EXPLOITABILITY_THRESHOLD",),                 "exploitability_threshold", "str"),

    # Parallel agents
    (("ENABLE_PARALLEL_AGENTS",),                   "enable_parallel_agents", "bool"),
    (("PARALLEL_AGENT_WORKERS",),                   "parallel_agent_workers", "int"),

    # Phase gating
    (("ENABLE_PHASE_GATING",),                      "enable_phase_gating",  "bool"),
    (("PHASE_GATE_STRICT",),                        "phase_gate_strict",    "bool"),

    # Temporal orchestration
    (("ENABLE_TEMPORAL",),                          "enable_temporal",      "bool"),
    (("TEMPORAL_SERVER",),                          "temporal_server",      "str"),
    (("TEMPORAL_NAMESPACE",),                       "temporal_namespace",   "str"),
    (("TEMPORAL_RETRY_MODE",),                      "temporal_retry_mode",  "str"),

    # Deep analysis
    (("DEEP_ANALYSIS_MODE",),                       "deep_analysis_mode",   "str"),
    (("DEEP_ANALYSIS_MAX_FILES", "MAX_FILES_DEEP_ANALYSIS"), "deep_analysis_max_files", "int"),
    (("DEEP_ANALYSIS_TIMEOUT",),                    "deep_analysis_timeout", "int"),
    (("DEEP_ANALYSIS_COST_CEILING",),               "deep_analysis_cost_ceiling", "float"),

    # Output
    (("FAIL_ON", "INPUT_FAIL_ON"),                  "fail_on",              "str"),

    # DAST auth
    (("DAST_AUTH_CONFIG_PATH",),                    "dast_auth_config_path", "str"),
    (("DAST_ENABLE_TOTP",),                         "dast_enable_totp",     "bool"),

    # Vulnerability enrichment & compliance
    (("ENABLE_LICENSE_RISK_SCORING",),              "enable_license_risk_scoring", "bool"),
    (("ENABLE_EPSS_SCORING",),                      "enable_epss_scoring",  "bool"),
    (("EPSS_CACHE_TTL_HOURS",),                     "epss_cache_ttl_hours", "int"),
    (("ENABLE_FIX_VERSION_TRACKING",),              "enable_fix_version_tracking", "bool"),
    (("ENABLE_VEX",),                               "enable_vex",           "bool"),
    (("VEX_PATHS",),                                "vex_paths",            "str"),
    (("VEX_AUTO_DISCOVER_DIR",),                    "vex_auto_discover_dir", "str"),
    (("ENABLE_VULN_DEDUPLICATION",),                "enable_vuln_deduplication", "bool"),
    (("DEDUPLICATION_STRATEGY",),                   "deduplication_strategy", "str"),
    (("ENABLE_ADVANCED_SUPPRESSION",),              "enable_advanced_suppression", "bool"),
    (("SUPPRESSION_AUTO_EXPIRE_DAYS",),             "suppression_auto_expire_days", "int"),
    (("ENABLE_COMPLIANCE_MAPPING",),                "enable_compliance_mapping", "bool"),
    (("COMPLIANCE_FRAMEWORKS",),                    "compliance_frameworks", "str"),
]


def _coerce(raw: str, type_tag: str) -> Any:
    """Convert a raw env-var string to the appropriate Python type."""
    if type_tag == "bool":
        return raw.lower() == "true"
    if type_tag == "int":
        return int(raw)
    if type_tag == "float":
        return float(raw)
    return raw


def load_env_overrides() -> Dict[str, Any]:
    """Load configuration values from explicitly-set environment variables.

    Only variables that are **present** in ``os.environ`` are returned.
    Variables that are absent are silently skipped so that defaults or
    profile values are not accidentally overwritten.

    Both bare names (``AI_PROVIDER``) and GitHub-Action-style ``INPUT_``
    prefixed names are supported.  The first found wins (left-to-right in
    the mapping tuple).
    """
    overrides: Dict[str, Any] = {}

    for env_names, config_key, type_tag in _ENV_MAPPINGS:
        for env_name in env_names:
            if env_name in os.environ:
                try:
                    overrides[config_key] = _coerce(os.environ[env_name], type_tag)
                except (ValueError, TypeError) as exc:
                    logger.warning(
                        "Ignoring env var %s: could not convert %r to %s (%s)",
                        env_name, os.environ[env_name], type_tag, exc,
                    )
                break  # first match wins

    return overrides

# ---------------------------------------------------------------------------
# CLI argument extraction
# ---------------------------------------------------------------------------

# Mapping: argparse attribute -> config key
# Only attributes that may be explicitly provided (not store_true defaults).
_CLI_ATTR_MAP: Dict[str, str] = {
    "provider": "ai_provider",
    "model": "model",
    "max_files": "max_files",
    "cost_limit": "cost_limit",
    "deep_analysis_mode": "deep_analysis_mode",
    "max_files_deep_analysis": "deep_analysis_max_files",
    "deep_analysis_timeout": "deep_analysis_timeout",
    "deep_analysis_cost_ceiling": "deep_analysis_cost_ceiling",
    "fail_on": "fail_on",
    "review_type": "review_type",
    "project_type": "project_type",
    "profile": "_profile",  # handled separately in build_unified_config
    "only_changed": "only_changed",
    "include_paths": "include_paths",
    "exclude_paths": "exclude_paths",
    "multi_agent_mode": "multi_agent_mode",
    "ai_provider": "ai_provider",
    "enable_semgrep": "enable_semgrep",
    "enable_trivy": "enable_trivy",
    "enable_checkov": "enable_checkov",
    "enable_api_security": "enable_api_security",
    "enable_dast": "enable_dast",
    "enable_supply_chain": "enable_supply_chain",
    "enable_fuzzing": "enable_fuzzing",
    "enable_threat_intel": "enable_threat_intel",
    "enable_remediation": "enable_remediation",
    "enable_runtime_security": "enable_runtime_security",
    "enable_regression_testing": "enable_regression_testing",
    "enable_mcp_server": "enable_mcp_server",
    "enable_multi_agent": "enable_multi_agent",
    "enable_spontaneous_discovery": "enable_spontaneous_discovery",
    "enable_collaborative_reasoning": "enable_collaborative_reasoning",
    "enable_ai_enrichment": "enable_ai_enrichment",
    "enable_threat_modeling": "enable_threat_modeling",
    "enable_sandbox_validation": "enable_sandbox_validation",
    "enable_heuristics": "enable_heuristics",
    "enable_consensus": "enable_consensus",
    "enable_iris": "enable_iris",
    "enable_exploit_analysis": "enable_exploit_analysis",
    "enable_proof_by_exploitation": "enable_proof_by_exploitation",
    "max_exploit_attempts": "max_exploit_attempts",
    "generate_security_tests": "generate_security_tests",
    "enable_smart_retry": "enable_smart_retry",
    "retry_max_attempts": "retry_max_attempts",
    "retry_billing_delay": "retry_billing_delay",
    "consensus_threshold": "consensus_threshold",
    "exploitability_threshold": "exploitability_threshold",
    "fuzzing_duration": "fuzzing_duration",
    "runtime_monitoring_duration": "runtime_monitoring_duration",
    "agent_profile": "agent_profile",
    "enable_parallel_agents": "enable_parallel_agents",
    "parallel_agent_workers": "parallel_agent_workers",
    "enable_phase_gating": "enable_phase_gating",
    "phase_gate_strict": "phase_gate_strict",
    "enable_temporal": "enable_temporal",
    "temporal_server": "temporal_server",
    "temporal_namespace": "temporal_namespace",
    "temporal_retry_mode": "temporal_retry_mode",
    "dast_auth_config_path": "dast_auth_config_path",
    "dast_enable_totp": "dast_enable_totp",
    "enable_license_risk_scoring": "enable_license_risk_scoring",
    "enable_epss_scoring": "enable_epss_scoring",
    "epss_cache_ttl_hours": "epss_cache_ttl_hours",
    "enable_fix_version_tracking": "enable_fix_version_tracking",
    "enable_vex": "enable_vex",
    "vex_paths": "vex_paths",
    "vex_auto_discover_dir": "vex_auto_discover_dir",
    "enable_vuln_deduplication": "enable_vuln_deduplication",
    "deduplication_strategy": "deduplication_strategy",
    "enable_advanced_suppression": "enable_advanced_suppression",
    "suppression_auto_expire_days": "suppression_auto_expire_days",
    "enable_compliance_mapping": "enable_compliance_mapping",
    "compliance_frameworks": "compliance_frameworks",
}


def extract_cli_overrides(args: Any) -> Dict[str, Any]:
    """Extract explicitly-set CLI arguments into a flat config dict.

    Only attributes whose value is not ``None`` are included, so that
    argparse defaults do not shadow earlier layers.

    Parameters
    ----------
    args:
        An ``argparse.Namespace`` (or compatible object).

    Returns
    -------
    dict
        Config keys with values that were explicitly passed on the CLI.
    """
    if args is None:
        return {}

    overrides: Dict[str, Any] = {}
    for attr, config_key in _CLI_ATTR_MAP.items():
        value = getattr(args, attr, None)
        if value is not None:
            overrides[config_key] = value

    # Special handling: --enable-deep-analysis is a store_true shorthand
    if getattr(args, "enable_deep_analysis", False):
        # Only set if deep_analysis_mode wasn't explicitly provided
        if "deep_analysis_mode" not in overrides:
            overrides["deep_analysis_mode"] = "conservative"

    return overrides

# ---------------------------------------------------------------------------
# Merge helpers
# ---------------------------------------------------------------------------

def deep_merge(base: dict, override: dict) -> dict:
    """Merge *override* into *base*.  Only non-None override values win.

    This operates on **flat** dicts (no recursive descent).  ``None``
    values in *override* are silently skipped.
    """
    merged = dict(base)
    for key, value in override.items():
        if value is not None:
            merged[key] = value
    return merged

# ---------------------------------------------------------------------------
# .argus.yml loader
# ---------------------------------------------------------------------------

def _load_argus_yml(repo_path: str) -> Dict[str, Any]:
    """Load ``.argus.yml`` from *repo_path* and return flat config dict.

    Returns an empty dict if the file does not exist.
    """
    yml_path = Path(repo_path) / ".argus.yml"
    if not yml_path.is_file():
        return {}

    logger.info("Loading .argus.yml from %s", yml_path)
    with open(yml_path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    # .argus.yml may contain a top-level "profile" key
    # and/or nested config sections identical to profile YAML
    return flatten_profile(raw)

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def build_unified_config(
    profile: Optional[str] = None,
    cli_args: Any = None,
    repo_path: str = ".",
) -> Dict[str, Any]:
    """Build a fully-merged configuration dict.

    Layer precedence (last wins):
        1. Hard-coded defaults          (``get_default_config()``)
        2. Profile YAML                 (``load_profile()``)
        3. ``.argus.yml``               (project-level overrides)
        4. Environment variables        (``load_env_overrides()``)
        5. CLI arguments                (``extract_cli_overrides()``)

    Parameters
    ----------
    profile:
        Explicit profile name.  If ``None``, the function checks
        ``cli_args.profile``, then the ``ARGUS_PROFILE`` env var.
    cli_args:
        An ``argparse.Namespace`` (or ``None``).
    repo_path:
        Path to the repository root (used for ``.argus.yml`` lookup).

    Returns
    -------
    dict
        The fully-resolved, flat configuration dict.
    """
    # -- Layer 1: defaults --
    config = get_default_config()

    # -- Determine profile name --
    profile_name = profile
    if profile_name is None and cli_args is not None:
        profile_name = getattr(cli_args, "profile", None)
    if profile_name is None:
        profile_name = os.environ.get("ARGUS_PROFILE")

    # -- Layer 2: profile --
    if profile_name:
        try:
            profile_values = load_profile(profile_name)
            config = deep_merge(config, profile_values)
            logger.info("Applied profile '%s'", profile_name)
        except FileNotFoundError:
            logger.warning("Profile '%s' not found; skipping", profile_name)

    # -- Layer 3: .argus.yml --
    argus_yml = _load_argus_yml(repo_path)
    if argus_yml:
        config = deep_merge(config, argus_yml)
        logger.info("Applied .argus.yml overrides (%d keys)", len(argus_yml))

    # -- Layer 4: env vars --
    env_overrides = load_env_overrides()
    if env_overrides:
        config = deep_merge(config, env_overrides)
        logger.debug("Applied %d env-var overrides", len(env_overrides))

    # -- Layer 5: CLI args --
    cli_overrides = extract_cli_overrides(cli_args)
    # Remove the internal _profile key if present
    cli_overrides.pop("_profile", None)
    if cli_overrides:
        config = deep_merge(config, cli_overrides)
        logger.debug("Applied %d CLI overrides", len(cli_overrides))

    return config

# ---------------------------------------------------------------------------
# Profile discovery
# ---------------------------------------------------------------------------

def list_available_profiles() -> List[str]:
    """Return the names of all available profiles.

    Searches:
    - ``{PROJECT_ROOT}/profiles/*.yml``
    - ``~/.argus/profiles/*.yml``
    - ``.argus/profiles/*.yml``
    """
    names: set = set()

    search_dirs = [
        PROJECT_ROOT / "profiles",
        Path.home() / ".argus" / "profiles",
        Path(".argus") / "profiles",
    ]
    for directory in search_dirs:
        if directory.is_dir():
            for yml_file in directory.glob("*.yml"):
                names.add(yml_file.stem)

    return sorted(names)

# ---------------------------------------------------------------------------
# Configuration validation
# ---------------------------------------------------------------------------

_VALID_AI_PROVIDERS = {"auto", "anthropic", "openai", "ollama", "foundation-sec"}
_VALID_MULTI_AGENT_MODES = {"single", "sequential", "parallel"}
_VALID_DEEP_ANALYSIS_MODES = {"off", "semantic-only", "conservative", "full"}
_VALID_EXPLOITABILITY_THRESHOLDS = {"none", "low", "moderate", "high", "critical"}


def validate_config(config: Dict[str, Any]) -> List[str]:
    """Validate a configuration dict and return a list of warnings/errors.

    Returns
    -------
    list[str]
        Human-readable warning/error messages.  An empty list means the
        config is valid.
    """
    issues: List[str] = []

    # -- API key requirements per provider --
    provider = config.get("ai_provider", "auto")
    if provider == "anthropic" and not config.get("anthropic_api_key"):
        issues.append(
            "ERROR: ai_provider is 'anthropic' but ANTHROPIC_API_KEY is not set."
        )
    if provider == "openai" and not config.get("openai_api_key"):
        issues.append(
            "ERROR: ai_provider is 'openai' but OPENAI_API_KEY is not set."
        )
    if provider == "ollama" and not config.get("ollama_endpoint"):
        issues.append(
            "WARNING: ai_provider is 'ollama' but OLLAMA_ENDPOINT is not set. "
            "Defaulting to http://localhost:11434."
        )
    if provider == "auto":
        has_any = (
            config.get("anthropic_api_key")
            or config.get("openai_api_key")
            or config.get("ollama_endpoint")
        )
        if not has_any:
            issues.append(
                "WARNING: ai_provider is 'auto' but no API keys or endpoints are "
                "configured.  AI-powered features will be unavailable."
            )

    # -- Valid enum values --
    if provider not in _VALID_AI_PROVIDERS:
        issues.append(
            f"ERROR: Invalid ai_provider '{provider}'. "
            f"Must be one of: {', '.join(sorted(_VALID_AI_PROVIDERS))}"
        )

    mam = config.get("multi_agent_mode", "single")
    if mam not in _VALID_MULTI_AGENT_MODES:
        issues.append(
            f"ERROR: Invalid multi_agent_mode '{mam}'. "
            f"Must be one of: {', '.join(sorted(_VALID_MULTI_AGENT_MODES))}"
        )

    dam = config.get("deep_analysis_mode", "off")
    if dam not in _VALID_DEEP_ANALYSIS_MODES:
        issues.append(
            f"ERROR: Invalid deep_analysis_mode '{dam}'. "
            f"Must be one of: {', '.join(sorted(_VALID_DEEP_ANALYSIS_MODES))}"
        )

    et = config.get("exploitability_threshold", "moderate")
    if et not in _VALID_EXPLOITABILITY_THRESHOLDS:
        issues.append(
            f"ERROR: Invalid exploitability_threshold '{et}'. "
            f"Must be one of: {', '.join(sorted(_VALID_EXPLOITABILITY_THRESHOLDS))}"
        )

    # -- Numeric range checks --
    max_files = config.get("max_files", 50)
    if isinstance(max_files, (int, float)) and max_files < 1:
        issues.append("ERROR: max_files must be >= 1.")

    cost_limit = config.get("cost_limit", 1.0)
    if isinstance(cost_limit, (int, float)) and cost_limit < 0:
        issues.append("ERROR: cost_limit must be >= 0.")

    consensus_threshold = config.get("consensus_threshold", 0.5)
    if isinstance(consensus_threshold, (int, float)):
        if not (0.0 <= consensus_threshold <= 1.0):
            issues.append("ERROR: consensus_threshold must be between 0.0 and 1.0.")

    # -- Mutually exclusive / dependency checks --
    if config.get("enable_collaborative_reasoning") and not config.get("enable_multi_agent"):
        issues.append(
            "WARNING: enable_collaborative_reasoning requires enable_multi_agent. "
            "Collaborative reasoning will be skipped."
        )

    if config.get("enable_consensus") and not config.get("enable_multi_agent"):
        issues.append(
            "WARNING: enable_consensus requires enable_multi_agent. "
            "Consensus building will be skipped."
        )

    if config.get("enable_dast") and not config.get("dast_target_url"):
        issues.append(
            "WARNING: enable_dast is true but no DAST target URL is configured. "
            "DAST scanning will be skipped."
        )

    return issues
