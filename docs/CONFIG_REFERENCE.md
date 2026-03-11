# Config Reference

All configuration keys and their defaults. Override via **profile YAML**, **.argus.yml**, **environment variables**, or **CLI**. Precedence: defaults < profile < .argus.yml < env < CLI.

Source: `scripts/config_loader.get_default_config()` and `_ENV_MAPPINGS`.

---

## AI

| Key | Default | Env var(s) |
|-----|---------|------------|
| ai_provider | auto | AI_PROVIDER, INPUT_AI_PROVIDER |
| model | auto | MODEL, INPUT_MODEL |
| multi_agent_mode | single | MULTI_AGENT_MODE, INPUT_MULTI_AGENT_MODE |
| anthropic_api_key | "" | ANTHROPIC_API_KEY |
| openai_api_key | "" | OPENAI_API_KEY |
| ollama_endpoint | "" | OLLAMA_ENDPOINT |

## Scanners

| Key | Default | Env var(s) |
|-----|---------|------------|
| enable_semgrep | true | ENABLE_SEMGREP, SEMGREP_ENABLED |
| enable_trivy | true | ENABLE_TRIVY |
| enable_checkov | true | ENABLE_CHECKOV |
| enable_api_security | true | ENABLE_API_SECURITY |
| enable_dast | false | ENABLE_DAST |
| enable_supply_chain | true | ENABLE_SUPPLY_CHAIN |
| enable_fuzzing | false | ENABLE_FUZZING |
| enable_threat_intel | true | ENABLE_THREAT_INTEL |
| enable_remediation | true | ENABLE_REMEDIATION |
| enable_runtime_security | false | ENABLE_RUNTIME_SECURITY |
| enable_regression_testing | true | ENABLE_REGRESSION_TESTING |
| enable_gitleaks | true | ENABLE_GITLEAKS |
| enable_nuclei_templates | true | ENABLE_NUCLEI_TEMPLATES |
| enable_zap_baseline | false | ENABLE_ZAP_BASELINE |

## DAST (orchestrator)

| Key | Default | Env var(s) |
|-----|---------|------------|
| dast_target_url | "" | DAST_TARGET_URL |
| dast_auth_config_path | "" | DAST_AUTH_CONFIG_PATH |
| dast_enable_nuclei | true | DAST_ENABLE_NUCLEI |
| dast_enable_zap | true | DAST_ENABLE_ZAP |
| dast_max_duration | 900 | DAST_MAX_DURATION |
| dast_parallel_agents | true | DAST_PARALLEL_AGENTS |

## Feature toggles

| Key | Default | Env var(s) |
|-----|---------|------------|
| enable_multi_agent | true | ENABLE_MULTI_AGENT, INPUT_ENABLE_MULTI_AGENT |
| enable_spontaneous_discovery | true | ENABLE_SPONTANEOUS_DISCOVERY |
| enable_collaborative_reasoning | false | ENABLE_COLLABORATIVE_REASONING |
| enable_ai_enrichment | true | ENABLE_AI_ENRICHMENT |
| enable_threat_modeling | true | ENABLE_THREAT_MODELING |
| enable_sandbox_validation | true | ENABLE_SANDBOX_VALIDATION |
| enable_heuristics | true | ENABLE_HEURISTICS |
| enable_consensus | true | ENABLE_CONSENSUS |
| enable_iris | true | ENABLE_IRIS |
| enable_proof_by_exploitation | false | ENABLE_PROOF_BY_EXPLOITATION |
| max_exploit_attempts | 10 | MAX_EXPLOIT_ATTEMPTS |
| enable_audit_trail | true | ENABLE_AUDIT_TRAIL |
| audit_save_prompts | true | AUDIT_SAVE_PROMPTS |
| enable_smart_retry | true | ENABLE_SMART_RETRY |
| retry_max_attempts | 3 | RETRY_MAX_ATTEMPTS |
| retry_billing_delay | 60 | RETRY_BILLING_DELAY |

## Limits & files

| Key | Default | Env var(s) |
|-----|---------|------------|
| max_files | 50 | MAX_FILES, INPUT_MAX_FILES |
| max_file_size | 50000 | MAX_FILE_SIZE, INPUT_MAX_FILE_SIZE |
| max_tokens | 8000 | MAX_TOKENS, INPUT_MAX_TOKENS |
| cost_limit | 1.0 | COST_LIMIT, INPUT_COST_LIMIT |
| only_changed | false | ONLY_CHANGED, INPUT_ONLY_CHANGED |
| include_paths | "" | INCLUDE_PATHS, INPUT_INCLUDE_PATHS |
| exclude_paths | .github/**,node_modules/**,... | EXCLUDE_PATHS, INPUT_EXCLUDE_PATHS |

## Deep analysis

| Key | Default | Env var(s) |
|-----|---------|------------|
| deep_analysis_mode | off | DEEP_ANALYSIS_MODE |
| deep_analysis_max_files | 50 | DEEP_ANALYSIS_MAX_FILES, MAX_FILES_DEEP_ANALYSIS |
| deep_analysis_timeout | 300 | DEEP_ANALYSIS_TIMEOUT |
| deep_analysis_cost_ceiling | 5.0 | DEEP_ANALYSIS_COST_CEILING |

## Phase gating & parallel

| Key | Default | Env var(s) |
|-----|---------|------------|
| enable_phase_gating | true | ENABLE_PHASE_GATING |
| phase_gate_strict | false | PHASE_GATE_STRICT |
| enable_parallel_agents | true | ENABLE_PARALLEL_AGENTS |
| parallel_agent_workers | 3 | PARALLEL_AGENT_WORKERS |

## Vulnerability enrichment & compliance

| Key | Default | Env var(s) |
|-----|---------|------------|
| enable_license_risk_scoring | true | ENABLE_LICENSE_RISK_SCORING |
| enable_epss_scoring | true | ENABLE_EPSS_SCORING |
| epss_cache_ttl_hours | 24 | EPSS_CACHE_TTL_HOURS |
| enable_fix_version_tracking | true | ENABLE_FIX_VERSION_TRACKING |
| enable_vex | true | ENABLE_VEX |
| vex_paths | "" | VEX_PATHS |
| vex_auto_discover_dir | .argus/vex | VEX_AUTO_DISCOVER_DIR |
| enable_vuln_deduplication | true | ENABLE_VULN_DEDUPLICATION |
| deduplication_strategy | auto | DEDUPLICATION_STRATEGY |
| enable_advanced_suppression | true | ENABLE_ADVANCED_SUPPRESSION |
| suppression_auto_expire_days | 90 | SUPPRESSION_AUTO_EXPIRE_DAYS |
| enable_compliance_mapping | true | ENABLE_COMPLIANCE_MAPPING |
| compliance_frameworks | "" | COMPLIANCE_FRAMEWORKS |

## Continuous security (v3)

| Key | Default | Env var(s) |
|-----|---------|------------|
| enable_diff_scoping | true | ENABLE_DIFF_SCOPING |
| diff_expand_impact_radius | true | DIFF_EXPAND_IMPACT_RADIUS |
| enable_autofix_pr | false | ENABLE_AUTOFIX_PR |
| autofix_confidence_threshold | high | AUTOFIX_CONFIDENCE_THRESHOLD |
| autofix_max_prs_per_scan | 5 | AUTOFIX_MAX_PRS_PER_SCAN |
| enable_findings_store | true | ENABLE_FINDINGS_STORE |
| findings_db_path | .argus/findings.db | FINDINGS_DB_PATH |
| inject_historical_context | true | INJECT_HISTORICAL_CONTEXT |
| enable_agent_chain_discovery | false | ENABLE_AGENT_CHAIN_DISCOVERY |
| enable_cross_component_analysis | true | ENABLE_CROSS_COMPONENT_ANALYSIS |
| enable_app_context | true | ENABLE_APP_CONTEXT |
| enable_live_validation | false | ENABLE_LIVE_VALIDATION |
| live_validation_environment | staging | LIVE_VALIDATION_ENVIRONMENT |

## Other

| Key | Default | Env var(s) |
|-----|---------|------------|
| enable_mcp_server | false | ENABLE_MCP_SERVER |
| enable_quality_filter | true | ENABLE_QUALITY_FILTER |
| quality_filter_min_confidence | 0.30 | QUALITY_FILTER_MIN_CONFIDENCE |
| review_type | audit | — |
| project_type | auto | — |
| fail_on | "" | FAIL_ON, INPUT_FAIL_ON |
| agent_profile | default | — |
| enable_temporal | false | ENABLE_TEMPORAL |
| temporal_server | localhost:7233 | TEMPORAL_SERVER |
| temporal_namespace | argus | TEMPORAL_NAMESPACE |
| temporal_retry_mode | production | TEMPORAL_RETRY_MODE |
| consensus_threshold | 0.5 | CONSENSUS_THRESHOLD |
| exploitability_threshold | moderate | EXPLOITABILITY_THRESHOLD |
| fuzzing_duration | 300 | FUZZING_DURATION |
| runtime_monitoring_duration | 60 | RUNTIME_MONITORING_DURATION |

For full env-to-key mapping and types, see `config_loader._ENV_MAPPINGS` and `build_unified_config()`.
