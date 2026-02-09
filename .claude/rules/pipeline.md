---
description: 6-phase pipeline architecture and phase details
globs: ["scripts/run_ai_audit.py", "scripts/hybrid_analyzer.py", "scripts/agent_personas.py", "scripts/sandbox_validator.py"]
---

# 6-Phase Pipeline Details

## Phase 1: Scanner Orchestration (30-60 sec)
Runs 4 scanners in parallel:
- **Semgrep** - SAST with 2000+ rules
- **Trivy** - CVE/dependency scanning
- **Checkov** - IaC security (Terraform, K8s)
- **TruffleHog** - Verified and pattern-based secret detection

## Phase 2: AI Enrichment (2-5 min)
- Claude/OpenAI/Ollama triage
- Noise scoring & false positive prediction
- CWE mapping & risk scoring
- Spontaneous discovery: heuristic-based pattern matching via `HeuristicScanner` (regex, not AI-powered); runs before LLM enrichment to find issues beyond scanner rules

## Phase 3: Multi-Agent Review
5 specialized AI personas run with parallel execution for quality agents:
- Security agents run sequentially (context dependencies)
- Quality agents (performance, testing, quality) run in parallel via `ThreadPoolExecutor`
- Toggle: `enable_parallel_agents=True`, `parallel_agent_workers=3`

## Phase 4: Sandbox Validation + Proof-by-Exploitation
Docker-based exploit verification with LLM-powered PoC generation:
- `ExploitGenerator`: Uses LLM to generate targeted exploit code from findings
- `ProofByExploitation`: Orchestrates generation + sandbox validation
- Safety blocklist prevents dangerous operations in generated exploits
- Toggle: `enable_proof_by_exploitation=False` (opt-in, uses LLM credits)

## Phase 5: Policy Gates
Rego/OPA policies enforce pass/fail:
- PR gates block verified secrets, critical CVEs
- Release gates require SBOM + signature

## Phase 6: Reporting
- **SARIF** - GitHub code scanning integration
- **JSON** - Programmatic access
- **Markdown** - PR comments
