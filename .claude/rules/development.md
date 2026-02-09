---
description: Development workflow, Docker, GitHub Action, and project structure
globs: ["*.yml", "*.yaml", "Dockerfile", "action.yml", "tests/**"]
---

# Development

## Commands
```bash
ruff check scripts/ && ruff format scripts/   # Lint and format
pytest -v --cov=scripts                        # Run tests
mypy scripts/*.py                              # Type check
```

## GitHub Action
```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    review-type: security
    fail-on-blockers: true
```

## Docker
```bash
docker build -t argus .
docker run -v $(pwd):/workspace -e ANTHROPIC_API_KEY argus --project-type backend-api
```

## Project Structure
```
Argus-Security/
├── scripts/
│   ├── run_ai_audit.py           # Main orchestrator (all 6 phases)
│   ├── error_classifier.py       # Smart retry + error classification
│   ├── audit_trail.py            # Per-agent metrics + audit logging
│   ├── phase_gate.py             # Phase output validation
│   ├── mcp_server.py             # Custom MCP server for Claude Code
│   ├── dast_auth_config.py       # DAST auth config + TOTP
│   ├── temporal_orchestrator.py  # Temporal workflow orchestration
│   ├── license_risk_scorer.py    # SBOM license risk classification
│   ├── epss_scorer.py            # EPSS exploit probability scoring
│   ├── fix_version_tracker.py    # Fix version extraction + upgrade paths
│   ├── vex_processor.py          # VEX document parsing
│   ├── vuln_deduplicator.py      # Multi-level finding deduplication
│   ├── advanced_suppression.py   # .argus-ignore.yml suppression engine
│   ├── compliance_mapper.py      # Compliance framework mapping
│   ├── heuristic_scanner.py      # Pre-LLM code scanning
│   ├── hybrid_analyzer.py        # Multi-scanner coordination
│   ├── agent_personas.py         # Phase 3: Multi-agent review
│   ├── sandbox_validator.py      # Phase 4: Docker validation
│   ├── remediation_engine.py     # Auto-fix generation
│   └── argus                     # CLI entry point
├── policy/rego/                  # Phase 5: OPA policies
├── profiles/                     # Config profiles
├── tests/                        # Test suite (2,200+ tests)
└── action.yml                    # GitHub Action definition
```
