# Argus Security: codebase review and maturity roadmap

Reviewed 7 October 2026. Baseline: `24b72c7` (including the upstream adoption-evidence
update). This is an architecture and engineering review of the repository, with
focused execution of critical contracts; it is not an exhaustive security audit
or a comparative vulnerability-detection benchmark.

## Assessment

Argus has useful breadth and a promising role as a security-scanner orchestrator
with optional AI triage. Its main maturity gap is dependable integration: several
well-developed modules do not yet produce the end-to-end guarantees advertised
by the README. Making outcomes trustworthy is more valuable at this stage than
adding another scanner or AI persona.

The repository contains 318 tracked Python files and 37 workflow YAML files at
baseline. A build could succeed while shipping an empty wheel. A scanner failure
could become “clean,” and the Action could discard the pipeline's failure status.
This change repairs those release and execution boundaries, while preserving a
separate roadmap for larger architectural work.

## Strengths

- **Broad existing integrations.** SAST, dependency, IaC, and secret adapters are
  present, with optional DAST and enrichment modules. Argus can compose existing
  engines instead of attempting to recreate each detection engine.
- **Usable decomposition.** `scripts/hybrid/phases/` separates orchestration,
  enrichment, review, sandboxing, policy, and reporting. Runner and report modules
  already provide natural places for contract tests.
- **Deterministic policy foundation.** PR/release Rego policies distinguish
  verified secrets, exploitability, public exposure, and release metadata. The
  existing Rego suite passes all 23 tests with OPA 1.21.1.
- **Substantial test assets.** Thousands of tests, scanner-output fixtures, and
  dedicated workflow-security checks give changes a useful regression baseline.
- **Operational building blocks.** Config profiles, retries, audit trails,
  suppression/VEX handling, cost tracking modules, SQLite history, SARIF, and
  Docker support are valuable foundations, though integration varies by path.
- **Security-maintenance foundations.** A security contact, Dependabot, many
  SHA-pinned actions, and network-disabled sandbox configurations already exist.

## Gaps and actions

| Priority | Evidence at baseline | Impact | Disposition |
|---|---|---|---|
| P0 | `hybrid/scanner_runners.py` caught exceptions and returned `[]`; Phase 1 ignored Semgrep/TruffleHog error dictionaries | Failed scans looked clean | Fixed runner/error handling; retain requested scanners and report unavailable tools |
| P0 | `hybrid_analyzer.py` attached health after Phase 6 saved reports; `HybridScanResult` omitted health/policy/chains | Saved artifacts lost execution and enforcement state | Added serialized fields and JSON, SARIF, Markdown status |
| P0 | `hybrid/cli.py` used only severity; Phase 5 skipped empty scans and sent mismatched category/CVSS fields to Rego | Policy decisions and release requirements could be bypassed | Evaluate empty scans, normalize evidence, use exit codes 0/1/2, preserve verified-secret evidence against AI removal |
| P0 | `action.yml` ignored pipeline exit and selected any newest JSON, including quality reports | Failed CI scan could be reported as complete | Isolate each run's report directory, select scan artifacts, validate outcome fields, propagate execution errors and policy failures, install declared dependencies and retain built-in resources |
| P1 | Baseline wheel had only five metadata files; metadata declared only three dependencies | Package installation did not install the product | Package application code/resources, expose three commands, build and installed-wheel tests |
| P1 | `gate.py` used ambient pytest environment to substitute a weaker Python policy | Tests could pass without exercising production policy | Remove implicit fallback; run actual OPA tests; missing engine is an explicit error |
| P1 | Some workflows used floating actions; Docker workflow used shell `eval` | Existing workflow-security tests failed | Pin remaining action references, use local Action for self-testing, replace `eval` with argument-based execution |
| P1 | Phase validation calls `phase1`/`phase2`/`phase3`, schemas use descriptive names; returned gate decisions ignored | “Strict” phase gating is not effective on the synchronous path | Next milestone: align phase identifiers and enforce `should_proceed` |
| P1 | Findings store, diff analysis, context builders are initialized without consistent use by synchronous phases | Advertised continuous-security behavior exceeds integration evidence | Next milestone: wire or explicitly mark unsupported paths, with end-to-end tests |
| P1 | FindingsStore fingerprint omits CVE/package identity when hybrid fields are supplied; repository/branch scoping is limited | Distinct findings can merge; missing findings are not reliable proof of fixes | Versioned identities and scoped full/diff scan lifecycle before automatic closure |
| P1 | Scanner-specific parsers and optional tools still have differing failure contracts | Completeness remains dependent on adapter semantics | Extend the outcome contract to every optional adapter and parser |
| P2 | 802 Ruff findings at baseline; overlapping CI workflows; timing-dependent and environment-dependent tests | Red/noisy CI obscures regressions | Consolidate CI, isolate slow/live tests, ratchet lint/type coverage |
| P2 | README gives general percentage/time/cost claims without a published reproducible comparison | Users cannot assess detection quality or cost tradeoffs | Remove unsupported headline percentages; publish an evaluation harness and dataset |
| P2 | `scripts` imports mix top-level/package styles; package version and “v3” feature naming diverge | Harder distribution, upgrades, and maintenance | Migrate incrementally to a dedicated namespace and coherent release/version policy |

## Comparison with established open-source peers

No single peer has exactly Argus's scope. These projects cover its scanner,
orchestration, findings-management, and AI-review roles. This comparison uses
primary repositories/documentation accessed on the review date. It does not
attribute commercial-only features to an open-source edition or rank detection
accuracy by stars or marketing claims.

| Project | Relevant role and demonstrated capability | Lesson for Argus |
|---|---|---|
| [Semgrep](https://github.com/semgrep/semgrep) | Dedicated static-analysis engine with rules and developer/CI integration. Its [CLI reference](https://docs.semgrep.dev/cli-reference#exit-codes) distinguishes findings from operational failures. | Keep Semgrep as an engine; preserve its error semantics across Argus's adapters and CI. |
| [Trivy](https://github.com/aquasecurity/trivy) | Broad artifact scanning for vulnerabilities, misconfigurations, secrets, and SBOMs. It documents [scanner selection and configurable finding exit codes](https://trivy.dev/docs/latest/configuration/others/). | Prefer predictable scanner controls and artifact contracts over a larger default feature inventory. |
| [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | Findings ingestion, tracking, deduplication, remediation, and reporting. Its [open-source deduplication documentation](https://docs.defectdojo.com/triage_findings/finding_deduplication/about_deduplication/) describes configurable matching. | Treat finding identity, scan scope, reimport, and lifecycle as a product contract before claiming cross-scan intelligence. An export integration is cheaper than recreating an enterprise findings UI. |
| [ArcherySec](https://github.com/archerysec/archerysec) | Scanner orchestration and vulnerability management with web/API surfaces and multiple scanner integrations. | Argus can stay focused on CI and local workflows; prioritize observable execution and stable integration APIs before expanding into a management platform. |
| [PR-Agent](https://github.com/The-PR-Agent/pr-agent) | Open-source AI-assisted PR review and code suggestions; distinct from the vendor's commercial free tier. | Separate AI suggestions from deterministic security evidence. Measure review usefulness and cost without allowing AI verdicts to erase verified secrets. |

Argus's opportunity is the combination: several scanners, contextual AI review,
and deterministic gating in one workflow. Its disadvantage is integration
consistency and release discipline. The selected improvements directly address
that gap; they do not establish that Argus detects more vulnerabilities than
these peers.

## Prioritized roadmap

### Milestone 1 — trustworthy execution and distribution (this change)

Acceptance: scanner exceptions and missing binaries cannot appear clean;
verified secrets survive AI filtering; policy errors are explicit; empty release
scans still evaluate requirements; saved artifacts and CLI/Action agree; wheel
and source archive contain working code, entry points, and built-in resources.
Regression CI uses a pinned, checksum-verified OPA binary. Existing broad CI
failures are not hidden by the new focused workflow.

### Milestone 2 — consistent pipeline contracts

- Define one typed scanner result: status, findings, diagnostics, tool/version,
  scanned/skipped paths, duration, and rule/database versions. Preserve useful
  partial findings while reporting incomplete coverage.
- Align PhaseGate names and enforce strict decisions; add malformed phase-output
  and missing-required-stage tests.
- Select one authoritative finding schema across enrichment, Rego, persistence,
  and SARIF. Make pre/post-suppression policy semantics explicit.
- Wire diff scope, app context, findings storage, and costs into the synchronous
  pipeline, or disable/label unfinished integrations.

Acceptance: all supported scanner adapters pass the same fixture-based contract
suite; strict invalid output stops enforcement; optional features have a tested
observable effect; reported cost is the measured provider total.

### Milestone 3 — finding lifecycle and measurable quality

- Introduce versioned fingerprints including rule/CVE, package identity, location,
  and repository scope, with migrations and collision fixtures.
- Record scan scope/completeness; never infer fixed status from a partial scan.
- Publish labeled vulnerable and clean fixtures, scanner versions, model/prompt
  revisions, precision/recall, suppression false negatives, latency, and cost.
- Compare deterministic-only and AI-enriched runs on the same corpus. Include
  adversarial repository text and verified-secret retention tests.

Acceptance: reproducible evaluation output, explicit confidence intervals/sample
sizes, and no material suppression regression against deterministic evidence.

### Milestone 4 — operational maturity

- Consolidate duplicate CI into lint/type, offline unit/contract, scanner/container,
  policy, and distribution jobs with clear required checks.
- Separate minute-long fuzzing, Docker/npm behavior tests, and live network tests
  from fast unit tests; remove nondeterministic fixtures and source-text assertions.
  Mock package-manager downloads at their actual subprocess boundary: some unit
  tests currently mock HTTP while the implementation invokes npm or pip. Clarify
  whether network-disabled settings cover all downloads or only scorecard checks.
- Add dependency constraints/lock strategy, reproducible scanner downloads,
  signed release artifacts, and compatibility/release documentation.
- Audit sandbox capabilities, mounts, privilege, resource limits, and generated
  exploit handling. Network-disabled configuration alone is not proof of isolation.
- Add a stable export contract for downstream findings systems such as DefectDojo.

Acceptance: clean required CI across the supported Python matrix, repeatable
install/build results, documented upgrades, and a separately reviewed sandbox
threat model. Multi-tenant UI, fleet scheduling, and enterprise access control
should be separate product decisions.

## Validation and limits

Baseline on Python 3.11: 4,052 passed, 113 skipped, 12 failed, 40 subtests passed
with a deliberately bounded 20-second timeout. Seven failures were minute-long
fuzzing or Docker behavior tests exceeding that local limit; three were incomplete
analyzer test fixtures and two were workflow-security checks. Those five fixture/
workflow failures were repaired. Baseline Ruff reported 802 findings. The wheel
built successfully but contained no application files.

Final full suite: **4,118 passed, 110 skipped, 40 subtests passed, zero failures**
with a 120-second per-test timeout and four workers. All 23 Rego tests pass.
Changed Python files pass Ruff, and clean installed-wheel checks pass. Detailed
commands and results are recorded in the implementation plan. No paid AI
request, remote target scan, or production exploit execution was needed. Live
scanner/container tests require their external runtimes and remain a separate
validation obligation. This review does not certify the remaining sandbox,
autofix, MCP, or optional scanner attack surface.
