# Continuous Security Testing: Closing the Ship-to-Secure Gap

> From periodic pentests to autonomous, every-deploy security validation.

## The Problem

The industry gap is structural: engineering teams push thousands of lines daily, but security validation happens periodically — maybe twice a year for external pentests, or continuously-but-incompletely for in-house teams making hard triage choices about what to cover. Every change that ships untested is a version of the application that was never fully validated.

Argus already addresses much of this with its 6-phase pipeline, AI enrichment, and proof-by-exploitation. But there are specific capabilities that would close the remaining gaps between "scan on schedule" and "secure every release."

This guide maps what Argus has today, what's missing, and concrete implementation paths for each gap.

---

## Capability Matrix: Argus Today vs. Continuous Autonomous Testing

| Capability | Industry Goal | Argus Today | Gap |
|---|---|---|---|
| **Diff-aware scoping** | Only test what changed; skip README edits, focus on auth logic | `FileSelector.get_changed_files()` in fast mode; Phase 1 scanners scan full project | Scanners not diff-scoped |
| **Per-deploy trigger** | Every release triggers security validation | CI workflows on push/PR + weekly cron | No deployment-event integration |
| **Multi-step attack reasoning** | Agents chain cross-component vulnerabilities | `VulnerabilityChainer` with 14 rule-based chain patterns | Rule-based, not agent-driven |
| **Live exploitation** | Validate against running deployment | `SandboxValidator` + `ProofByExploitation` in Docker | Sandbox only, not against live targets |
| **AutoFix → PR** | Generate merge-ready PRs with code fixes | `RemediationEngine` generates diffs/text, no PR creation | No automated PR creation for fixes |
| **Retest after fix** | Automatically verify fix holds | `RegressionTester` as separate CI step | Not a closed loop within a single run |
| **Persistent knowledge base** | Each scan enriches cross-run intelligence | Flat-file JSONL feedback + per-scan JSON outputs | No cross-scan dedup, trending, or historical context |
| **Code-to-runtime context** | Source + API specs + cloud config + architecture | SAST + DAST exist separately; `sast_dast_correlator.py` bridges | No unified context model |

---

## 1. Diff-Intelligent Scanner Scoping

### What exists

`scripts/orchestrator/file_selector.py` has `get_changed_files()` using `git diff --name-only HEAD^ HEAD`. When `only_changed=True`, the AI file-selection layer filters to changed files and boosts their priority by +200 points.

### The gap

Phase 1 scanners (Semgrep, Trivy, Checkov, TruffleHog) always scan the full project path. For a 500-file repo where 3 files changed, all 4 scanners still analyze everything.

### What to build

**a) Semgrep diff scoping**

Semgrep natively supports `--include` patterns. Pass changed file paths:

```python
# In scanner_runners.py, SemgrepRunner.run()
if self.only_changed and self.changed_files:
    for f in self.changed_files:
        cmd.extend(["--include", f])
```

**b) Impact radius expansion**

A single-line change to an auth middleware affects every protected route. Diff-scoping shouldn't be file-literal — it should expand to the blast radius:

```python
class DiffImpactAnalyzer:
    """Expand changed files to their security-relevant impact radius."""

    def expand_impact(self, changed_files: list[str], project_path: str) -> list[str]:
        """Given changed files, return the full set of files in the blast radius.

        - If a middleware/decorator changed, include all files that import it
        - If a model changed, include all routes that use that model
        - If an auth module changed, include all protected endpoints
        """
        expanded = set(changed_files)
        for f in changed_files:
            if self._is_security_critical(f):
                importers = self._find_importers(f, project_path)
                expanded.update(importers)
        return list(expanded)

    def _is_security_critical(self, filepath: str) -> bool:
        """Check if file is auth, middleware, permissions, crypto, etc."""
        security_indicators = [
            'auth', 'permission', 'middleware', 'security',
            'crypto', 'session', 'token', 'oauth', 'rbac',
            'acl', 'policy', 'guard', 'interceptor'
        ]
        name = os.path.basename(filepath).lower()
        return any(ind in name for ind in security_indicators)
```

**c) Smart skip logic**

The Aikido article highlights: "Updated a README and button color? Skipped." Argus should classify diffs by security relevance before deciding whether to scan at all:

```python
class DiffClassifier:
    """Classify a diff as security-relevant or skip-safe."""

    SKIP_PATTERNS = [
        r'\.md$', r'\.txt$', r'\.css$', r'\.scss$',
        r'\.svg$', r'\.png$', r'\.jpg$',
        r'CHANGELOG', r'LICENSE', r'\.gitignore',
    ]

    ALWAYS_SCAN_PATTERNS = [
        r'auth', r'login', r'session', r'token', r'password',
        r'secret', r'key', r'crypt', r'permission', r'rbac',
        r'middleware', r'guard', r'policy', r'\.env',
        r'docker', r'Dockerfile', r'\.tf$', r'\.yml$', r'\.yaml$',
    ]

    def classify(self, changed_files: list[str]) -> dict:
        security_relevant = []
        skippable = []
        for f in changed_files:
            if any(re.search(p, f, re.I) for p in self.ALWAYS_SCAN_PATTERNS):
                security_relevant.append(f)
            elif any(re.search(p, f, re.I) for p in self.SKIP_PATTERNS):
                skippable.append(f)
            else:
                security_relevant.append(f)  # Default: scan
        return {
            'security_relevant': security_relevant,
            'skippable': skippable,
            'should_scan': len(security_relevant) > 0
        }
```

### Where it plugs in

- `scripts/hybrid_analyzer.py` Phase 1 entry, before scanner invocation
- `scripts/scanner_runners.py` in each scanner's `run()` method
- New module: `scripts/diff_impact_analyzer.py`
- Config toggle: `enable_diff_scoping=True`, `diff_expand_impact_radius=True`

---

## 2. Deployment-Triggered Scanning

### What exists

CI workflows trigger on push, PR, and weekly cron. The `action.yml` GitHub Action is the primary integration point.

### The gap

No integration with deployment events. Security validation happens pre-merge, not post-deploy. The running application is never validated against what actually shipped.

### What to build

**a) GitHub Deployment event webhook**

```yaml
# .github/workflows/post-deploy-scan.yml
name: Post-Deploy Security Validation
on:
  deployment_status:
    types: [success]

jobs:
  scan:
    if: github.event.deployment_status.state == 'success'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Get deployment diff
        run: |
          PREV_SHA=$(git log --format='%H' -2 | tail -1)
          echo "DIFF_BASE=$PREV_SHA" >> $GITHUB_ENV

      - uses: devatsecure/Argus-Security@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          review-type: security
          only-changed: true
          fail-on-blockers: true

      # If DAST target is available, also run live validation
      - name: DAST against deployment
        if: vars.DEPLOYMENT_URL != ''
        run: |
          python scripts/dast_orchestrator.py \
            --target-url "${{ vars.DEPLOYMENT_URL }}" \
            --auth-config .argus/dast-auth.yml \
            --diff-only
```

**b) Container registry webhook**

For Docker-based deployments, trigger on image push:

```yaml
on:
  registry_package:
    types: [published]
```

**c) ArgoCD / Flux / Spinnaker integration**

Expose a webhook endpoint (or use the MCP server) that deployment tools call post-deploy:

```python
# In scripts/mcp_server.py, add tool:
@mcp_server.tool("trigger_post_deploy_scan")
async def trigger_post_deploy_scan(
    deployment_url: str,
    commit_sha: str,
    previous_sha: str,
    environment: str = "staging",
) -> dict:
    """Trigger a diff-scoped security scan after deployment."""
    changed_files = get_diff_files(previous_sha, commit_sha)
    results = await run_pipeline(
        target_path=repo_path,
        changed_files=changed_files,
        dast_target=deployment_url,
        scan_mode="post-deploy",
    )
    return results
```

### Where it plugs in

- New workflow: `.github/workflows/post-deploy-scan.yml`
- `scripts/mcp_server.py` new tool registration
- Config: `scan_trigger=["push", "pr", "deploy", "schedule"]`

---

## 3. Agent-Driven Attack Path Reasoning

### What exists

`scripts/vulnerability_chaining_engine.py` implements `VulnerabilityChainer` with 14 pre-defined rule-based chaining patterns (IDOR → Privilege Escalation → Data Breach, XSS → Session Hijacking → Account Takeover, etc.). Uses NetworkX for graph traversal with probability-weighted edges.

Phase 3's `agent_personas.py` runs 5 specialized AI personas for multi-agent review, but these are independent reviewers — they don't collaborate on attack path discovery.

### The gap

The chaining is rule-based: if finding A is category X and finding B is category Y, draw an edge. It doesn't reason about application-specific context — whether a particular XSS is actually in a position to steal a session token, or whether a specific SSRF can reach an internal metadata endpoint.

The Aikido article describes agents that "reason about application behavior, chain multi-step attack paths, and validate exploitability through real exploitation." That's agent-driven reasoning, not pattern matching.

### What to build

**a) LLM-powered chain discovery**

Use the existing LLM infrastructure to ask the model to reason about cross-finding relationships:

```python
class AgentChainDiscovery:
    """Use LLM agents to discover attack chains that rule-based logic misses."""

    CHAIN_DISCOVERY_PROMPT = """You are a senior penetration tester analyzing a set of
security findings from the same application. Your job is to identify multi-step
attack paths that chain these findings together.

For each chain you discover, explain:
1. The entry point (which finding starts the chain)
2. Each step and what it enables
3. The final impact (what an attacker achieves)
4. Why these specific findings combine dangerously
5. Whether the chain requires authentication or can be triggered anonymously

Findings:
{findings_json}

Application context:
- Framework: {framework}
- Auth mechanism: {auth_type}
- Architecture: {architecture}

Return your analysis as JSON array of chain objects."""

    async def discover_chains(
        self,
        findings: list[dict],
        app_context: dict,
        llm_client,
    ) -> list[dict]:
        prompt = self.CHAIN_DISCOVERY_PROMPT.format(
            findings_json=json.dumps(findings, indent=2),
            framework=app_context.get('framework', 'unknown'),
            auth_type=app_context.get('auth_type', 'unknown'),
            architecture=app_context.get('architecture', 'unknown'),
        )
        response = await llm_client.analyze(prompt)
        return self._parse_chains(response)
```

**b) Cross-component reasoning**

The key insight from the article: "Two changes that are individually safe can be dangerous in combination: a new API field here, a relaxed permission check there, and suddenly there's a cross-tenant data leak."

This requires understanding component boundaries. Extend the chaining engine to consider data flow between components:

```python
class CrossComponentAnalyzer:
    """Analyze how findings in different components interact."""

    def analyze_cross_component_risk(
        self,
        findings: list[dict],
        dependency_graph: dict,  # file → [files it imports]
    ) -> list[dict]:
        """Find findings that are individually low-risk but
        dangerous in combination across component boundaries."""

        # Group findings by component
        by_component = defaultdict(list)
        for f in findings:
            component = self._classify_component(f['file_path'])
            by_component[component].append(f)

        # For each pair of connected components,
        # check if their findings combine dangerously
        dangerous_combos = []
        for comp_a, comp_b in self._connected_pairs(dependency_graph):
            findings_a = by_component.get(comp_a, [])
            findings_b = by_component.get(comp_b, [])
            if findings_a and findings_b:
                combos = self._evaluate_combinations(findings_a, findings_b)
                dangerous_combos.extend(combos)

        return dangerous_combos
```

**c) Collaborative agent reasoning**

Currently Phase 3 agents review independently. Add a "red team council" step where agents share findings and collaboratively build attack narratives:

```python
# In agent_personas.py, add collaborative reasoning phase
CHAIN_COUNCIL_PROMPT = """The following security agents have independently
reviewed the codebase and found these issues:

{agent_findings}

As the Red Team Council, your job is to:
1. Identify attack paths that span multiple agents' findings
2. Determine if any combination of "medium" findings creates a "critical" chain
3. Propose exploitation sequences that chain findings end-to-end
4. Highlight any finding that is a prerequisite for exploiting another

Focus on practical, real-world attack scenarios."""
```

### Where it plugs in

- Extend `scripts/vulnerability_chaining_engine.py` with LLM-powered discovery
- New module: `scripts/cross_component_analyzer.py`
- Phase 3 in `scripts/agent_personas.py` — add collaborative council step
- Config: `enable_agent_chain_discovery=True`, `enable_cross_component_analysis=True`

---

## 4. AutoFix → PR → Retest Closed Loop

### What exists

- `RemediationEngine` generates `RemediationSuggestion` objects with `fixed_code`, `diff`, `explanation`, `testing_recommendations`
- `RegressionTester` generates language-specific test code and runs it in CI
- `automated-audit.yml` uses `peter-evans/create-pull-request` to open PRs with audit findings (reports, not code fixes)

### The gap

These three capabilities are disconnected. The engine generates a fix, but nobody applies it. The regression tester exists, but isn't triggered by the fix. There's no PR-with-code-fix flow.

The Aikido article describes: "AutoFix generates a merge-ready PR with the specific code-level fix. Developers review, merge, and agents automatically retest to confirm the fix holds."

### What to build

**a) AutoFix PR generator**

Wire `RemediationEngine` output into actual PR creation:

```python
class AutoFixPRGenerator:
    """Generate merge-ready PRs from remediation suggestions."""

    def create_fix_pr(
        self,
        suggestion: RemediationSuggestion,
        repo_path: str,
        base_branch: str = "main",
    ) -> dict:
        branch_name = f"argus/fix-{suggestion.vulnerability_type}-{suggestion.finding_id[:8]}"

        # Apply the diff to the actual file
        self._apply_fix(suggestion, repo_path)

        # Generate regression test for this fix
        regression_test = self.regression_tester.generate_test(
            finding=suggestion.to_finding_dict(),
            language=self._detect_language(suggestion.file_path),
        )

        # Create PR with fix + test
        pr_body = self._format_pr_body(suggestion, regression_test)

        return {
            'branch': branch_name,
            'files_changed': [suggestion.file_path],
            'test_file': regression_test.path if regression_test else None,
            'title': f"fix: {suggestion.vulnerability_type} in {os.path.basename(suggestion.file_path)}",
            'body': pr_body,
        }

    def _format_pr_body(self, suggestion, regression_test) -> str:
        return f"""## Security Fix — {suggestion.vulnerability_type}

**Finding:** {suggestion.finding_id}
**File:** `{suggestion.file_path}:{suggestion.line_number}`
**CWE:** {', '.join(suggestion.cwe_references)}
**Confidence:** {suggestion.confidence}

### What changed
{suggestion.explanation}

### Diff
```diff
{suggestion.diff}
```

### Testing
{chr(10).join(f'- {t}' for t in suggestion.testing_recommendations)}

### Regression test included
{'Yes — see ' + regression_test.path if regression_test else 'No (template not available for this vuln type)'}

---
*Generated by Argus Security — [verify before merging]*
"""
```

**b) Retest-on-merge workflow**

```yaml
# .github/workflows/argus-retest.yml
name: Argus Retest After Fix
on:
  pull_request:
    types: [closed]

jobs:
  retest:
    if: |
      github.event.pull_request.merged == true &&
      startsWith(github.event.pull_request.head.ref, 'argus/fix-')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run targeted rescan
        run: |
          # Extract the finding ID from the branch name
          FINDING_ID=$(echo "${{ github.event.pull_request.head.ref }}" | sed 's/argus\/fix-.*-//')
          python scripts/regression_tester.py run \
            --test-dir tests/security_regression \
            --finding-id "$FINDING_ID"

      - name: Run SAST on fixed file
        run: |
          CHANGED_FILES=$(gh pr view ${{ github.event.pull_request.number }} --json files -q '.files[].path')
          semgrep --config=auto $CHANGED_FILES

      - name: Update finding status
        if: success()
        run: |
          python -c "
          from feedback_loop import FeedbackLoop
          fl = FeedbackLoop()
          fl.record_feedback(
              finding_id='$FINDING_ID',
              automated_verdict='confirmed',
              human_verdict='confirmed',
              confidence=1.0,
              category='fix_verified',
              reasoning='Automated retest passed after merge'
          )"
```

**c) Full closed-loop orchestration**

The holy grail: scan → find → fix → PR → merge → retest → verify, all automated:

```python
class ClosedLoopOrchestrator:
    """Orchestrate the full find → fix → verify loop."""

    async def run_closed_loop(self, scan_results: list[dict]) -> dict:
        loop_results = {
            'fixed': [],
            'fix_failed': [],
            'retest_failed': [],
            'verified': [],
        }

        fixable = [f for f in scan_results if f.get('auto_fixable')]

        for finding in fixable:
            # Step 1: Generate fix
            suggestion = self.remediation_engine.generate_fix(finding)
            if not suggestion or suggestion.confidence == 'low':
                loop_results['fix_failed'].append(finding)
                continue

            # Step 2: Create PR
            pr = self.pr_generator.create_fix_pr(suggestion)
            loop_results['fixed'].append({**finding, 'pr': pr})

            # Step 3: Run regression test against the fix (pre-merge validation)
            test_result = self.regression_tester.run_single(
                finding_id=finding['id'],
                patched_code=suggestion.fixed_code,
            )

            if test_result.passed:
                loop_results['verified'].append(finding)
            else:
                loop_results['retest_failed'].append(finding)

        return loop_results
```

### Where it plugs in

- New module: `scripts/autofix_pr_generator.py`
- New workflow: `.github/workflows/argus-retest.yml`
- Extend `scripts/hybrid_analyzer.py` Phase 6 to optionally trigger AutoFix
- Config: `enable_autofix_pr=False` (opt-in), `autofix_confidence_threshold="high"`, `autofix_retest=True`

---

## 5. Persistent Security Knowledge Base

### What exists

Argus stores results as flat files:
- `.argus/feedback/feedback_records.jsonl` — human TP/FP verdicts
- `.argus/feedback/confidence_adjustments.json` — pattern multipliers
- `.argus/sandbox-results/` — per-exploit outcomes
- `tests/security_regression/` — regression test cases
- Per-scan JSON/SARIF/Markdown reports

### The gap

Each scan is independent. There's no way to ask "has this vulnerability been seen before?", "is this a regression?", "what's our false positive rate trending?", or "what attack patterns are most common in this codebase?"

### What to build

**a) SQLite-backed findings store**

Lightweight, zero-infrastructure, embedded in the repo (or `.argus/`):

```python
class FindingsStore:
    """Persistent cross-scan findings database."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        scan_timestamp TEXT NOT NULL,
        vuln_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        file_path TEXT,
        line_number INTEGER,
        cwe TEXT,
        cvss_score REAL,
        source_tool TEXT,
        status TEXT DEFAULT 'open',  -- open, fixed, false_positive, accepted_risk
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        times_seen INTEGER DEFAULT 1,
        fix_verified BOOLEAN DEFAULT FALSE,
        fingerprint TEXT NOT NULL  -- content-based dedup key
    );

    CREATE TABLE IF NOT EXISTS scan_history (
        scan_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        commit_sha TEXT,
        branch TEXT,
        total_findings INTEGER,
        critical INTEGER,
        high INTEGER,
        medium INTEGER,
        low INTEGER,
        duration_seconds REAL,
        cost_usd REAL
    );

    CREATE TABLE IF NOT EXISTS fix_history (
        finding_id TEXT,
        fix_commit TEXT,
        fix_timestamp TEXT,
        fix_method TEXT,  -- autofix, manual, dependency_update
        retest_passed BOOLEAN,
        regression_detected BOOLEAN DEFAULT FALSE
    );
    """

    def record_scan(self, scan_results: dict) -> None:
        """Record a scan and upsert all findings."""
        ...

    def is_regression(self, finding: dict) -> bool:
        """Check if a finding was previously fixed but has reappeared."""
        ...

    def trending(self, days: int = 90) -> dict:
        """Return severity trends over time."""
        ...

    def mean_time_to_fix(self, severity: str = None) -> float:
        """Calculate MTTF across all findings or by severity."""
        ...
```

**b) Cross-scan deduplication**

Use content-based fingerprinting to track findings across scans:

```python
def fingerprint_finding(finding: dict) -> str:
    """Generate a stable fingerprint for cross-scan dedup.

    Uses vulnerability type + file path + code context (not line number,
    which shifts with unrelated edits).
    """
    key_parts = [
        finding.get('vuln_type', ''),
        finding.get('file_path', ''),
        finding.get('code_snippet', '')[:200],  # Normalized code context
        finding.get('cwe', ''),
    ]
    return hashlib.sha256('|'.join(key_parts).encode()).hexdigest()[:16]
```

**c) Historical context injection**

Feed knowledge base context into LLM enrichment prompts:

```python
# In Phase 2 AI enrichment, add historical context
historical_context = f"""
Historical context for this finding:
- First seen: {store.first_seen(fingerprint)}
- Times detected: {store.times_seen(fingerprint)}
- Previous status: {store.previous_status(fingerprint)}
- Related findings in same file: {store.related_count(file_path)}
- False positive rate for this pattern: {store.fp_rate(vuln_type)}%

Use this context to calibrate your confidence score.
"""
```

### Where it plugs in

- New module: `scripts/findings_store.py`
- Integrate into `scripts/hybrid_analyzer.py` Phase 6 (record) and Phase 2 (query)
- Extend `scripts/feedback_loop.py` to write to the store
- Config: `enable_findings_store=True`, `findings_db_path=".argus/findings.db"`

---

## 6. Unified Code-to-Runtime Context Model

### What exists

- SAST: Semgrep, Checkov, TruffleHog, heuristic scanner
- DAST: ZAP + Nuclei via `dast_orchestrator.py`
- Correlation: `sast_dast_correlator.py` bridges SAST and DAST findings
- Auth config: `dast_auth_config.py` handles authenticated scanning

### The gap

Each scanner operates with its own isolated view. There's no unified application model that says "here's the full attack surface: these API endpoints exist, they're backed by these handlers, protected by this middleware, talking to this database, deployed behind this cloud config." The correlator connects findings after the fact, but doesn't inform the scanning itself.

### What to build

**a) Application context model**

Build a lightweight representation of the application that all phases can reference:

```python
@dataclass
class ApplicationContext:
    """Unified application context fed to all pipeline phases."""

    # Code structure
    framework: str  # django, express, spring, etc.
    language: str
    entry_points: list[str]  # Main files, route definitions
    auth_mechanism: str  # jwt, session, oauth2, api_key

    # API surface
    api_endpoints: list[dict]  # From OpenAPI spec or route discovery
    middleware_chain: list[str]  # Auth, CORS, rate limiting, etc.
    data_models: list[dict]  # Database models / schemas

    # Infrastructure
    cloud_provider: str  # aws, gcp, azure, none
    iac_files: list[str]  # Terraform, K8s manifests
    container_config: dict  # Dockerfile analysis
    secrets_management: str  # vault, env, ssm, none

    # Dependencies
    direct_deps: list[dict]  # From package.json, requirements.txt, etc.
    transitive_deps: list[dict]  # Full dependency tree

    # DAST context (if available)
    deployment_url: str | None
    authenticated_endpoints: list[str]
    discovered_endpoints: list[str]  # From crawling
```

**b) Context-aware scanning**

Pass the context model into scanner configuration:

```python
# Phase 1: Context-aware Semgrep rules
if context.framework == 'django':
    semgrep_rules.append('p/django')
    semgrep_rules.append('p/python-django-security')
if context.auth_mechanism == 'jwt':
    semgrep_rules.append('p/jwt')

# Phase 2: Context-enriched LLM prompts
enrichment_prompt += f"""
Application context:
- Framework: {context.framework}
- Auth: {context.auth_mechanism}
- Cloud: {context.cloud_provider}
- Known API endpoints: {len(context.api_endpoints)}
- Middleware chain: {' → '.join(context.middleware_chain)}

Use this context to determine if the finding is actually exploitable
in this specific application architecture.
"""
```

### Where it plugs in

- New module: `scripts/app_context_builder.py`
- Called once at pipeline start, passed to all phases
- Feed into `scripts/config_loader.py` as enrichment context
- Config: `enable_app_context=True`

---

## 7. Live Target Validation (Beyond Sandbox)

### What exists

- `SandboxValidator` runs exploit PoCs in isolated Docker containers
- `dast_orchestrator.py` runs ZAP + Nuclei against live targets
- These are separate capabilities — sandbox validates code-level findings, DAST scans network-level surface

### The gap

The sandbox proves "this code is theoretically exploitable in isolation." DAST finds "this endpoint responds to this payload." Neither proves "this specific finding from SAST is exploitable in the deployed application."

The article describes: "Every finding is confirmed through direct exploitation against the live target."

### What to build

**a) SAST-to-DAST validation pipeline**

Take SAST findings and generate targeted DAST tests:

```python
class SastToDastValidator:
    """Validate SAST findings against the live deployment."""

    async def validate_finding(
        self,
        finding: dict,
        target_url: str,
        auth_config: dict,
    ) -> dict:
        """Generate and execute a targeted DAST test for a SAST finding."""

        # Map SAST finding to HTTP test
        test_case = self._generate_test_case(finding)
        if not test_case:
            return {'validated': False, 'reason': 'no_test_mapping'}

        # Execute against live target
        result = await self._execute_test(test_case, target_url, auth_config)

        return {
            'validated': result.exploitable,
            'evidence': result.response_excerpt,
            'http_status': result.status_code,
            'validation_method': 'live_dast',
        }

    def _generate_test_case(self, finding: dict) -> dict | None:
        """Map a SAST finding to a concrete HTTP test case.

        Example: SQL injection in /api/users?id= →
        GET /api/users?id=1' OR '1'='1 and check for data leak indicators
        """
        vuln_type = finding.get('vuln_type', '')
        endpoint = finding.get('endpoint') or self._infer_endpoint(finding)

        if not endpoint:
            return None

        # Generate test payloads based on vulnerability type
        payloads = self.payload_generator.for_vuln_type(vuln_type)
        return {
            'endpoint': endpoint,
            'method': finding.get('http_method', 'GET'),
            'payloads': payloads,
            'success_indicators': self._success_indicators(vuln_type),
        }
```

**b) Exploit replay against deployment**

Wire `ProofByExploitation` to optionally target a live URL instead of only the Docker sandbox:

```python
# In sandbox_validator.py, add a mode for live target validation
class LiveTargetValidator:
    """Validate findings against a live deployment (staging/preview)."""

    ALLOWED_ENVIRONMENTS = ['staging', 'preview', 'development']  # Never production

    def validate(self, finding: dict, target_url: str, environment: str) -> dict:
        if environment not in self.ALLOWED_ENVIRONMENTS:
            raise ValueError(f"Live validation not allowed against {environment}")
        ...
```

### Where it plugs in

- New module: `scripts/sast_dast_validator.py`
- Extend Phase 4 to include live validation when `dast_target_url` is set
- Config: `enable_live_validation=False`, `live_validation_environment="staging"`

---

## Implementation Priority

Ordered by impact-to-effort ratio:

| Priority | Feature | Effort | Impact |
|---|---|---|---|
| **P0** | Diff-intelligent scanner scoping | Medium | High — every scan runs faster and more focused |
| **P0** | AutoFix → PR generation | Medium | High — closes the most visible gap |
| **P1** | Persistent findings store (SQLite) | Medium | High — enables trending, regression detection, MTTF |
| **P1** | Retest-on-merge workflow | Low | Medium — completes the closed loop |
| **P1** | Agent-driven chain discovery | Medium | High — biggest quality uplift for finding depth |
| **P2** | Deployment-triggered scanning | Low | Medium — extends coverage to post-deploy |
| **P2** | Application context model | High | High — improves everything but requires broad integration |
| **P2** | SAST-to-DAST validation | High | Medium — requires live target, auth, environment setup |

---

## Config Toggles Summary

All new capabilities follow Argus's existing pattern of config-driven feature flags:

```yaml
# In profiles/ or config_loader.py defaults
continuous_testing:
  enable_diff_scoping: true
  diff_expand_impact_radius: true
  scan_trigger: ["push", "pr", "deploy"]

autonomous_loop:
  enable_autofix_pr: false          # Opt-in: generates PRs with fixes
  autofix_confidence_threshold: high # Only auto-fix high-confidence suggestions
  autofix_retest: true              # Retest after fix merge
  autofix_max_prs_per_scan: 5      # Rate limit

knowledge_base:
  enable_findings_store: true
  findings_db_path: ".argus/findings.db"
  enable_cross_scan_dedup: true
  enable_trending: true
  inject_historical_context: true   # Feed history into LLM prompts

agent_reasoning:
  enable_agent_chain_discovery: true
  enable_cross_component_analysis: true
  enable_collaborative_council: false  # Expensive: multi-agent discussion

live_validation:
  enable_live_validation: false
  live_validation_environment: staging
  enable_sast_dast_validation: false
```

---

## What This Changes

Today, Argus is a powerful **scan-on-demand** pipeline: trigger it, get results, act on them.

With these additions, Argus becomes a **continuous security loop**:

```
Code pushed → Diff classified → Scanners scoped to blast radius
    → AI enrichment with historical context → Agent-driven chain discovery
    → Sandbox + live validation → AutoFix PRs generated
    → Developer merges → Automated retest → Finding marked verified
    → Knowledge base updated → Next scan is smarter
```

The attackers have autonomous tools. This gives defenders the same.
