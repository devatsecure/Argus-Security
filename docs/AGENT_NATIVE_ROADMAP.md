# Agent-Native Development Roadmap

> **Analysis Date:** 2026-01-14
> **Reference:** [Every.to Agent-Native Guide](https://every.to/guides/agent-native)
> **Status:** Recommendations for enhancing Argus with agent-native principles

---

## Executive Summary

Argus already follows many agent-native principles (atomic tools, modular architecture, clear verification). This document outlines enhancements to make the platform more "agent-first" by enabling:

1. **Dynamic tool composition** - Agents discover and combine security checks at runtime
2. **Feedback loops** - System learns from user corrections to improve accuracy
3. **Self-observation** - Track agent decision quality to discover improvement opportunities
4. **Emergent capabilities** - New security patterns emerge from tool composition vs hard-coding

---

## Current State: What Argus Does Well

| Principle | Implementation | Evidence |
|-----------|----------------|----------|
| **Atomic Tools** | ✅ Excellent | TruffleHog, Gitleaks, Semgrep, Trivy, Checkov as discrete primitives |
| **Clear Verification** | ✅ Strong | pytest (167 tests), ruff, mypy, 100% coverage on critical modules |
| **Modular Architecture** | ✅ Strong | `orchestrator/` pattern, `BaseScannerInterface` abstraction |
| **Observable Outcomes** | ✅ Good | Rich progress bars, structured JSON/SARIF output |
| **Disciplined Workflow** | ✅ Good | Scan → Normalize → Triage → Gate → Report pipeline |
| **Agent Documentation** | ✅ Excellent | CLAUDE.md (14KB), comprehensive architecture docs |

**Strengths:**
- Scanner orchestration is well-designed for composition
- AI triage reduces noise by 60-70%
- Caching system speeds up repeat scans 10-100x
- Policy-as-code (Rego) enables flexible gates

---

## Gaps: Agent-Native Principles Not Yet Implemented

| Principle | Current State | Impact |
|-----------|---------------|--------|
| **Tool-UI Parity** | ❌ Missing | Agents can't programmatically compose security checks without CLI |
| **Emergent Features** | ⚠️ Limited | Workflows are hard-coded; can't discover new patterns dynamically |
| **Agent Self-Observation** | ⚠️ Limited | AI decisions logged but not analyzed for quality improvement |
| **Feedback Loop** | ❌ Missing | No mechanism to mark findings as TP/FP and learn from corrections |
| **Dynamic Tool Loading** | ❌ Missing | Scanners statically configured; no plugin architecture |
| **Composable Primitives** | ⚠️ Limited | Can't define custom security checks without code changes |

**Consequences:**
- Agents must use CLI wrappers instead of native APIs
- New security checks require code changes vs composition
- AI accuracy can't improve from user feedback
- Limited observability into agent decision-making quality

---

## Recommendations

### 🔥 **Priority 1: Quick Wins (1-2 weeks)**

#### **1. Agent Decision Telemetry**
**Status:** ⭐⭐⭐ (High Impact, Low Effort)

**What:** Log AI triage decisions with reasoning traces for analysis

**Files to modify:**
- `scripts/providers/anthropic_provider.py`
- `scripts/providers/openai_provider.py`
- `scripts/cache_manager.py` (add `log_decision()` method)

**Implementation:**
```python
# In anthropic_provider.py after AI triage
decision_log = {
    "finding_id": finding.id,
    "finding_type": finding.type,
    "scanner": finding.scanner,
    "decision": "suppress" if is_suppressed else "escalate",
    "reasoning": response.get("reasoning", ""),
    "confidence": response.get("confidence", 0.0),
    "noise_score": finding.noise_score,
    "model": self.model_name,
    "timestamp": datetime.utcnow().isoformat(),
}
self.cache_manager.log_decision(decision_log)
```

**New file:** `scripts/decision_analyzer.py`
```python
class DecisionAnalyzer:
    """Analyze AI triage decision quality over time."""

    def analyze_decisions(self, log_file: Path) -> Dict[str, Any]:
        """Aggregate decision logs and compute metrics."""
        # Group by scanner, finding_type
        # Compute: suppression rate, avg confidence, decision distribution

    def identify_patterns(self) -> List[Pattern]:
        """Find patterns in suppressed findings (e.g., always suppresses test files)."""

    def suggest_improvements(self) -> List[str]:
        """Recommend new heuristics based on decision patterns."""
```

**Benefits:**
- Discover which finding types AI handles well/poorly
- Build dataset for model fine-tuning
- Audit AI behavior for compliance
- **Estimated effort:** 1 day

---

#### **2. Feedback Collection System**
**Status:** ⭐⭐⭐ (High Impact, Low Effort)

**What:** Let users mark findings as "true positive" or "false positive" to improve AI

**New file:** `scripts/feedback_collector.py`
```python
from typing import Literal, List
from pathlib import Path
import json
from datetime import datetime

class FeedbackCollector:
    """Collect user feedback on finding accuracy to improve AI triage."""

    def __init__(self, feedback_dir: Path = Path(".argus/feedback")):
        self.feedback_dir = feedback_dir
        self.feedback_dir.mkdir(parents=True, exist_ok=True)

    def record_feedback(
        self,
        finding_id: str,
        feedback: Literal["tp", "fp"],
        reason: str,
        user: str = "unknown"
    ):
        """Store feedback for future model improvement."""
        feedback_entry = {
            "finding_id": finding_id,
            "feedback": feedback,
            "reason": reason,
            "user": user,
            "timestamp": datetime.utcnow().isoformat(),
        }
        feedback_file = self.feedback_dir / "feedback.jsonl"
        with feedback_file.open("a") as f:
            f.write(json.dumps(feedback_entry) + "\n")

    def get_similar_findings(
        self,
        finding: UnifiedFinding,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Retrieve past feedback for similar findings (for few-shot prompting)."""
        # Load feedback.jsonl, filter by scanner + finding_type
        # Return most similar findings with feedback

    def generate_few_shot_examples(self, finding: UnifiedFinding) -> str:
        """Generate few-shot prompt from historical feedback."""
        similar = self.get_similar_findings(finding)
        examples = []
        for fb in similar:
            examples.append(f"Finding: {fb['description']}\nDecision: {fb['feedback']}\nReason: {fb['reason']}")
        return "\n\n".join(examples)
```

**CLI integration:** Add `argus feedback` subcommand
```bash
# New CLI command
./scripts/argus feedback <finding-id> --mark fp --reason "Test fixture file"
./scripts/argus feedback <finding-id> --mark tp --reason "Verified exploitable"

# Integration with AI triage
./scripts/argus scan --enable-feedback-learning  # Use historical feedback in prompts
```

**AI integration:** In `anthropic_provider.py`, inject few-shot examples:
```python
# Before making AI call
feedback_examples = self.feedback_collector.generate_few_shot_examples(finding)
prompt = f"""
Previous similar findings and feedback:
{feedback_examples}

Now analyze this finding:
{finding.description}
"""
```

**Benefits:**
- Improve AI accuracy over time without retraining
- Reduce repeat false positives on common patterns
- Users feel in control of system behavior
- **Estimated effort:** 2 days

---

#### **3. Enhanced CLAUDE.md with Agent-Native Examples**
**Status:** ⭐⭐ (Medium Impact, Low Effort)

**What:** Add concrete examples of how agents should compose Argus tools

**File to modify:** `CLAUDE.md`

**Add new section:**
```markdown
## Agent Interaction Patterns

### 1. Discovering Available Capabilities

When asked "What security checks can you run for SQL injection?":

bash
# Discover scanners with SQL injection detection
./scripts/argus list-scanners --capability sql-injection
# Output: semgrep (cwe-89, cwe-564), custom-regex (sql-concat)

# Get details on specific scanner
./scripts/argus scanner-info semgrep --show-rules | grep -i sql
# Output: 47 rules matching SQL injection patterns


### 2. Composing Custom Security Workflows

When asked "Check all user input handlers for injection vulnerabilities":

bash
# Step 1: Find files with user input handling
FILES=$(grep -rl 'params\[' app/controllers/)

# Step 2: Run targeted SAST scan
./scripts/argus scan --scanners semgrep --rules injection \
  --paths "$FILES" --output findings.json

# Step 3: Apply AI triage with custom context
./scripts/argus triage findings.json \
  --context "This is a Rails app using strong params" \
  --output triaged.json

# Step 4: Apply policy gate
./scripts/argus gate triaged.json --stage pr --policy policy/rego/strict.rego


### 3. Explaining and Fixing Findings

When asked "Why was finding abc123 suppressed?":

bash
# Get full finding context with AI reasoning
./scripts/argus explain --finding-id abc123
# Output: AI explanation + suppression reason + confidence score

# Generate fix suggestion
./scripts/argus suggest-fix --finding-id abc123 --language ruby
# Output: Code diff with suggested remediation


### 4. Learning from Feedback

When user says "This finding is wrong - test files should be ignored":

bash
# Record feedback
./scripts/argus feedback abc123 --mark fp --reason "Test fixture file"

# Re-run scan with feedback learning enabled
./scripts/argus scan --enable-feedback-learning
# AI now uses past feedback as few-shot examples


### Key Principles for Agents

1. **Discover, don't assume:** Use `list-scanners`, `scanner-info` to discover capabilities
2. **Compose primitives:** Chain `scan` → `triage` → `gate` → `explain` for custom workflows
3. **Use feedback loops:** Mark findings as TP/FP to improve future scans
4. **Provide context:** Use `--context` flag to give AI domain-specific info
5. **Verify decisions:** Use `explain` to understand why AI made specific choices

### Emergent Capabilities

By composing primitives, agents can create workflows without hard-coding:
- **Incremental scanning:** Scan only changed files in PR
- **Targeted audits:** Focus on specific CWEs or OWASP categories
- **Custom policies:** Combine scanner outputs with Rego logic
- **Compliance reports:** Filter findings by compliance framework (PCI-DSS, SOC2)
```

**Benefits:**
- Agents understand how to use Argus compositionally
- Reduces need for hard-coded workflows
- Encourages tool discovery
- **Estimated effort:** 1 day

---

### 🚀 **Priority 2: Medium-Term Enhancements (2-4 weeks)**

#### **4. Plugin Architecture for Scanners**
**Status:** ⭐⭐ (Medium Impact, Medium Effort)

**What:** Load custom scanners dynamically from `~/.argus/plugins/`

**New file:** `scripts/scanner_registry.py`
```python
import importlib.util
from pathlib import Path
from typing import Dict, Type
from scripts.scanners.base_scanner import BaseScannerInterface

class ScannerRegistry:
    """Discover and load security scanners dynamically."""

    def __init__(self):
        self._scanners: Dict[str, Type[BaseScannerInterface]] = {}
        self._load_builtin_scanners()
        self._discover_plugins()

    def _load_builtin_scanners(self):
        """Load built-in scanners (TruffleHog, Semgrep, etc.)."""
        from scripts.scanners import (
            TruffleHogScanner,
            SemgrepScanner,
            TrivyScanner,
            CheckovScanner,
            GitleaksScanner,
        )
        self._scanners.update({
            "trufflehog": TruffleHogScanner,
            "semgrep": SemgrepScanner,
            "trivy": TrivyScanner,
            "checkov": CheckovScanner,
            "gitleaks": GitleaksScanner,
        })

    def _discover_plugins(self, plugin_dir: Path = Path.home() / ".argus" / "plugins"):
        """Load scanner plugins from filesystem."""
        if not plugin_dir.exists():
            return

        for plugin_file in plugin_dir.glob("*.py"):
            try:
                spec = importlib.util.spec_from_file_location(plugin_file.stem, plugin_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Find classes implementing BaseScannerInterface
                for name, obj in module.__dict__.items():
                    if (isinstance(obj, type) and
                        issubclass(obj, BaseScannerInterface) and
                        obj is not BaseScannerInterface):
                        scanner_name = getattr(obj, "SCANNER_NAME", name.lower())
                        self._scanners[scanner_name] = obj
            except Exception as e:
                logger.warning(f"Failed to load plugin {plugin_file}: {e}")

    def list_scanners(self, capability: str = None) -> List[str]:
        """List available scanners, optionally filtered by capability."""
        scanners = list(self._scanners.keys())
        if capability:
            # Filter by scanner capabilities (e.g., "sql-injection", "secrets")
            scanners = [
                name for name in scanners
                if capability in self._scanners[name].CAPABILITIES
            ]
        return scanners

    def get_scanner(self, name: str) -> BaseScannerInterface:
        """Get scanner instance by name."""
        if name not in self._scanners:
            raise ValueError(f"Unknown scanner: {name}")
        return self._scanners[name]()
```

**CLI integration:** Add `list-scanners` and `scanner-info` commands
```bash
./scripts/argus list-scanners
# Output: trufflehog, semgrep, trivy, checkov, gitleaks, custom-osv

./scripts/argus list-scanners --capability secrets
# Output: trufflehog, gitleaks

./scripts/argus scanner-info semgrep
# Output: Name, version, capabilities, rule count, languages supported
```

**Plugin example:** `~/.argus/plugins/osv_scanner.py`
```python
from scripts.scanners.base_scanner import BaseScannerInterface

class OSVScanner(BaseScannerInterface):
    SCANNER_NAME = "osv"
    CAPABILITIES = ["vulnerabilities", "dependencies"]

    def scan(self, file_path: Path) -> List[UnifiedFinding]:
        # Run OSV scanner and convert to UnifiedFinding format
        pass
```

**Benefits:**
- Users can add custom scanners without forking
- Agents discover available scanners at runtime
- True extensibility
- **Estimated effort:** 3 days

---

#### **5. Security Rule DSL**
**Status:** ⭐⭐ (Medium Impact, Medium Effort)

**What:** Let users define custom security checks in YAML

**New directory:** `~/.argus/custom-rules/`

**Rule format:**
```yaml
# custom-rules/api-key-in-logs.yaml
id: custom-api-key-in-logs
severity: high
category: secrets
message: "API key logged in plaintext"
description: |
  Logging API keys in plaintext exposes them in log aggregation systems.
  Use environment variables and log only key prefixes.
pattern: |
  logger\.(info|debug|warn|error)\(.*['\"]api_key['\"].*\)
languages: [python, ruby, javascript]
paths:
  include: ["app/", "src/", "lib/"]
  exclude: ["test/", "spec/", "tests/"]
metadata:
  cwe: CWE-532
  owasp: A3:2021-Sensitive-Data-Exposure
  remediation: |
    # BEFORE
    logger.info(f"User API key: {user.api_key}")

    # AFTER
    logger.info(f"User API key: {user.api_key[:8]}...")
```

**Integration:** Load custom rules alongside Semgrep rules

**New file:** `scripts/custom_rule_loader.py`
```python
class CustomRuleLoader:
    """Load and validate custom security rules."""

    def load_rules(self, rule_dir: Path) -> List[Dict[str, Any]]:
        """Load all YAML rules from directory."""

    def convert_to_semgrep(self, custom_rule: Dict) -> str:
        """Convert custom rule to Semgrep YAML format."""

    def validate_rule(self, rule: Dict) -> bool:
        """Validate rule has required fields."""
```

**CLI integration:**
```bash
./scripts/argus scan --custom-rules ~/.argus/custom-rules/
./scripts/argus validate-rule ~/.argus/custom-rules/api-key-in-logs.yaml
```

**Benefits:**
- Agents can create security checks on-the-fly
- Codify tribal knowledge as rules
- Share rules across teams
- **Estimated effort:** 4 days

---

### 🌟 **Priority 3: Long-Term Vision (4-8 weeks)**

#### **6. Agent Conversation API**
**Status:** ⭐⭐⭐⭐ (High Impact, High Effort)

**What:** RESTful API for agents to interact with Argus programmatically

**New file:** `scripts/api_server.py` (FastAPI)

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="Argus API", version="1.0.0")

class ScanRequest(BaseModel):
    paths: List[str]
    scanners: List[str] = ["trufflehog", "semgrep", "trivy"]
    enable_ai_triage: bool = True
    context: Optional[str] = None

class ScanResponse(BaseModel):
    scan_id: str
    status: str  # "running", "completed", "failed"
    findings_count: int
    findings_url: str

@app.post("/v1/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    """Trigger security scan with specified scanners and paths."""
    # Run scan asynchronously, return scan_id

@app.get("/v1/scan/{scan_id}")
async def get_scan_status(scan_id: str) -> ScanResponse:
    """Get scan status and results."""

@app.get("/v1/findings/{finding_id}")
async def get_finding(finding_id: str) -> UnifiedFinding:
    """Retrieve finding details and AI explanation."""

@app.post("/v1/findings/{finding_id}/feedback")
async def record_feedback(finding_id: str, feedback: Feedback):
    """Mark finding as true/false positive."""

@app.get("/v1/scanners")
async def list_scanners(capability: Optional[str] = None) -> List[str]:
    """List available scanners."""

@app.get("/v1/scanners/{scanner_name}")
async def get_scanner_info(scanner_name: str) -> ScannerInfo:
    """Get scanner capabilities and metadata."""
```

**Usage by agents:**
```python
# Agent code
import requests

# Start scan
response = requests.post("http://localhost:8000/v1/scan", json={
    "paths": ["app/controllers/"],
    "scanners": ["semgrep"],
    "context": "This is a Rails API with authentication"
})
scan_id = response.json()["scan_id"]

# Poll for results
while True:
    status = requests.get(f"http://localhost:8000/v1/scan/{scan_id}").json()
    if status["status"] == "completed":
        break
    time.sleep(5)

# Get findings
findings = requests.get(status["findings_url"]).json()
```

**Benefits:**
- **True tool-UI parity** - Programmatic access to all capabilities
- Enables multi-agent workflows (orchestration)
- Foundation for web UI
- Integration with external systems (Slack, Jira, etc.)
- **Estimated effort:** 2 weeks

---

#### **7. Observability Dashboard**
**Status:** ⭐⭐ (Medium Impact, High Effort)

**What:** Web UI showing agent decision quality over time

**New directory:** `scripts/dashboard/` (Streamlit)

**Files:**
- `dashboard/app.py` - Main Streamlit app
- `dashboard/metrics.py` - Compute metrics from decision logs
- `dashboard/visualizations.py` - Charts and graphs

**Features:**
- **Decision quality metrics:** False positive rate by scanner, AI suppression accuracy
- **Cost tracking:** Cost per scan, cumulative spend, projected monthly cost
- **Trend analysis:** How accuracy improves with feedback over time
- **Pattern discovery:** Which finding types have high FP rates
- **Recommendations:** Suggested new heuristics based on patterns

**Launch:**
```bash
streamlit run scripts/dashboard/app.py
# Opens browser to http://localhost:8501
```

**Benefits:**
- Discover "latent demand" - what agents struggle with
- Data-driven improvement priorities
- Justify AI cost with measurable ROI
- **Estimated effort:** 2 weeks

---

## Implementation Roadmap

### Phase 1: Foundation (2 weeks)
- ✅ **Week 1:** Agent Decision Telemetry + Enhanced CLAUDE.md
- ✅ **Week 2:** Feedback Collection System

**Deliverables:**
- Decision logs in `.argus/decisions.jsonl`
- `argus feedback` CLI command
- Updated CLAUDE.md with agent interaction patterns

### Phase 2: Extensibility (4 weeks)
- ✅ **Week 3-4:** Plugin Architecture for Scanners
- ✅ **Week 5-6:** Security Rule DSL + Custom Rule Loader

**Deliverables:**
- `~/.argus/plugins/` directory for custom scanners
- `~/.argus/custom-rules/` for security checks
- `argus list-scanners`, `argus validate-rule` commands

### Phase 3: API & Observability (6 weeks)
- ✅ **Week 7-8:** Agent Conversation API (FastAPI)
- ✅ **Week 9-10:** Observability Dashboard (Streamlit)
- ✅ **Week 11-12:** Integration testing + documentation

**Deliverables:**
- RESTful API on `localhost:8000`
- Observability dashboard on `localhost:8501`
- Comprehensive API documentation

---

## Success Metrics

| Metric | Baseline | Target (3 months) | Measurement |
|--------|----------|-------------------|-------------|
| **False Positive Rate** | 30-40% | 15-20% | Feedback system tracking |
| **Agent Adoption** | CLI-only | 50% API usage | API request logs |
| **Custom Scanners** | 5 built-in | 5+ community plugins | Plugin registry |
| **Custom Rules** | 0 | 20+ shared rules | Rule repository |
| **Decision Quality** | Unknown | >80% confidence | Decision log analysis |
| **Cost per Scan** | $0.35 | <$0.25 | Improved targeting |

---

## Resources

### References
- **Every.to Agent-Native Guide:** https://every.to/guides/agent-native
- **Factory.ai Agent Development:** https://factory.ai/news/build-with-agents
- **Tool-UI Parity Principle:** Core concept of agent-native architectures

### Inspiration
- **GitHub Copilot Workspace:** Tool composition for code generation
- **Anthropic Claude Console:** Agent-native API design
- **Semgrep Cloud:** Custom rule marketplace

---

## Next Steps

1. **Review with team:** Discuss priorities and timeline
2. **Spike on P1 items:** Validate effort estimates (1-2 days)
3. **Create GitHub issues:** One issue per recommendation with acceptance criteria
4. **Start with telemetry:** Quick win that enables future improvements
5. **Document as we build:** Update CLAUDE.md with new capabilities

**Questions?** Open a discussion in GitHub Discussions or ping @security-team

---

*Document created: 2026-01-14 by Claude (Argus analysis)*
*Last updated: 2026-01-14*
