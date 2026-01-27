# Multi-Agent DAST Architecture (Phase 1 MVP)

## 🎯 Overview

Phase 1 MVP delivers enhanced DAST integration through specialized agents working in parallel:

```
┌─────────────────────────────────────────────────────────────────┐
│                    DAST Orchestrator                             │
│           (Parallel Execution + Smart Routing)                   │
└────────────┬────────────────────────────────┬───────────────────┘
             │                                │
    ┌────────▼─────────┐            ┌────────▼─────────┐
    │  Nuclei Agent    │            │    ZAP Agent     │
    │  Enhanced        │            │  Spider + Scan   │
    │  Template Mgmt   │            │  API Testing     │
    └────────┬─────────┘            └────────┬─────────┘
             │                                │
             │         ┌──────────────────────┘
             │         │
    ┌────────▼─────────▼─────────┐
    │  Results Aggregator         │
    │  - Deduplication            │
    │  - Enrichment               │
    │  - Priority Scoring         │
    └────────┬────────────────────┘
             │
    ┌────────▼────────────────────┐
    │  SAST-DAST Correlator       │
    │  - Match static + dynamic   │
    │  - Confirm exploitability   │
    │  - Reduce false positives   │
    └────────┬────────────────────┘
             │
    ┌────────▼────────────────────┐
    │  Unified Reporter           │
    │  SARIF + JSON + Markdown    │
    └─────────────────────────────┘
```

## 🤖 Agent Specializations

### 1. **NucleiAgent** - Fast & Comprehensive
**Responsibilities:**
- Smart template selection based on tech stack
- Rate-limited scanning (150 req/s)
- OpenAPI endpoint discovery
- CVE detection (4000+ templates)
- OWASP Top 10 coverage

**Enhancements (Phase 1):**
- **Template Intelligence:** Auto-select templates based on detected framework
- **Caching:** Skip templates that rarely find issues
- **Incremental Scanning:** Only test changed endpoints
- **Custom Rules:** Project-specific vulnerability patterns

**Tech Stack Detection:**
- Django → SQLi, CSRF, XSS templates
- FastAPI → API misconfiguration, JWT issues
- Next.js → XSS, CSP bypass, SSRF
- Spring Boot → Deserialization, SSRF, XXE

### 2. **ZAPAgent** - Deep & Thorough
**Responsibilities:**
- Spider crawling for endpoint discovery
- Active scanning for complex attacks
- Authentication handling (session, JWT, OAuth)
- API schema-based testing
- Ajax spider for SPAs

**Configuration:**
```python
{
    "spider_max_depth": 3,
    "spider_max_duration": 300,  # 5 minutes
    "active_scan_policy": "balanced",
    "ajax_spider": True,
    "api_scan": True,
    "authentication": {
        "type": "bearer",  # bearer, cookie, basic
        "credentials": "..."
    }
}
```

**Scan Profiles:**
- **Fast:** Spider + passive scan (2-3 min)
- **Balanced:** Spider + active scan (5-10 min)
- **Comprehensive:** Full active scan (15-30 min)

### 3. **DASTOrchestrator** - Intelligent Coordination
**Responsibilities:**
- Parallel agent execution
- Smart routing (Nuclei for APIs, ZAP for web apps)
- Resource management (rate limiting across agents)
- Failure handling & retries
- Progress tracking

**Execution Strategy:**
```python
# Run both agents in parallel
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    nuclei_future = executor.submit(nuclei_agent.scan, targets)
    zap_future = executor.submit(zap_agent.scan, target_url)
    
    # Wait for both with timeout
    nuclei_results = nuclei_future.result(timeout=600)
    zap_results = zap_future.result(timeout=1200)
```

**Decision Logic:**
- **API-Heavy Project:** Prioritize Nuclei + ZAP API scan
- **Web Application:** Prioritize ZAP spider + active scan
- **Both:** Run in parallel, correlate results

### 4. **CorrelationEngine** - SAST ↔ DAST Bridge
**Responsibilities:**
- Match SAST findings with DAST confirmations
- Upgrade severity if exploitable
- Reduce false positives
- Build attack chains

**Correlation Rules:**
```python
{
    "SQLi": {
        "sast_rules": ["python.sql-injection", "semgrep.sqli"],
        "dast_templates": ["nuclei/sqli/*", "zap/40018"],
        "confidence_boost": 0.9  # High confidence if both find it
    },
    "XSS": {
        "sast_rules": ["javascript.xss-sink"],
        "dast_templates": ["nuclei/xss/*", "zap/40012"],
        "confidence_boost": 0.85
    }
}
```

**Output Example:**
```json
{
    "id": "correlated-sqli-001",
    "type": "SQL Injection",
    "sast_finding": {
        "file": "api/users.py",
        "line": 42,
        "code": "db.execute(f'SELECT * FROM users WHERE id={user_id}')",
        "rule": "python.sql-injection"
    },
    "dast_confirmation": {
        "url": "https://api.example.com/users?id=1' OR '1'='1",
        "template": "nuclei/sqli-error-based",
        "exploitable": true,
        "poc": "curl -X GET '...'"
    },
    "severity": "critical",
    "confidence": 0.95
}
```

### 5. **ResultsAggregator** - Smart Deduplication
**Responsibilities:**
- Merge findings from Nuclei + ZAP
- Deduplicate identical issues
- Enrich with CWE/CVE mappings
- Priority scoring

**Deduplication Strategy:**
- **Exact Match:** Same URL + same vuln type → dedupe
- **Similar Match:** Same URL + related vuln type → merge evidence
- **Different Context:** Same vuln type + different URL → keep separate

**Priority Scoring:**
```
Priority = (Severity × 10) + (Exploitability × 5) + (Confidence × 3)

Critical + Exploitable + High Confidence = 10×10 + 5×5 + 3×0.9 = 127.7
High + Moderate + Medium Confidence = 10×7 + 5×3 + 3×0.6 = 86.8
```

## 📊 Phase 1 MVP Deliverables

### Week 1: Foundation
- [x] NucleiAgent enhancement (template intelligence)
- [x] ZAPAgent implementation (spider + active scan)
- [ ] DASTOrchestrator (parallel execution)
- [ ] Basic configuration system

### Week 2: Integration
- [ ] SAST-DAST correlation engine
- [ ] ResultsAggregator with deduplication
- [ ] OpenAPI-based testing
- [ ] Authentication handling

### Week 3: Orchestration
- [ ] Parallel execution framework
- [ ] Smart routing logic
- [ ] Resource management
- [ ] Progress tracking

### Week 4: Reporting
- [ ] Unified SARIF output
- [ ] Markdown report generator
- [ ] JSON API for programmatic access
- [ ] Cost & duration metrics

### Week 5: Testing & Polish
- [ ] Integration tests
- [ ] Docker support
- [ ] GitHub Actions workflow
- [ ] Documentation & examples

## 🚀 Quick Start (Post-MVP)

```bash
# Install dependencies
pip install -r requirements-dast.txt

# Run enhanced DAST scan
python scripts/dast_orchestrator.py \
    --target https://api.example.com \
    --openapi openapi.yaml \
    --agents nuclei,zap \
    --profile balanced \
    --correlation-enabled \
    --output dast-results/
```

## 🔧 Configuration

```yaml
# dast-config.yml
orchestrator:
  max_duration: 600  # 10 minutes
  parallel_agents: true
  failure_threshold: 0.5

agents:
  nuclei:
    enabled: true
    templates:
      - cves/
      - vulnerabilities/
      - misconfiguration/
    rate_limit: 150
    concurrency: 25
    
  zap:
    enabled: true
    profile: balanced
    spider:
      max_depth: 3
      max_duration: 300
    active_scan:
      policy: "OWASP Top 10"
      max_duration: 600

correlation:
  enabled: true
  confidence_threshold: 0.7
  sast_sources:
    - semgrep
    - trivy
    - checkov

reporting:
  formats:
    - sarif
    - json
    - markdown
  include_correlation: true
  include_poc: true
```

## 💰 Cost & Performance

### Phase 1 MVP Scan (5-10 min):
- **Nuclei:** 2-3 minutes, free
- **ZAP:** 5-8 minutes, free
- **Correlation:** 10-30 seconds, free
- **Total:** 5-10 minutes, $0

### Compared to Commercial Tools:
- **Burp Suite Pro:** $449/year per user
- **Veracode DAST:** $1,500-3,000/app/year
- **Checkmarx DAST:** Custom pricing ($$$$)

**Argus Phase 1 MVP:** Free + open source

## 📈 Success Metrics

### Goals:
- **50%+ DAST coverage** improvement over Nuclei alone
- **30%+ false positive reduction** via correlation
- **5-10 minute** scan time (balanced mode)
- **90%+ OWASP Top 10** detection rate
- **Zero cost** (all open source tools)

### Measurement:
```python
{
    "coverage_improvement": 0.52,  # 52% more endpoints tested
    "false_positive_reduction": 0.34,  # 34% fewer false positives
    "scan_duration": 487,  # 8 minutes 7 seconds
    "owasp_detection_rate": 0.93,  # 93% OWASP Top 10 coverage
    "cost": 0.0  # Free!
}
```

## 🔮 Phase 2 Enhancements (Future)

- **Burp Suite integration** (for teams with Pro license)
- **Environment-aware scanning** (staging vs production)
- **Continuous DAST** (monitor production APIs)
- **ML-based attack generation** (custom payloads)
- **Vulnerability chaining** (exploit combos)
