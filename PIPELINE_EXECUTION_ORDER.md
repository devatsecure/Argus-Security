# Argus Security - Complete Pipeline Execution Order

## Overview

This document details the complete execution flow of Argus Security's analysis pipeline, showing how all phases integrate together.

## Pipeline Execution Flow

### Main Pipeline (Single-Agent Mode)

```
┌─────────────────────────────────────────────────────────────────┐
│                    ARGUS SECURITY PIPELINE                      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ PRE-PHASE: INITIALIZATION                                       │
├─────────────────────────────────────────────────────────────────┤
│ • Detect AI provider (Anthropic/OpenAI/Ollama)                  │
│ • Initialize AI client and verify model access                  │
│ • Set cost limits and circuit breaker                           │
│ • Generate/Load threat model (if pytm available)                │
│ • Analyze codebase structure and enumerate files                │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ PRE-SCAN: HEURISTIC SCANNING                                    │
├─────────────────────────────────────────────────────────────────┤
│ • Run lightweight pattern matching (HeuristicScanner)           │
│ • Flag suspicious files before expensive LLM calls              │
│ • Run Semgrep SAST scan (if enabled)                            │
│ • Estimate cost and verify against limit                        │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 1: RESEARCH & FILE SELECTION                              │
├─────────────────────────────────────────────────────────────────┤
│ Location: run_ai_audit.py:3525-3625                            │
│ • Build lightweight file summary                                │
│ • Add threat model context if available                         │
│ • LLM analyzes file list and identifies priority files          │
│ • Categorize files by risk level (high/medium/low)              │
│ • Identify focus areas (security/performance/testing/quality)   │
│ Output: research_data with high_priority_files list             │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 2: PLANNING & FOCUS IDENTIFICATION                        │
├─────────────────────────────────────────────────────────────────┤
│ Location: run_ai_audit.py:3627-3693                            │
│ • Build context with ONLY priority files (first 500 chars)      │
│ • LLM creates focused analysis plan                             │
│ • Identifies specific issues to investigate                     │
│ • Generates actionable checklist for detailed analysis          │
│ Output: plan_summary                                            │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ ⭐ PHASE 2.7: DEEP ANALYSIS ENGINE                              │
├─────────────────────────────────────────────────────────────────┤
│ Location: run_ai_audit.py:3695-3795                            │
│ Conditional: Only runs if deep_analysis_mode != "off"           │
│                                                                  │
│ Configuration:                                                   │
│ • Mode: off / semantic-only / conservative / full               │
│ • Max files: 50 (default, configurable)                         │
│ • Timeout: 300s (default, configurable)                         │
│ • Cost ceiling: $5.00 (default, configurable)                   │
│ • Dry run: false (default, configurable)                        │
│                                                                  │
│ Sub-Phases (based on mode):                                     │
│ • Semantic Analysis: Code twin comparison & logical flaws       │
│ • Proactive Analysis: Spontaneous vulnerability discovery       │
│                                                                  │
│ Process:                                                         │
│ 1. Parse deep_analysis_mode from config/env                     │
│ 2. Initialize DeepAnalysisEngine with config                    │
│ 3. Run enabled analysis phases                                  │
│ 4. Normalize findings to standard format                        │
│ 5. Merge findings into main findings dict                       │
│ 6. Export detailed results to argus_deep_analysis_results.json  │
│ 7. Print benchmark report if enabled                            │
│                                                                  │
│ Output: deep_analysis_findings added to findings dict           │
│         Categories: deep_analysis_semantic, deep_analysis_proactive │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 3: DETAILED IMPLEMENTATION ANALYSIS                       │
├─────────────────────────────────────────────────────────────────┤
│ Location: run_ai_audit.py:3797-3929                            │
│ • Build FULL context for priority files                         │
│ • Load audit instructions from profile or use default           │
│ • Detect contradictions in context                              │
│ • LLM performs detailed analysis based on plan                  │
│ • Generate comprehensive audit report                           │
│ Output: phase3_findings                                         │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ POST-PHASE 3: FINDINGS MERGE                                    │
├─────────────────────────────────────────────────────────────────┤
│ Location: run_ai_audit.py:3930-3942                            │
│ • Parse Phase 3 findings from report                            │
│ • Merge Phase 2.7 deep analysis findings (if any)               │
│ • Convert findings dict to list                                 │
│ • Normalize all findings to consistent format                   │
│ Output: all_findings (combined list)                            │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 6: REPORTING                                              │
├─────────────────────────────────────────────────────────────────┤
│ Location: run_ai_audit.py:3944-3999                            │
│ • Record finding metrics                                        │
│ • Generate SARIF (GitHub code scanning format)                  │
│ • Generate structured JSON output                               │
│ • Save metrics to metrics.json                                  │
│ • Save context tracking summary                                 │
│ • Print summary statistics                                      │
│                                                                  │
│ Output Files:                                                    │
│ • .argus/reviews/{review_type}-report.md                        │
│ • .argus/reviews/results.sarif                                  │
│ • .argus/reviews/results.json                                   │
│ • .argus/reviews/metrics.json                                   │
│ • .argus/reviews/context-tracking.json                          │
│ • argus_deep_analysis_results.json (if Phase 2.7 ran)           │
└─────────────────────────────────────────────────────────────────┘
```

## Multi-Agent Mode (Sequential)

When `--multi-agent-mode=sequential`:

```
┌─────────────────────────────────────────────────────────────────┐
│ MULTI-AGENT SEQUENTIAL REVIEW                                   │
├─────────────────────────────────────────────────────────────────┤
│ Replaces Phases 1-3 with specialized agents:                    │
│ • SecretHunter: Credentials expert                              │
│ • ArchitectureReviewer: Design flaws                            │
│ • ExploitAssessor: Exploitability analysis                      │
│ • FalsePositiveFilter: Noise elimination                        │
│ • ThreatModeler: Attack chain mapping                           │
│                                                                  │
│ Note: Phase 2.7 can run alongside multi-agent mode              │
└─────────────────────────────────────────────────────────────────┘
```

## Phase 2.7 Integration Details

### Conditional Execution

Phase 2.7 only executes when:

```python
deep_mode = DeepAnalysisMode.from_string(config.get("deep_analysis_mode", "off"))
if deep_mode != DeepAnalysisMode.OFF:
    # Phase 2.7 executes
```

### Configuration Priority

1. Command-line flag: `--deep-analysis-mode=conservative`
2. Environment variable: `DEEP_ANALYSIS_MODE=conservative`
3. Default: `off` (Phase 2.7 skipped)

### Modes and Enabled Phases

| Mode | Semantic Analysis | Proactive Analysis | Use Case |
|------|-------------------|-------------------|----------|
| `off` | ❌ | ❌ | Skip Phase 2.7 entirely |
| `semantic-only` | ✅ | ❌ | Code twin comparison only |
| `conservative` | ✅ | ✅ | Recommended for most use cases |
| `full` | ✅ | ✅ | All modules (future-proof) |

### Findings Integration

Phase 2.7 findings are normalized and merged with Phase 3 findings:

```python
# Phase 2.7 stores findings in dict format
findings["deep_analysis_semantic"] = [...]
findings["deep_analysis_proactive"] = [...]

# Merged with Phase 3 findings (list format)
all_findings = phase3_findings + deep_analysis_findings
```

### Finding Normalization

Deep analysis findings are normalized to match standard format:

```python
{
    "severity": "high",           # critical/high/medium/low
    "category": "deep_analysis_semantic",
    "message": "Title of finding",
    "file_path": "path/to/file.py",
    "line_number": 42,
    "rule_id": "DEEP_ANALYSIS_SEMANTIC-001",
    "description": "Detailed description",
    "confidence": 0.85
}
```

## Feature Compatibility Matrix

| Feature | Compatible with Phase 2.7 | Notes |
|---------|---------------------------|-------|
| Semgrep scanning | ✅ | Runs before Phase 2.7 |
| Threat modeling | ✅ | Used as context in Phase 2.7 |
| Multi-agent mode | ✅ | Phase 2.7 runs before agents |
| Heuristic scanning | ✅ | Runs before Phase 2.7 |
| Cost circuit breaker | ✅ | Separate cost tracking |
| Benchmarking | ✅ | Optional via --benchmark flag |

## Command-Line Examples

### Enable Phase 2.7 with conservative mode
```bash
python scripts/run_ai_audit.py . audit --deep-analysis-mode=conservative
```

### Enable with shorthand flag
```bash
python scripts/run_ai_audit.py . audit --enable-deep-analysis
```

### Configure limits
```bash
python scripts/run_ai_audit.py . audit \
  --deep-analysis-mode=full \
  --max-files-deep-analysis=100 \
  --deep-analysis-timeout=600 \
  --deep-analysis-cost-ceiling=10.0
```

### Dry run to estimate cost
```bash
python scripts/run_ai_audit.py . audit \
  --deep-analysis-mode=conservative \
  --deep-analysis-dry-run
```

### All features enabled
```bash
python scripts/run_ai_audit.py . audit \
  --deep-analysis-mode=conservative \
  --multi-agent-mode=sequential \
  --benchmark
```

## Environment Variables

Phase 2.7 respects these environment variables:

```bash
export DEEP_ANALYSIS_MODE=conservative           # Mode setting
export DEEP_ANALYSIS_MAX_FILES=50                # Max files to analyze
export DEEP_ANALYSIS_TIMEOUT=300                 # Timeout in seconds
export DEEP_ANALYSIS_COST_CEILING=5.0            # Cost limit in USD
```

## Output Files

### Standard Outputs (always generated)
- `.argus/reviews/audit-report.md` - Main report
- `.argus/reviews/results.sarif` - SARIF format
- `.argus/reviews/results.json` - Structured JSON
- `.argus/reviews/metrics.json` - Metrics
- `.argus/reviews/context-tracking.json` - Context tracking

### Phase 2.7 Outputs (when enabled)
- `argus_deep_analysis_results.json` - Detailed deep analysis results
  - Contains all findings with full context
  - Includes benchmark data if enabled
  - Shows cost and token usage per phase

## Verification Checklist

- ✅ Phase 2.7 executes AFTER Phase 2 (Planning)
- ✅ Phase 2.7 executes BEFORE Phase 3 (Detailed Analysis)
- ✅ Conditional execution based on mode flag works
- ✅ Findings are normalized to standard format
- ✅ Findings are merged with Phase 3 findings
- ✅ Compatible with Semgrep, threat modeling, multi-agent mode
- ✅ Cost tracking and circuit breaker work independently
- ✅ Benchmarking can be enabled alongside Phase 2.7
- ✅ All configuration methods work (CLI, env vars, defaults)

## Performance Characteristics

| Mode | Typical Duration | Typical Cost | Findings |
|------|-----------------|--------------|----------|
| off | 0s | $0.00 | None |
| semantic-only | 30-60s | $0.50-$2.00 | Code twins, logical flaws |
| conservative | 60-120s | $1.00-$4.00 | + proactive discovery |
| full | 90-180s | $2.00-$5.00 | All modules |

*Note: Times and costs are estimates based on a 50-file codebase with moderate complexity.*

## Troubleshooting

### Phase 2.7 not running?

1. Check mode setting: `echo $DEEP_ANALYSIS_MODE`
2. Verify argus_deep_analysis is installed
3. Check logs for import errors
4. Ensure cost limit allows Phase 2.7

### Findings not appearing in output?

1. Check findings merge logic (line 3933-3942)
2. Verify finding normalization (line 3763-3775)
3. Check category names match expected format

### Cost exceeded?

1. Reduce max-files: `--max-files-deep-analysis=25`
2. Use semantic-only mode: `--deep-analysis-mode=semantic-only`
3. Increase ceiling: `--deep-analysis-cost-ceiling=10.0`
4. Use dry run first: `--deep-analysis-dry-run`

## Architecture Diagram

```
┌──────────────┐
│   run_audit  │  Main orchestrator
└──────┬───────┘
       │
       ├─→ Threat Modeling (optional)
       ├─→ Heuristic Scanning
       ├─→ Semgrep Scanning (optional)
       │
       ├─→ Phase 1: Research
       ├─→ Phase 2: Planning
       │
       ├─→ Phase 2.7: Deep Analysis (conditional) ← NEW
       │   ├─→ Semantic Analysis
       │   └─→ Proactive Analysis
       │
       ├─→ Phase 3: Detailed Analysis
       │
       ├─→ Findings Merge ← Phase 2.7 + Phase 3
       │
       └─→ Phase 6: Reporting
```

## Version Information

- **Pipeline Version**: 1.0.16
- **Phase 2.7 Added**: 2024-01-29
- **Compatible With**: All existing features
- **Breaking Changes**: None
