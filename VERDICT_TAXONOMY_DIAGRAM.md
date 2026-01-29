# Verdict Taxonomy Visual Reference

## Confidence-to-Verdict Mapping

### Standard Severity (Medium/Low)
```
Confidence    Verdict                  Priority   Action
Range                                  (1-6)
-----------   --------------------     --------   ---------------------------------
1.0 ─┐
     │        CONFIRMED                   1       Immediate/Schedule remediation
0.8 ─┤
     │        LIKELY_TRUE                 2       Manual validation recommended
0.7 ─┤
     │        UNCERTAIN                   3       Human review required
0.4 ─┤
     │        LIKELY_FALSE_POSITIVE       5       Spot check recommended
0.2 ─┤
     │        FALSE_POSITIVE              6       Can suppress
0.0 ─┘

     [NEEDS_REVIEW]                       4       Analysis incomplete - manual investigation
     (analysis_complete = False, any confidence)
```

### High/Critical Severity (Conservative Thresholds)
```
Confidence    Verdict                  Priority   Action
Range                                  (1-6)
-----------   --------------------     --------   ---------------------------------
1.0 ─┐
     │        CONFIRMED                   1       Immediate remediation required
0.8 ─┤
     │        LIKELY_TRUE                 2       Manual validation recommended
0.7 ─┤
     │
     │
     │        UNCERTAIN                   3       Human review required
     │        (expanded range)
     │
     │
0.15─┤
     │        FALSE_POSITIVE              6       Can suppress
0.0 ─┘

Note: For high/critical findings, LIKELY_FALSE_POSITIVE range is effectively removed
      to avoid premature dismissal of serious vulnerabilities
```

## Decision Tree

```
┌─────────────────────────────────────────────────────────────┐
│                  Finding Analysis Complete?                  │
└─────────────────┬───────────────────────────────────────────┘
                  │
        ┌─────────┴─────────┐
        │                   │
       YES                 NO
        │                   │
        │                   └──> NEEDS_REVIEW (Priority 4)
        │                        "Analysis incomplete"
        │
        ├─────────────────────┐
        │  Severity Level?    │
        └─────────────────────┘
                │
        ┌───────┴────────┐
        │                │
    Medium/Low      High/Critical
        │                │
        │                │
┌───────▼─────────┐  ┌──▼──────────────┐
│ Standard        │  │ Conservative    │
│ Thresholds      │  │ Thresholds      │
│                 │  │                 │
│ ≥0.8: CONFIRMED │  │ ≥0.8: CONFIRMED │
│ ≥0.7: LIKELY_TRUE│  │ ≥0.7: LIKELY_TRUE│
│ ≥0.4: UNCERTAIN │  │ ≥0.15: UNCERTAIN│
│ ≥0.2: LIKELY_FP │  │ <0.15: FALSE_POS│
│ <0.2: FALSE_POS │  │                 │
└─────────────────┘  └─────────────────┘
```

## Priority-Based Consensus Example

When multiple agents disagree, highest priority verdict wins:

```
Agent 1: CONFIRMED (priority 1)
Agent 2: UNCERTAIN (priority 3)       → Consensus: CONFIRMED
Agent 3: FALSE_POSITIVE (priority 6)     (priority 1 = highest)
```

```
Agent 1: UNCERTAIN (priority 3)
Agent 2: LIKELY_FALSE_POSITIVE (priority 5)  → Consensus: UNCERTAIN
Agent 3: FALSE_POSITIVE (priority 6)            (priority 3 = highest)
```

```
Agent 1: LIKELY_TRUE (priority 2)
Agent 2: LIKELY_TRUE (priority 2)     → Consensus: LIKELY_TRUE
Agent 3: UNCERTAIN (priority 3)          (unanimous at priority 2)
```

## Deployment/PR Blocking Logic

```
┌───────────────────────────────────────────────────────────────┐
│                    Should Block Deployment?                    │
└───────────────────────────────────────────────────────────────┘

CONFIRMED + Critical     → ✅ BLOCK
CONFIRMED + High         → ✅ BLOCK
CONFIRMED + Medium       → ⚪ PASS
CONFIRMED + Low          → ⚪ PASS

LIKELY_TRUE + Critical   → ✅ BLOCK
LIKELY_TRUE + High       → ⚪ PASS
LIKELY_TRUE + Medium     → ⚪ PASS

UNCERTAIN + Any          → ⚪ PASS (human review needed, not blocker)
LIKELY_FP + Any          → ⚪ PASS
FALSE_POSITIVE + Any     → ⚪ PASS
NEEDS_REVIEW + Any       → ⚪ PASS (investigation needed, not blocker)
```

## Auto-Suppression Logic

```
┌───────────────────────────────────────────────────────────────┐
│                    Can Auto-Suppress Finding?                  │
└───────────────────────────────────────────────────────────────┘

FALSE_POSITIVE + Confidence ≤ 0.2  → ✅ YES (high confidence FP)
FALSE_POSITIVE + Confidence > 0.2  → ❌ NO  (need review)
Any other verdict                  → ❌ NO
```

## Real-World Examples

### Example 1: Clear Vulnerability
```
Finding: Hardcoded AWS secret key in production code
Confidence: 0.92
Severity: Critical
Analysis Complete: Yes

→ Verdict: CONFIRMED
→ Priority: 1
→ Action: "Immediate remediation required"
→ Block Deployment: YES
```

### Example 2: Ambiguous Finding
```
Finding: SQL query construction from user input
Confidence: 0.62
Severity: High
Analysis Complete: Yes
Review Reason: "Cannot determine if ORM provides parameterization"

→ Verdict: UNCERTAIN
→ Priority: 3
→ Action: "Human review required - insufficient confidence for auto-triage"
→ Block Deployment: NO
```

### Example 3: Test File Secret
```
Finding: API key pattern in test fixture
Confidence: 0.15
Severity: Low
Analysis Complete: Yes

→ Verdict: FALSE_POSITIVE
→ Priority: 6
→ Action: "High confidence false positive - can suppress"
→ Block Deployment: NO
→ Auto-Suppress: YES
```

### Example 4: LLM Timeout
```
Finding: Complex authorization check
Confidence: 0.0 (default on timeout)
Severity: Medium
Analysis Complete: NO (LLM timeout after 30s)

→ Verdict: NEEDS_REVIEW
→ Priority: 4
→ Action: "Analysis incomplete - manual investigation needed"
→ Block Deployment: NO
```

### Example 5: Probable CVE
```
Finding: Dependency with known CVE-2024-1234
Confidence: 0.75
Severity: High
Analysis Complete: Yes

→ Verdict: LIKELY_TRUE
→ Priority: 2
→ Action: "Manual validation recommended, likely true positive"
→ Block Deployment: NO (only critical + likely_true blocks)
```

## Migration from Old 3-Verdict System

### Old System (3 verdicts)
```
confirmed        → Used for anything >0.7
false_positive   → Used for anything <0.3
needs_review     → Used for 0.3-0.7 (catch-all for ambiguity)
```

### New System (6 verdicts)
```
confirmed              → 0.8-1.0 (unchanged)
likely_true            → 0.7-0.8 (NEW: probable vulnerability)
uncertain              → 0.4-0.7 (NEW: explicit ambiguity)
likely_false_positive  → 0.2-0.4 (NEW: probable FP)
false_positive         → 0.0-0.2 (unchanged)
needs_review           → N/A (NEW: analysis failed, not ambiguous)
```

### Backward Compatibility
- Old `verdict` field remains as string
- New `verdict_type` enum added
- Old code continues to work unchanged
- New code can use type-safe enums

---

## Summary Statistics (from test suite)

```
Test Coverage: 99% (29/29 tests passing)
Lines of Code: 217 (verdict_taxonomy.py)
Test Lines: 395 (test_verdict_taxonomy.py)
Integration Points: 3 (AgentAnalysis, _parse_llm_response, build_consensus)
```

## Key Insights

1. **Uncertain ≠ Needs Review**
   - `UNCERTAIN`: Analysis succeeded but confidence is middling (0.4-0.7)
   - `NEEDS_REVIEW`: Analysis failed/incomplete (timeout, error, etc.)

2. **Severity Matters**
   - Critical/high findings get conservative treatment
   - Uncertain range expands from 0.4-0.7 to 0.15-0.7
   - Avoids premature dismissal of serious vulnerabilities

3. **Priority Wins Consensus**
   - Consensus uses priority, not simple majority
   - `CONFIRMED` always wins over other verdicts
   - Prevents one false positive vote from blocking real issues

4. **Conservative Deployment Blocking**
   - Only highest confidence vulnerabilities block deployment
   - `UNCERTAIN` findings don't block (require human review)
   - Balances security with development velocity
