# Argus Security - PR Policy (Enhanced with Velocity Metrics)
# Purpose: Deterministic gates for pull requests with delivery velocity tracking
# Decision: pass/fail based on verified secrets, critical IaC, exploitable SAST
# Features: Velocity metrics, noise filtering, and auto-fix opportunities

package argus.pr

import future.keywords.if
import future.keywords.in

# Default decision (pass if no critical findings)
default decision := {
    "decision": "pass",
    "reasons": [],
    "blocks": [],
    "warnings": [],
    "velocity_metrics": {}
}

# ========================================
# CRITICAL FINDINGS (MUST BLOCK)
# ========================================

# 1. Verified Secrets (cross-validated by TruffleHog + Gitleaks)
critical_secret(f) if {
    f.category == "SECRETS"
    f.secret_verified == "true"  # MUST be verified via API
}

# 2. Critical IaC with public exposure
critical_iac(f) if {
    f.category == "IAC"
    f.severity in ["critical", "high"]
    f.service_tier == "public"  # Only block if publicly exposed
}

# 3. Exploitable SAST (trivial exploitability)
critical_sast(f) if {
    f.category == "SAST"
    f.severity == "critical"
    f.exploitability == "trivial"  # Easy to exploit
}

# 4. High CVSS with reachability
critical_deps(f) if {
    f.category == "DEPS"
    f.cvss >= 9.0  # CVSS >= 9.0
    f.reachability == "yes"  # Code is actually reachable
}

# Helper: Check if finding is critical
is_critical(f) if critical_secret(f)
is_critical(f) if critical_iac(f)
is_critical(f) if critical_sast(f)
is_critical(f) if critical_deps(f)

# Collect all blocking findings
blocking_findings := [f | f := input.findings[_]; is_critical(f)]
block_ids := [f.id | f := blocking_findings[_]]

# ========================================
# WARNING FINDINGS (DON'T BLOCK, BUT ALERT)
# ========================================

# Unverified secrets (warn but don't block)
warning_secret(f) if {
    f.category == "SECRETS"
    f.secret_verified == "false"  # Not verified
}

# Medium/High severity without reachability
warning_deps(f) if {
    f.category == "DEPS"
    f.severity in ["medium", "high"]
    f.reachability == "unknown"
}

# High severity SAST with complex exploitability
warning_sast(f) if {
    f.category == "SAST"
    f.severity == "high"
    f.exploitability in ["complex", "theoretical"]
}

is_warning(f) if warning_secret(f)
is_warning(f) if warning_deps(f)
is_warning(f) if warning_sast(f)

warning_findings := [f | f := input.findings[_]; is_warning(f)]
warning_ids := [f.id | f := warning_findings[_]]

# ========================================
# NOISE FILTERING (NEW - Phase 1)
# ========================================

# Suppress high-noise findings — never suppress critical/high severity
suppressed_findings := [f |
    f := input.findings[_]
    f.noise_score > 0.7  # High noise threshold
    not f.severity in ["critical", "high"]
]

# Suppress findings with low historical fix rate — never suppress critical/high severity
low_value_findings := [f |
    f := input.findings[_]
    f.historical_fix_rate < 0.2  # <20% fix rate
    f.noise_score > 0.5
    not f.severity in ["critical", "high"]
]

# Don't block auto-fixable findings — but NEVER auto-pass critical/high severity
auto_fixable_findings := [f |
    f := input.findings[_]
    f.auto_fixable == true
    not f.severity in ["critical", "high"]
]

# ========================================
# HARDENING: DENY AUTO-FIX FOR CRITICAL/HIGH
# ========================================

# Explicit deny: Critical/High severity MUST NEVER be bypassed by auto_fixable
# This is defense-in-depth — even if auto_fixable_findings filter is relaxed,
# these rules ensure critical/high findings always block.
deny_auto_fix_critical_high contains msg if {
    f := input.findings[_]
    f.auto_fixable == true
    f.severity in ["critical", "high"]
    msg := sprintf("DENIED: %s severity finding '%s' (id: %s) cannot be auto-fixed — manual remediation required", [f.severity, f.rule_name, f.id])
}

# Collect IDs of critical/high findings that attempted auto-fix bypass
attempted_auto_fix_bypass_ids := [f.id |
    f := input.findings[_]
    f.auto_fixable == true
    f.severity in ["critical", "high"]
]

# ========================================
# HARDENING: NOISE SCORE TRUST CAPS
# ========================================

# Cap noise_score influence: critical/high findings with noise_score > 0.9
# MUST still be reported and MUST NOT be suppressed
noise_score_override_findings := [f |
    f := input.findings[_]
    f.severity in ["critical", "high"]
    f.noise_score > 0.9
]

# Flag suspicious noise_score values that suggest manipulation
# A noise_score of exactly 1.0 on critical findings is highly suspicious
# A noise_score of exactly 0.0 on critical findings is also suspicious (may indicate tampering)
suspicious_noise_score contains msg if {
    f := input.findings[_]
    f.severity in ["critical", "high"]
    f.noise_score == 1.0
    msg := sprintf("SUSPICIOUS: Finding '%s' (id: %s, severity: %s) has noise_score=1.0 — possible manipulation to suppress critical finding", [f.rule_name, f.id, f.severity])
}

suspicious_noise_score contains msg if {
    f := input.findings[_]
    f.severity in ["critical", "high"]
    f.noise_score == 0.0
    msg := sprintf("SUSPICIOUS: Finding '%s' (id: %s, severity: %s) has noise_score=0.0 — possible manipulation to inflate severity", [f.rule_name, f.id, f.severity])
}

# Effective noise_score: cap at 0.9 for critical/high severity findings
# This ensures noise_score alone can never fully suppress important findings
effective_noise_score(f) := 0.9 if {
    f.severity in ["critical", "high"]
    f.noise_score > 0.9
}

effective_noise_score(f) := f.noise_score if {
    f.severity in ["critical", "high"]
    f.noise_score <= 0.9
}

effective_noise_score(f) := f.noise_score if {
    not f.severity in ["critical", "high"]
}

# Hardened suppressed findings: use effective_noise_score and enforce floor
hardened_suppressed_findings := [f |
    f := input.findings[_]
    effective_noise_score(f) > 0.7
    not f.severity in ["critical", "high"]
]

# ========================================
# VELOCITY METRICS (NEW - Phase 1)
# ========================================

velocity_metrics := {
    "total_findings": count(input.findings),
    "blocked_findings": count(block_ids),
    "warning_findings": count(warning_ids),
    "suppressed_noise": count(hardened_suppressed_findings),
    "auto_fixable": count(auto_fixable_findings),
    "noise_reduction_rate": noise_reduction_rate,
    "estimated_pr_delay_minutes": estimated_delay,
    "delivery_impact": delivery_impact,
    "denied_auto_fix_critical_high": count(deny_auto_fix_critical_high),
    "noise_score_overrides": count(noise_score_override_findings),
    "suspicious_noise_scores": count(suspicious_noise_score)
}

# Calculate noise reduction rate (using hardened suppression)
noise_reduction_rate := rate if {
    total := count(input.findings)
    total > 0
    suppressed := count(hardened_suppressed_findings)
    rate := (suppressed / total) * 100
} else := 0

# Estimate PR delay based on findings
estimated_delay := delay if {
    blockers := count(block_ids)
    warnings := count(warning_ids)
    # Assume: 15 min per blocker, 5 min per warning
    delay := (blockers * 15) + (warnings * 5)
} else := 0

# Delivery impact assessment
delivery_impact := "high" if count(block_ids) > 5
delivery_impact := "medium" if {
    count(block_ids) > 0
    count(block_ids) <= 5
}
delivery_impact := "low" if count(block_ids) == 0

# ========================================
# FINAL DECISION
# ========================================

# Block if any critical findings (excluding auto-fixable)
decision := result if {
    count(block_ids) > 0
    # Filter out auto-fixable from blocks
    non_fixable_blocks := [id | 
        id := block_ids[_]
        not id in [f.id | f := auto_fixable_findings[_]]
    ]
    count(non_fixable_blocks) > 0
    
    reasons_list := array.concat(
        critical_reasons,
        [sprintf("See full report for %d warnings", [count(warning_ids)])]
    )
    result := {
        "decision": "fail",
        "reasons": reasons_list,
        "blocks": non_fixable_blocks,
        "warnings": warning_ids,
        "velocity_metrics": velocity_metrics,
        "auto_fixable_count": count(auto_fixable_findings)
    }
}

# Critical reasons breakdown
critical_reasons := r if {
    secrets := [f | f := blocking_findings[_]; critical_secret(f)]
    iac := [f | f := blocking_findings[_]; critical_iac(f)]
    sast := [f | f := blocking_findings[_]; critical_sast(f)]
    deps := [f | f := blocking_findings[_]; critical_deps(f)]
    
    r := array.concat(
        array.concat(
            secret_reasons(secrets),
            iac_reasons(iac)
        ),
        array.concat(
            sast_reasons(sast),
            deps_reasons(deps)
        )
    )
}

secret_reasons(secrets) := [sprintf("🔴 %d verified secret(s) detected - MUST FIX", [count(secrets)])] if count(secrets) > 0
secret_reasons(secrets) := [] if count(secrets) == 0

iac_reasons(iac) := [sprintf("🔴 %d critical IaC misconfiguration(s) with public exposure - MUST FIX", [count(iac)])] if count(iac) > 0
iac_reasons(iac) := [] if count(iac) == 0

sast_reasons(sast) := [sprintf("🔴 %d critical SAST finding(s) with trivial exploitability - MUST FIX", [count(sast)])] if count(sast) > 0
sast_reasons(sast) := [] if count(sast) == 0

deps_reasons(deps) := [sprintf("🔴 %d critical CVE(s) with confirmed reachability - MUST FIX", [count(deps)])] if count(deps) > 0
deps_reasons(deps) := [] if count(deps) == 0

# Pass with warnings if only warnings exist
decision := result if {
    count(block_ids) == 0
    count(warning_ids) > 0
    result := {
        "decision": "pass",
        "reasons": [sprintf("✅ No blockers, but %d warning(s) found - review recommended", [count(warning_ids)])],
        "blocks": [],
        "warnings": warning_ids,
        "velocity_metrics": velocity_metrics
    }
}

# Clean pass if no findings
decision := result if {
    count(block_ids) == 0
    count(warning_ids) == 0
    result := {
        "decision": "pass",
        "reasons": ["✅ No security issues detected"],
        "blocks": [],
        "warnings": [],
        "velocity_metrics": velocity_metrics
    }
}

# Pass if all blockers are auto-fixable AND none are critical/high
# HARDENED: Explicitly check that no critical/high findings attempted auto-fix bypass
decision := result if {
    count(block_ids) > 0
    count(attempted_auto_fix_bypass_ids) == 0  # No critical/high attempted auto-fix
    non_fixable_blocks := [id |
        id := block_ids[_]
        not id in [f.id | f := auto_fixable_findings[_]]
    ]
    count(non_fixable_blocks) == 0  # All blockers are auto-fixable (and none are critical/high)

    result := {
        "decision": "pass",
        "reasons": [sprintf("✅ %d finding(s) will be auto-fixed - no manual action needed", [count(auto_fixable_findings)])],
        "blocks": [],
        "warnings": warning_ids,
        "velocity_metrics": velocity_metrics,
        "auto_fixable_count": count(auto_fixable_findings)
    }
}

# HARDENED: Block if critical/high findings attempted auto-fix bypass
decision := result if {
    count(block_ids) > 0
    count(attempted_auto_fix_bypass_ids) > 0  # Critical/high attempted auto-fix bypass

    bypass_reasons := [msg | msg := deny_auto_fix_critical_high[_]]
    reasons_list := array.concat(
        critical_reasons,
        array.concat(
            bypass_reasons,
            [sprintf("See full report for %d warnings", [count(warning_ids)])]
        )
    )
    result := {
        "decision": "fail",
        "reasons": reasons_list,
        "blocks": block_ids,
        "warnings": warning_ids,
        "velocity_metrics": velocity_metrics,
        "denied_auto_fix_bypass": attempted_auto_fix_bypass_ids
    }
}

