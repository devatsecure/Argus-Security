# Argus Security - PR Policy Hardening Tests
# Tests for auto_fixable bypass prevention and noise_score trust caps
# Run with: opa test policy/rego/ -v

package argus.pr

import future.keywords.if
import future.keywords.in

# ========================================
# TEST: Critical + auto_fixable is DENIED
# ========================================

# Critical SAST finding with auto_fixable=true must still be denied
test_critical_auto_fixable_still_blocked if {
    result := deny_auto_fix_critical_high with input as {
        "findings": [{
            "id": "SAST-001",
            "category": "SAST",
            "severity": "critical",
            "exploitability": "trivial",
            "auto_fixable": true,
            "rule_name": "sql-injection",
            "noise_score": 0.1
        }]
    }
    count(result) > 0
}

# High severity IaC finding with auto_fixable=true must still be denied
test_high_auto_fixable_still_blocked if {
    result := deny_auto_fix_critical_high with input as {
        "findings": [{
            "id": "IAC-001",
            "category": "IAC",
            "severity": "high",
            "service_tier": "public",
            "auto_fixable": true,
            "rule_name": "public-s3-bucket",
            "noise_score": 0.2
        }]
    }
    count(result) > 0
}

# Medium severity with auto_fixable=true should NOT be denied
test_medium_auto_fixable_not_denied if {
    result := deny_auto_fix_critical_high with input as {
        "findings": [{
            "id": "SAST-002",
            "category": "SAST",
            "severity": "medium",
            "exploitability": "complex",
            "auto_fixable": true,
            "rule_name": "missing-csrf",
            "noise_score": 0.3
        }]
    }
    count(result) == 0
}

# Low severity with auto_fixable=true should NOT be denied
test_low_auto_fixable_not_denied if {
    result := deny_auto_fix_critical_high with input as {
        "findings": [{
            "id": "SAST-003",
            "category": "SAST",
            "severity": "low",
            "exploitability": "theoretical",
            "auto_fixable": true,
            "rule_name": "code-smell",
            "noise_score": 0.1
        }]
    }
    count(result) == 0
}

# Critical finding without auto_fixable should NOT trigger deny_auto_fix
test_critical_no_auto_fixable_not_denied if {
    result := deny_auto_fix_critical_high with input as {
        "findings": [{
            "id": "SAST-004",
            "category": "SAST",
            "severity": "critical",
            "exploitability": "trivial",
            "auto_fixable": false,
            "rule_name": "rce-vulnerability",
            "noise_score": 0.1
        }]
    }
    count(result) == 0
}

# ========================================
# TEST: Attempted auto-fix bypass IDs collected
# ========================================

test_attempted_bypass_ids_collected if {
    result := attempted_auto_fix_bypass_ids with input as {
        "findings": [
            {
                "id": "CRIT-001",
                "category": "SAST",
                "severity": "critical",
                "exploitability": "trivial",
                "auto_fixable": true,
                "rule_name": "sqli",
                "noise_score": 0.1
            },
            {
                "id": "MED-001",
                "category": "SAST",
                "severity": "medium",
                "exploitability": "complex",
                "auto_fixable": true,
                "rule_name": "xss",
                "noise_score": 0.3
            }
        ]
    }
    count(result) == 1
    result[0] == "CRIT-001"
}

# ========================================
# TEST: noise_score caps for critical/high
# ========================================

# High severity with noise_score=0.99 must still be reported (not suppressed)
test_high_noise_score_critical_not_suppressed if {
    result := noise_score_override_findings with input as {
        "findings": [{
            "id": "SAST-010",
            "category": "SAST",
            "severity": "critical",
            "exploitability": "trivial",
            "noise_score": 0.99,
            "auto_fixable": false,
            "rule_name": "rce"
        }]
    }
    count(result) == 1
}

# High severity with noise_score=0.95 must still be reported
test_high_severity_high_noise_not_suppressed if {
    result := noise_score_override_findings with input as {
        "findings": [{
            "id": "DEPS-010",
            "category": "DEPS",
            "severity": "high",
            "noise_score": 0.95,
            "auto_fixable": false,
            "rule_name": "critical-cve"
        }]
    }
    count(result) == 1
}

# Medium severity with noise_score=0.99 should NOT be in override list
test_medium_noise_score_not_overridden if {
    result := noise_score_override_findings with input as {
        "findings": [{
            "id": "SAST-011",
            "category": "SAST",
            "severity": "medium",
            "noise_score": 0.99,
            "auto_fixable": false,
            "rule_name": "info-disclosure"
        }]
    }
    count(result) == 0
}

# ========================================
# TEST: Suspicious noise_score detection
# ========================================

# noise_score=1.0 on critical finding is suspicious
test_suspicious_noise_score_1_0 if {
    result := suspicious_noise_score with input as {
        "findings": [{
            "id": "SAST-020",
            "category": "SAST",
            "severity": "critical",
            "noise_score": 1.0,
            "auto_fixable": false,
            "rule_name": "injection",
            "exploitability": "trivial"
        }]
    }
    count(result) > 0
}

# noise_score=0.0 on critical finding is suspicious
test_suspicious_noise_score_0_0 if {
    result := suspicious_noise_score with input as {
        "findings": [{
            "id": "SAST-021",
            "category": "SAST",
            "severity": "critical",
            "noise_score": 0.0,
            "auto_fixable": false,
            "rule_name": "injection",
            "exploitability": "trivial"
        }]
    }
    count(result) > 0
}

# noise_score=0.5 on critical finding is NOT suspicious
test_normal_noise_score_not_suspicious if {
    result := suspicious_noise_score with input as {
        "findings": [{
            "id": "SAST-022",
            "category": "SAST",
            "severity": "critical",
            "noise_score": 0.5,
            "auto_fixable": false,
            "rule_name": "injection",
            "exploitability": "trivial"
        }]
    }
    count(result) == 0
}

# noise_score=1.0 on LOW severity is NOT suspicious (only critical/high)
test_low_severity_noise_1_0_not_suspicious if {
    result := suspicious_noise_score with input as {
        "findings": [{
            "id": "SAST-023",
            "category": "SAST",
            "severity": "low",
            "noise_score": 1.0,
            "auto_fixable": false,
            "rule_name": "code-smell",
            "exploitability": "theoretical"
        }]
    }
    count(result) == 0
}

# ========================================
# TEST: Effective noise_score capping
# ========================================

# Critical finding with noise_score=0.99 is capped to 0.9
test_effective_noise_score_capped_critical if {
    effective_noise_score({"severity": "critical", "noise_score": 0.99}) == 0.9
}

# High finding with noise_score=0.95 is capped to 0.9
test_effective_noise_score_capped_high if {
    effective_noise_score({"severity": "high", "noise_score": 0.95}) == 0.9
}

# Critical finding with noise_score=0.8 is NOT capped
test_effective_noise_score_not_capped_critical if {
    effective_noise_score({"severity": "critical", "noise_score": 0.8}) == 0.8
}

# Medium finding with noise_score=0.99 is NOT capped
test_effective_noise_score_not_capped_medium if {
    effective_noise_score({"severity": "medium", "noise_score": 0.99}) == 0.99
}

# ========================================
# TEST: Hardened suppressed findings
# ========================================

# Critical finding with high noise_score must NOT be in hardened_suppressed_findings
test_critical_not_in_hardened_suppressed if {
    result := hardened_suppressed_findings with input as {
        "findings": [{
            "id": "SAST-030",
            "category": "SAST",
            "severity": "critical",
            "noise_score": 0.99,
            "auto_fixable": false,
            "rule_name": "rce",
            "exploitability": "trivial"
        }]
    }
    count(result) == 0
}

# Medium finding with high noise_score CAN be in hardened_suppressed_findings
test_medium_in_hardened_suppressed if {
    result := hardened_suppressed_findings with input as {
        "findings": [{
            "id": "SAST-031",
            "category": "SAST",
            "severity": "medium",
            "noise_score": 0.8,
            "auto_fixable": false,
            "rule_name": "info-disclosure",
            "exploitability": "complex"
        }]
    }
    count(result) == 1
}
