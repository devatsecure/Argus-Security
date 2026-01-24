# Argus Security - Release Policy
# Purpose: Deterministic gates for releases
# Decision: pass/fail based on SBOM, signing, and critical CVEs

package argus.release

import future.keywords.if
import future.keywords.in

# Default decision
default decision := {
    "decision": "pass",
    "reasons": [],
    "blocks": []
}

# ========================================
# RELEASE REQUIREMENTS
# ========================================

# 1. SBOM must be present
sbom_missing if {
    not input.sbom_present
}

# 2. Signature must be verified
signature_invalid if {
    not input.signature_verified
}

# 3. SLSA provenance must be present (optional but recommended)
provenance_missing if {
    not input.provenance_present
}

# ========================================
# CRITICAL FINDINGS (BLOCK RELEASE)
# ========================================

# Critical CVE with reachability
critical_cve(f) if {
    f.category == "DEPS"
    f.cvss >= 9.0  # Critical CVSS
    f.reachability == "yes"  # Confirmed reachable
}

# Verified secrets (should never reach release, but double-check)
critical_secret(f) if {
    f.category == "SECRETS"
    f.secret_verified == "true"
}

# Critical SAST with trivial exploitability
critical_sast(f) if {
    f.category == "SAST"
    f.severity == "critical"
    f.exploitability == "trivial"
}

is_critical(f) if critical_cve(f)
is_critical(f) if critical_secret(f)
is_critical(f) if critical_sast(f)

blocking_findings := [f | f := input.findings[_]; is_critical(f)]
block_ids := [f.id | f := blocking_findings[_]]

# ========================================
# FINAL DECISION
# ========================================

# Block if SBOM missing
decision := result if {
    sbom_missing
    result := {
        "decision": "fail",
        "reasons": [
            "🔴 SBOM missing - required for release",
            "💡 Generate SBOM: syft packages . -o cyclonedx-json > sbom.json"
        ],
        "blocks": []
    }
}

# Block if signature invalid
decision := result if {
    not sbom_missing
    signature_invalid
    result := {
        "decision": "fail",
        "reasons": [
            "🔴 Signature verification failed",
            "💡 Sign release: cosign sign-blob --key env://COSIGN_PRIVATE_KEY sbom.json"
        ],
        "blocks": []
    }
}

# Block if critical findings exist
decision := result if {
    not sbom_missing
    not signature_invalid
    count(block_ids) > 0
    
    cves := [f | f := blocking_findings[_]; critical_cve(f)]
    secrets := [f | f := blocking_findings[_]; critical_secret(f)]
    sast := [f | f := blocking_findings[_]; critical_sast(f)]
    
    result := {
        "decision": "fail",
        "reasons": array.concat(
            array.concat(
                cve_reasons(cves),
                secret_reasons(secrets)
            ),
            sast_reasons(sast)
        ),
        "blocks": block_ids
    }
}

cve_reasons(cves) := [sprintf("🔴 %d critical CVE(s) with confirmed reachability", [count(cves)])] if count(cves) > 0
cve_reasons(cves) := [] if count(cves) == 0

secret_reasons(secrets) := [sprintf("🔴 %d verified secret(s) in release - CRITICAL", [count(secrets)])] if count(secrets) > 0
secret_reasons(secrets) := [] if count(secrets) == 0

sast_reasons(sast) := [sprintf("🔴 %d critical SAST finding(s) with trivial exploitability", [count(sast)])] if count(sast) > 0
sast_reasons(sast) := [] if count(sast) == 0

# Warn if provenance missing
decision := result if {
    not sbom_missing
    not signature_invalid
    count(block_ids) == 0
    provenance_missing
    result := {
        "decision": "pass",
        "reasons": [
            "✅ SBOM and signature verified",
            "⚠️  SLSA provenance missing - recommended for supply chain security"
        ],
        "blocks": []
    }
}

# Clean pass
decision := result if {
    not sbom_missing
    not signature_invalid
    count(block_ids) == 0
    not provenance_missing
    result := {
        "decision": "pass",
        "reasons": [
            "✅ SBOM present and verified",
            "✅ Signature verified",
            "✅ SLSA provenance present",
            "✅ No critical security findings"
        ],
        "blocks": []
    }
}

