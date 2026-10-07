# Argus maturity: trustworthy scan outcomes and installable releases

The user requested an overall review, comparison with leading open-source peers,
a maturation plan, implementation, and a push to main. This release focuses on
correctness at the scanner → policy → report → CI boundary and the distribution
boundary. Preserve existing scanner integrations and source-checkout commands.

## Design

1. Scanner failure must never become a successful empty scan. Preserve requested
   scanners through initialization, propagate runner exceptions to the phase
   coordinator, and distinguish disabled, unavailable, failed, and successful
   scanners. Reject error-bearing scanner responses.
2. Persist scanner health, scan completeness, policy decisions, and attack chains
   as actual result fields before writing reports. JSON, Markdown, and SARIF must
   expose incomplete execution. Severity filtering must not bypass enforcement.
3. Evaluate policy even with no findings. Convert findings to the Rego input
   vocabulary, preserve verified-secret evidence, and return an explicit error
   decision when policy evaluation is unavailable or invalid. CLI exits: 0 for a
   completed passing scan, 1 for policy/high-or-critical finding failures, 2 for
   incomplete execution or policy errors. Continue producing reports on errors.
4. Build a wheel containing executable code and built-in policy/config/rules.
   Support `argus-scan`, `argus-audit`, and `argus-gate` from outside the checkout.
   Keep legacy internal imports behind a small compatibility entry point; defer
   a disruptive repository-wide import rewrite.
5. Add an offline regression workflow for these contracts and an installed-wheel
   smoke check. Do not silence the existing broad lint/test backlog.

## Constraints and acceptance

- Python >=3.10; no paid LLM calls or live-target scanning needed for validation.
- No force push, rule changes, release publication, or unrelated repository edits.
- Add regression tests that fail before the fixes; run the broad suite and record
  unrelated failures explicitly.
- Report comparison is capability-based, sourced to primary repositories/docs,
  and does not claim comparative detection accuracy without measurements.
- Full scanner/parser consistency, persistent-store integration, benchmark
  calibration, sandbox hardening, and CI consolidation remain explicit roadmap
  work, not claims that this release has completed them.

## Alternatives considered

More scanners and AI personas increase breadth but leave false-success behavior
unchanged. A full package/architecture rewrite could unify every interface but
would make regressions harder to attribute. Targeted boundary fixes deliver a
reviewable improvement while retaining the existing architecture.
