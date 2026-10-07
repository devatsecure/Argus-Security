# Public adoption evidence

Last verified: **2026-10-07**.

This inventory records public evidence of repositories integrating
[devatsecure/Argus-Security](https://github.com/devatsecure/Argus-Security).
It distinguishes a configured dependency, an observed execution, and a completed
scan. Entries are not endorsements or claims of production deployment.

## Verified public integration

**One public repository was verified invoking the upstream Argus Action.** Its
inspected runs include a failed AI review and a workflow marked successful with
degraded scanning. No complete, healthy AI pipeline execution was verified in
this review. This is an evidence inventory, not a complete count of Argus users.

| Repository | Integration evidence | Observed status |
| --- | --- | --- |
| [abdaalwhab04-lab/Argus-Security](https://github.com/abdaalwhab04-lab/Argus-Security) | [Example scan workflow](https://github.com/abdaalwhab04-lab/Argus-Security/blob/e5e83d1efd339f0cbaf3627e394cc6d3cec41c52/.github/workflows/argus-security-example.yml#L19-L24) and [full pipeline workflow](https://github.com/abdaalwhab04-lab/Argus-Security/blob/e5e83d1efd339f0cbaf3627e394cc6d3cec41c52/.github/workflows/full-pipeline.yml#L144-L150) pin `devatsecure/Argus-Security@7a6b42c8ab79016743c5115c0f360720ebaeb05b`. | Upstream Action download and execution verified in public logs. Successful operation is qualified by the run details below. |

The downstream repository is another Argus-Security codebase. These workflows
demonstrate reuse of the upstream Action; they do not establish an independent
production deployment or a customer count. Multiple workflows in this repository
count as one repository.

## Inspected runs

| Run | GitHub conclusion | What the logs establish |
| --- | --- | --- |
| [Example scans, 2026-10-06](https://github.com/abdaalwhab04-lab/Argus-Security/actions/runs/37391624002) | Failure | Basic, conservative, and semantic analysis jobs downloaded the pinned upstream Action, then reported `No AI provider configured` and `No AI provider available`, exiting with code 2. The full-analysis job was skipped. |
| [Full pipeline, 2026-08-16](https://github.com/abdaalwhab04-lab/Argus-Security/actions/runs/31968399099) | Success | Argus executed and some scanners, including Checkov, produced results. AI enrichment was unavailable, Trivy installation failed, Semgrep failed, and TruffleHog/Gitleaks were unavailable. SARIF upload reported that no SARIF files were found. This is evidence of execution with degraded coverage, not a verified complete pipeline. |

The successful GitHub conclusion above must not be presented as proof that every
scanner, AI stage, or report upload worked.

### Failed integration: finding and next verification

The example workflow supplies `anthropic-api-key` from
`${{ secrets.ANTHROPIC_API_KEY }}`. In the inspected run, no usable AI provider
configuration reached the fast review process. The upstream
[provider detection](https://github.com/devatsecure/Argus-Security/blob/7a6b42c8ab79016743c5115c0f360720ebaeb05b/scripts/run_ai_audit.py#L147-L175)
and [initialization](https://github.com/devatsecure/Argus-Security/blob/7a6b42c8ab79016743c5115c0f360720ebaeb05b/scripts/run_ai_audit.py#L947-L961)
match the logged failure and exit code. The public evidence does not establish
whether the secret was absent or unavailable to that run.

Before marking this integration as working, the downstream maintainer needs to
configure an available AI provider through the supported Action inputs, rerun the
workflow, and verify that the intended analysis completes and produces its report.
For full-pipeline verification, also confirm that the intended scanners execute
and the expected report is produced; a green workflow conclusion alone is not
sufficient.

## Examples and other references excluded from adopter counts

- [PayFlow Technologies](case-studies/example-fintech-startup.md) and
  [AsyncDB Project](case-studies/example-open-source.md) are explicitly fictional
  case studies. Their organizations, outcomes, and metrics are illustrative.
- Projects in the README's [Audited Projects](README.md#audited-projects) section
  are scan targets. A report submitted to a project's issue tracker does not by
  itself show that the project adopted Argus.
- Forks, copied documentation, and directory listings do not establish working
  integrations without additional execution evidence.
- [CivicActions/keychain-cli's Argus workflow](https://github.com/CivicActions/keychain-cli/blob/3de90f80704430dd435ef500864884d4681aed9a/.github/workflows/argus.yml)
  uses `huntridge-labs/argus` and its `argus-security` PyPI package. It is a different
  project and is excluded from this inventory.

## Scope and updates

The review searched public GitHub code references to
`devatsecure/Argus-Security`, `devatsecure/argus-action`, and
`argus-code-reviewer`, inspected relevant workflow definitions and available run
logs, and checked public fork activity. Private or unindexed usage and expired
run logs may not be discoverable. No private integration is included here.

To add or update an entry, open a pull request with:

1. The repository URL and a link to the workflow or dependency declaration,
   preferably pinned to a commit.
2. A public run URL and date, with confirmation that the Argus step executed.
3. The observed result, including skipped stages, missing scanners, or report
   failures. Label configuration-only evidence as unverified execution.
4. A clear distinction between adopting Argus and being scanned by someone else.

See [case studies](case-studies/README.md) for fictional examples and the template
for submitting a real, evidence-backed case study.
