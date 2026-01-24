# Argus Platform Integration Guide

Complete guide for integrating Argus with GitHub, GitLab, and Bitbucket with all security features.

**Version:** 4.0.0
**Last Updated:** 2026-01-15

---

## 📊 Quick Comparison

| Feature | GitHub Actions | GitLab CI/CD | Bitbucket Pipelines |
|---------|---------------|--------------|---------------------|
| **Native Support** | ✅ Yes (action.yml) | ✅ Yes (Docker) | ✅ Yes (Docker) |
| **PR Comments** | ✅ Yes | ✅ Yes (Merge Request) | ✅ Yes (Pull Request) |
| **SARIF Upload** | ✅ Yes (Security tab) | ✅ Yes (Security Dashboard) | ⚠️ Limited |
| **Artifact Upload** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Secret Management** | ✅ Repository Secrets | ✅ CI/CD Variables | ✅ Repository Variables |
| **Matrix Builds** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Caching** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Self-Hosted Runners** | ✅ Yes | ✅ Yes | ✅ Yes |

---

## 🎯 Platform-Specific Guides

- [GitHub Actions Integration](#github-actions-integration)
- [GitLab CI/CD Integration](#gitlab-cicd-integration)
- [Bitbucket Pipelines Integration](#bitbucket-pipelines-integration)

---

# GitHub Actions Integration

## 🚀 Quick Start

### Basic Security Scan

```yaml
# .github/workflows/security-scan.yml
name: Argus Security Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly scan

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for better analysis

      - name: Argus Security Scan
        uses: devatsecure/Argus-Security@v4.0.0
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          review-type: security
          fail-on-blockers: true
          comment-on-pr: true
```

## 🔥 Complete Integration (All Features)

```yaml
# .github/workflows/comprehensive-security.yml
name: Comprehensive Security Platform

on:
  pull_request:
  push:
    branches: [main, develop]
  workflow_dispatch:
    inputs:
      scan-type:
        description: 'Scan type'
        required: false
        default: 'full'
        type: choice
        options:
          - full
          - quick
          - custom

jobs:
  # Job 1: Complete Security Scan with All Features
  full-security-scan:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    permissions:
      contents: read
      security-events: write
      pull-requests: write
      actions: read

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Argus Complete Security Platform
        uses: devatsecure/Argus-Security@v4.0.0
        with:
          # Core Configuration
          review-type: security
          project-type: auto
          fail-on-blockers: true

          # AI Configuration
          ai-provider: anthropic
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          model: claude-sonnet-4

          # Multi-Scanner Configuration
          semgrep-enabled: true
          enable-trufflehog: true
          enable-gitleaks: true
          enable-trivy: true
          enable-checkov: true

          # New Security Features (v4.0.0)
          enable-api-security: true
          enable-dast: false  # Requires running app
          enable-supply-chain: true
          enable-fuzzing: false  # Expensive
          enable-threat-intel: true
          enable-remediation: true
          enable-runtime-security: false  # Production only
          enable-regression-testing: true

          # Exploit Analysis
          enable-exploit-analysis: true
          generate-security-tests: true
          exploitability-threshold: moderate

          # Output Configuration
          comment-on-pr: true
          upload-reports: true
          sarif-output: true

          # Performance Optimization
          only-changed: ${{ github.event_name == 'pull_request' }}
          max-files: 500
          max-file-size: 100000

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security-results.sarif
          category: argus-security

      - name: Upload Security Reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: |
            security-report.md
            security-results.json
            security-results.sarif
          retention-days: 90

  # Job 2: API Security Testing
  api-security:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'

    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Argus
        run: |
          git clone https://github.com/devatsecure/Argus-Security
          cd argus-action
          pip install -r requirements.txt

      - name: API Security Scan
        run: |
          cd argus-action
          ./scripts/argus api-security --path ${{ github.workspace }} \
            --output api-findings.json

      - name: Upload API Findings
        uses: actions/upload-artifact@v4
        with:
          name: api-security-findings
          path: argus-action/api-findings.json

  # Job 3: Supply Chain Security
  supply-chain:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Argus
        run: |
          git clone https://github.com/devatsecure/Argus-Security
          cd argus-action
          pip install -r requirements.txt

      - name: Supply Chain Analysis
        run: |
          cd argus-action

          # Check for typosquatting and malicious packages
          if [ "${{ github.event_name }}" == "pull_request" ]; then
            ./scripts/argus supply-chain diff \
              --base origin/${{ github.base_ref }} \
              --head HEAD \
              --output supply-chain-diff.json
          fi

          # Check all dependencies
          ./scripts/argus supply-chain scan \
            --path ${{ github.workspace }} \
            --output supply-chain-scan.json

      - name: Upload Supply Chain Report
        uses: actions/upload-artifact@v4
        with:
          name: supply-chain-report
          path: argus-action/*.json

  # Job 4: Threat Intelligence Enrichment
  threat-intel:
    runs-on: ubuntu-latest
    needs: [full-security-scan]

    steps:
      - uses: actions/checkout@v4

      - name: Download Security Findings
        uses: actions/download-artifact@v4
        with:
          name: security-reports

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Argus
        run: |
          git clone https://github.com/devatsecure/Argus-Security
          cd argus-action
          pip install -r requirements.txt

      - name: Enrich with Threat Intelligence
        run: |
          cd argus-action
          ./scripts/argus threat-intel enrich \
            --findings ../security-results.json \
            --output threat-intel-enriched.json

      - name: Upload Enriched Findings
        uses: actions/upload-artifact@v4
        with:
          name: threat-intel-report
          path: argus-action/threat-intel-enriched.json

  # Job 5: Auto-Remediation (Create Fix PR)
  auto-remediate:
    runs-on: ubuntu-latest
    needs: [full-security-scan]
    if: github.event_name == 'pull_request' && !cancelled()

    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Download Security Findings
        uses: actions/download-artifact@v4
        with:
          name: security-reports

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Argus
        run: |
          git clone https://github.com/devatsecure/Argus-Security
          cd argus-action
          pip install -r requirements.txt

      - name: Generate Remediation Fixes
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          cd argus-action
          ./scripts/argus remediate \
            --findings ../security-results.json \
            --output remediation-fixes.md \
            --auto-apply false

      - name: Comment Fixes on PR
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const fixes = fs.readFileSync('argus-action/remediation-fixes.md', 'utf8');

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## 🔧 Auto-Generated Security Fixes\n\n${fixes}`
            });

  # Job 6: Security Regression Testing
  regression-tests:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Argus
        run: |
          git clone https://github.com/devatsecure/Argus-Security
          cd argus-action
          pip install -r requirements.txt

      - name: Run Security Regression Tests
        run: |
          cd argus-action
          ./scripts/argus regression-test run \
            --path ${{ github.workspace }} \
            --output regression-results.json

      - name: Upload Regression Results
        uses: actions/upload-artifact@v4
        with:
          name: regression-test-results
          path: argus-action/regression-results.json
```

## 🎯 GitHub-Specific Features

### 1. Security Tab Integration (SARIF)

```yaml
- name: Upload to Security Tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: security-results.sarif
    category: argus-comprehensive
    checkout_path: ${{ github.workspace }}
```

### 2. PR Comments with Rich Formatting

```yaml
- name: Post Security Summary to PR
  uses: actions/github-script@v7
  if: github.event_name == 'pull_request'
  with:
    script: |
      const fs = require('fs');
      const report = fs.readFileSync('security-report.md', 'utf8');

      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: report
      });
```

### 3. Matrix Strategy for Multiple Projects

```yaml
strategy:
  matrix:
    project-type: [backend-api, frontend-ui, infrastructure]
    ai-provider: [anthropic, openai]
  fail-fast: false

steps:
  - uses: devatsecure/Argus-Security@v4.0.0
    with:
      project-type: ${{ matrix.project-type }}
      ai-provider: ${{ matrix.ai-provider }}
```

---

# GitLab CI/CD Integration

## 🚀 Quick Start

### Basic Security Scan

```yaml
# .gitlab-ci.yml
stages:
  - security

argus-security:
  stage: security
  image: python:3.11
  before_script:
    - git clone https://github.com/devatsecure/Argus-Security
    - cd argus-action
    - pip install -r requirements.txt
  script:
    - |
      python scripts/run_ai_audit.py \
        --project-type auto \
        --ai-provider anthropic \
        --output-file ../security-results.json \
        --sarif-output ../security-results.sarif
  artifacts:
    reports:
      sast: security-results.sarif
    paths:
      - security-results.json
      - security-report.md
    expire_in: 30 days
  variables:
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
```

## 🔥 Complete Integration (All Features)

```yaml
# .gitlab-ci.yml
variables:
  ARGUS_VERSION: "v4.0.0"
  PYTHON_VERSION: "3.11"

stages:
  - setup
  - scan
  - analyze
  - remediate
  - test
  - report

# Cache dependencies
.cache_template: &cache_template
  cache:
    key: argus-${CI_COMMIT_REF_SLUG}
    paths:
      - argus-action/
      - .argus-cache/

# Install Argus once
setup:argus:
  stage: setup
  image: python:${PYTHON_VERSION}
  <<: *cache_template
  script:
    - git clone --branch ${ARGUS_VERSION} https://github.com/devatsecure/Argus-Security
    - cd argus-action
    - pip install -r requirements.txt
  artifacts:
    paths:
      - argus-action/
    expire_in: 1 hour

# Job 1: Complete Security Scan
security:comprehensive-scan:
  stage: scan
  image: python:${PYTHON_VERSION}
  <<: *cache_template
  dependencies:
    - setup:argus
  before_script:
    - cd argus-action
  script:
    - |
      python scripts/run_ai_audit.py \
        --project-path ${CI_PROJECT_DIR} \
        --project-type auto \
        --ai-provider anthropic \
        --semgrep-enabled true \
        --enable-trufflehog true \
        --enable-gitleaks true \
        --enable-trivy true \
        --enable-checkov true \
        --enable-api-security true \
        --enable-supply-chain true \
        --enable-threat-intel true \
        --enable-remediation true \
        --enable-regression-testing true \
        --enable-exploit-analysis true \
        --generate-security-tests true \
        --output-file ../security-results.json \
        --sarif-output ../security-results.sarif \
        --markdown-output ../security-report.md
  artifacts:
    reports:
      sast: security-results.sarif
      dependency_scanning: security-results.json
    paths:
      - security-results.json
      - security-report.md
      - security-results.sarif
    expire_in: 90 days
  variables:
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
  only:
    - merge_requests
    - main
    - develop

# Job 2: API Security Testing
security:api-security:
  stage: scan
  image: python:${PYTHON_VERSION}
  <<: *cache_template
  dependencies:
    - setup:argus
  script:
    - cd argus-action
    - |
      ./scripts/argus api-security \
        --path ${CI_PROJECT_DIR} \
        --output api-findings.json
  artifacts:
    paths:
      - argus-action/api-findings.json
    expire_in: 30 days
  only:
    - merge_requests

# Job 3: Supply Chain Security
security:supply-chain:
  stage: scan
  image: python:${PYTHON_VERSION}
  <<: *cache_template
  dependencies:
    - setup:argus
  script:
    - cd argus-action
    - |
      # Diff mode for MRs
      if [ "$CI_PIPELINE_SOURCE" = "merge_request_event" ]; then
        ./scripts/argus supply-chain diff \
          --base origin/${CI_MERGE_REQUEST_TARGET_BRANCH_NAME} \
          --head HEAD \
          --output supply-chain-diff.json
      fi

      # Full scan
      ./scripts/argus supply-chain scan \
        --path ${CI_PROJECT_DIR} \
        --output supply-chain-scan.json
  artifacts:
    paths:
      - argus-action/supply-chain-*.json
    expire_in: 30 days

# Job 4: DAST Scanning (requires running app)
security:dast:
  stage: scan
  image: python:${PYTHON_VERSION}
  <<: *cache_template
  dependencies:
    - setup:argus
  services:
    - name: ${CI_REGISTRY_IMAGE}:${CI_COMMIT_REF_SLUG}
      alias: app
  script:
    - cd argus-action
    - |
      # Wait for app to be ready
      sleep 10

      # Run DAST scan
      ./scripts/argus dast \
        --target http://app:8080 \
        --openapi ${CI_PROJECT_DIR}/openapi.yaml \
        --output dast-findings.json
  artifacts:
    paths:
      - argus-action/dast-findings.json
    expire_in: 30 days
  only:
    - merge_requests
  when: manual

# Job 5: Threat Intelligence Enrichment
analyze:threat-intel:
  stage: analyze
  image: python:${PYTHON_VERSION}
  <<: *cache_template
  dependencies:
    - setup:argus
    - security:comprehensive-scan
  script:
    - cd argus-action
    - |
      ./scripts/argus threat-intel enrich \
        --findings ../security-results.json \
        --output threat-intel-enriched.json
  artifacts:
    paths:
      - argus-action/threat-intel-enriched.json
    expire_in: 30 days

# Job 6: SAST-DAST Correlation
analyze:correlate:
  stage: analyze
  image: python:${PYTHON_VERSION}
  <<: *cache_template
  dependencies:
    - setup:argus
    - security:comprehensive-scan
    - security:dast
  script:
    - cd argus-action
    - |
      ./scripts/argus correlate \
        --sast ../security-results.json \
        --dast dast-findings.json \
        --output correlated-findings.json
  artifacts:
    paths:
      - argus-action/correlated-findings.json
    expire_in: 30 days
  only:
    - merge_requests
  when: manual

# Job 7: Auto-Remediation
remediate:generate-fixes:
  stage: remediate
  image: python:${PYTHON_VERSION}
  <<: *cache_template
  dependencies:
    - setup:argus
    - security:comprehensive-scan
  script:
    - cd argus-action
    - |
      ./scripts/argus remediate \
        --findings ../security-results.json \
        --output remediation-fixes.md \
        --auto-apply false
  artifacts:
    paths:
      - argus-action/remediation-fixes.md
    expire_in: 30 days
  variables:
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
  only:
    - merge_requests

# Job 8: Security Regression Tests
test:regression:
  stage: test
  image: python:${PYTHON_VERSION}
  <<: *cache_template
  dependencies:
    - setup:argus
  script:
    - cd argus-action
    - |
      ./scripts/argus regression-test run \
        --path ${CI_PROJECT_DIR} \
        --output regression-results.json
  artifacts:
    reports:
      junit: argus-action/regression-results.xml
    paths:
      - argus-action/regression-results.json
    expire_in: 30 days

# Job 9: Generate Security Dashboard
report:dashboard:
  stage: report
  image: python:${PYTHON_VERSION}
  <<: *cache_template
  dependencies:
    - setup:argus
    - security:comprehensive-scan
    - analyze:threat-intel
  script:
    - cd argus-action
    - |
      ./scripts/argus dashboard generate \
        --findings ../security-results.json \
        --threat-intel threat-intel-enriched.json \
        --output security-dashboard.html
  artifacts:
    paths:
      - argus-action/security-dashboard.html
    expire_in: 90 days
  when: always

# Job 10: MR Comment
report:mr-comment:
  stage: report
  image: python:${PYTHON_VERSION}
  dependencies:
    - security:comprehensive-scan
  script:
    - |
      # Post to MR using GitLab API
      curl --request POST \
        --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
        --header "Content-Type: application/json" \
        --data "{\"body\": \"$(cat security-report.md | jq -Rs .)\"}" \
        "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/merge_requests/${CI_MERGE_REQUEST_IID}/notes"
  only:
    - merge_requests
  when: always
```

## 🎯 GitLab-Specific Features

### 1. Security Dashboard Integration

```yaml
artifacts:
  reports:
    sast: security-results.sarif
    dependency_scanning: security-results.json
    container_scanning: trivy-results.json
```

### 2. Merge Request Approval Rules

```yaml
# .gitlab-ci.yml
security:policy-gate:
  stage: report
  script:
    - cd argus-action
    - |
      EXIT_CODE=$(./scripts/argus gate --stage mr --input ../security-results.json)
      if [ $EXIT_CODE -ne 0 ]; then
        echo "Security gate failed - blocking MR"
        exit 1
      fi
  only:
    - merge_requests
```

### 3. Scheduled Pipelines

```yaml
security:weekly-scan:
  stage: scan
  script:
    - # Full comprehensive scan
  only:
    - schedules
```

---

# Bitbucket Pipelines Integration

## 🚀 Quick Start

### Basic Security Scan

```yaml
# bitbucket-pipelines.yml
image: python:3.11

definitions:
  caches:
    argus: argus-action

pipelines:
  default:
    - step:
        name: Argus Security Scan
        caches:
          - argus
          - pip
        script:
          - git clone https://github.com/devatsecure/Argus-Security
          - cd argus-action
          - pip install -r requirements.txt
          - |
            python scripts/run_ai_audit.py \
              --project-type auto \
              --ai-provider anthropic \
              --output-file ../security-results.json \
              --markdown-output ../security-report.md
        artifacts:
          - security-results.json
          - security-report.md
```

## 🔥 Complete Integration (All Features)

```yaml
# bitbucket-pipelines.yml
image: python:3.11

definitions:
  caches:
    argus: argus-action
    agent-cache: .argus-cache

  services:
    docker:
      memory: 2048

pipelines:
  # Pull Request Pipeline
  pull-requests:
    '**':
      - parallel:
          - step:
              name: Comprehensive Security Scan
              size: 2x
              caches:
                - argus
                - agent-cache
                - pip
              script:
                - git clone https://github.com/devatsecure/Argus-Security
                - cd argus-action
                - pip install -r requirements.txt
                - |
                  python scripts/run_ai_audit.py \
                    --project-path $BITBUCKET_CLONE_DIR \
                    --project-type auto \
                    --ai-provider anthropic \
                    --semgrep-enabled true \
                    --enable-trufflehog true \
                    --enable-gitleaks true \
                    --enable-trivy true \
                    --enable-checkov true \
                    --enable-api-security true \
                    --enable-supply-chain true \
                    --enable-threat-intel true \
                    --enable-remediation true \
                    --enable-regression-testing true \
                    --enable-exploit-analysis true \
                    --only-changed true \
                    --output-file ../security-results.json \
                    --sarif-output ../security-results.sarif \
                    --markdown-output ../security-report.md
              artifacts:
                - security-results.json
                - security-results.sarif
                - security-report.md

          - step:
              name: API Security Testing
              caches:
                - argus
                - pip
              script:
                - git clone https://github.com/devatsecure/Argus-Security
                - cd argus-action
                - pip install -r requirements.txt
                - |
                  ./scripts/argus api-security \
                    --path $BITBUCKET_CLONE_DIR \
                    --output api-findings.json
              artifacts:
                - argus-action/api-findings.json

          - step:
              name: Supply Chain Security
              caches:
                - argus
                - pip
              script:
                - git clone https://github.com/devatsecure/Argus-Security
                - cd argus-action
                - pip install -r requirements.txt
                - |
                  # Check dependency changes in PR
                  ./scripts/argus supply-chain diff \
                    --base origin/main \
                    --head HEAD \
                    --output supply-chain-diff.json

                  # Full scan
                  ./scripts/argus supply-chain scan \
                    --path $BITBUCKET_CLONE_DIR \
                    --output supply-chain-scan.json
              artifacts:
                - argus-action/supply-chain-*.json

      - step:
          name: Threat Intelligence Enrichment
          caches:
            - argus
            - pip
          script:
            - cd argus-action
            - |
              ./scripts/argus threat-intel enrich \
                --findings ../security-results.json \
                --output threat-intel-enriched.json
          artifacts:
            - argus-action/threat-intel-enriched.json

      - step:
          name: Generate Remediation Fixes
          caches:
            - argus
            - pip
          script:
            - cd argus-action
            - |
              ./scripts/argus remediate \
                --findings ../security-results.json \
                --output remediation-fixes.md
          artifacts:
            - argus-action/remediation-fixes.md

      - step:
          name: Security Regression Tests
          caches:
            - argus
            - pip
          script:
            - cd argus-action
            - |
              ./scripts/argus regression-test run \
                --path $BITBUCKET_CLONE_DIR \
                --output regression-results.json
          artifacts:
            - argus-action/regression-results.json

      - step:
          name: Post PR Comment
          script:
            - |
              # Post security report as PR comment
              REPORT=$(cat security-report.md)
              curl -X POST \
                -u "$BITBUCKET_USERNAME:$BITBUCKET_APP_PASSWORD" \
                -H "Content-Type: application/json" \
                -d "{\"content\": {\"raw\": \"$REPORT\"}}" \
                "https://api.bitbucket.org/2.0/repositories/$BITBUCKET_REPO_FULL_NAME/pullrequests/$BITBUCKET_PR_ID/comments"

  # Main Branch Pipeline
  branches:
    main:
      - step:
          name: Complete Security Audit
          size: 2x
          caches:
            - argus
            - agent-cache
            - pip
          script:
            - git clone https://github.com/devatsecure/Argus-Security
            - cd argus-action
            - pip install -r requirements.txt
            - |
              python scripts/run_ai_audit.py \
                --project-path $BITBUCKET_CLONE_DIR \
                --project-type auto \
                --ai-provider anthropic \
                --enable-all-scanners true \
                --output-file ../security-results.json \
                --markdown-output ../security-report.md
          artifacts:
            - security-results.json
            - security-report.md

  # Custom Pipeline for Full Scan
  custom:
    full-security-audit:
      - step:
          name: Deep Security Analysis
          size: 2x
          caches:
            - argus
            - pip
          script:
            - git clone https://github.com/devatsecure/Argus-Security
            - cd argus-action
            - pip install -r requirements.txt
            - |
              # Enable ALL features
              python scripts/run_ai_audit.py \
                --project-path $BITBUCKET_CLONE_DIR \
                --project-type auto \
                --ai-provider anthropic \
                --enable-all-scanners true \
                --enable-api-security true \
                --enable-supply-chain true \
                --enable-fuzzing true \
                --enable-threat-intel true \
                --enable-remediation true \
                --enable-runtime-security false \
                --enable-regression-testing true \
                --output-file ../security-results.json
          artifacts:
            - security-results.json
```

## 🎯 Bitbucket-Specific Features

### 1. PR Comments via API

```yaml
- step:
    name: Post Security Report
    script:
      - |
        curl -X POST \
          -u "$BITBUCKET_USERNAME:$BITBUCKET_APP_PASSWORD" \
          -H "Content-Type: application/json" \
          -d @comment-payload.json \
          "https://api.bitbucket.org/2.0/repositories/$BITBUCKET_REPO_FULL_NAME/pullrequests/$BITBUCKET_PR_ID/comments"
```

### 2. Deployment Gates

```yaml
- step:
    name: Security Gate
    deployment: production
    trigger: manual
    script:
      - cd argus-action
      - |
        ./scripts/argus gate --stage release --input ../security-results.json
        if [ $? -ne 0 ]; then
          echo "Security gate failed - deployment blocked"
          exit 1
        fi
```

### 3. Artifacts & Reports

```yaml
artifacts:
  download: true
  - "*.json"
  - "*.md"
  - "*.sarif"
```

---

## 🔧 Advanced Configuration

### Environment Variables (All Platforms)

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-xxx  # or OPENAI_API_KEY
GITHUB_TOKEN=ghp_xxx           # GitHub only
GITLAB_TOKEN=glpat-xxx         # GitLab only
BITBUCKET_APP_PASSWORD=xxx     # Bitbucket only

# Optional
OLLAMA_ENDPOINT=http://localhost:11434
ARGUS_DEBUG=true
ARGUS_CACHE_DIR=.argus-cache
```

### Secret Management

**GitHub:**
```
Settings → Secrets and variables → Actions → New repository secret
```

**GitLab:**
```
Settings → CI/CD → Variables → Add variable (Masked)
```

**Bitbucket:**
```
Repository settings → Pipelines → Repository variables → Add variable (Secured)
```

---

## 📊 Feature Matrix by Platform

| Feature | GitHub | GitLab | Bitbucket |
|---------|--------|--------|-----------|
| **API Security Scan** | ✅ | ✅ | ✅ |
| **DAST Scan** | ✅ | ✅ | ✅ |
| **Supply Chain** | ✅ | ✅ | ✅ |
| **Fuzzing** | ✅ | ✅ | ✅ |
| **Threat Intel** | ✅ | ✅ | ✅ |
| **Auto-Remediation** | ✅ | ✅ | ✅ |
| **Regression Tests** | ✅ | ✅ | ✅ |
| **SARIF Upload** | ✅ Security tab | ✅ Dashboard | ⚠️ Artifacts only |
| **PR Comments** | ✅ Native | ✅ Native | ✅ API |
| **Matrix Builds** | ✅ | ✅ | ✅ |
| **Caching** | ✅ | ✅ | ✅ |
| **Scheduled Scans** | ✅ Cron | ✅ Schedules | ✅ Schedules |

---

## 🚀 Best Practices (All Platforms)

### 1. **Use Caching**
```yaml
# Cache Argus installation and Python packages
cache:
  - argus-action/
  - .argus-cache/
  - pip/
```

### 2. **Optimize for PRs**
```yaml
# Only scan changed files in PRs
--only-changed ${{ github.event_name == 'pull_request' }}
```

### 3. **Fail Fast**
```yaml
# Stop pipeline on critical findings
--fail-on-blockers true
--exploitability-threshold moderate
```

### 4. **Parallel Execution**
```yaml
# Run independent scans in parallel
parallel:
  - step: API Security
  - step: Supply Chain
  - step: SAST/DAST
```

### 5. **Cost Optimization**
```yaml
# Use smaller models for non-critical scans
--model claude-haiku-4  # Faster, cheaper
```

---

## 📚 Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [GitLab CI/CD Documentation](https://docs.gitlab.com/ee/ci/)
- [Bitbucket Pipelines Documentation](https://support.atlassian.com/bitbucket-cloud/docs/get-started-with-bitbucket-pipelines/)
- [Argus Documentation](https://github.com/devatsecure/Argus-Security/tree/main/docs)

---

**Version:** 4.0.0
**Last Updated:** 2026-01-15
**Maintained by:** Argus Team
