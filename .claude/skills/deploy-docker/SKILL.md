---
name: deploy-docker
description: Build and run Argus complete Docker image for full 6-phase security scanning against a target repository.
---

Deploy Argus Docker scanner for: $ARGUMENTS

Expected arguments: `<target-repo-path> [--rebuild] [--ai-provider anthropic|openai|ollama]`

## Pre-Flight Checks (Do These First)

1. **Verify Docker is running:**
   ```
   docker info > /dev/null 2>&1
   ```
   If this fails, stop and tell the user to start Docker Desktop or the Docker daemon.

2. **Check disk space:**
   ```
   docker system df
   ```
   Warn the user if less than 5GB is available. The Argus complete image requires significant space for all scanner tooling.

3. **Verify API key is set:**
   - Default (anthropic): Check that `ANTHROPIC_API_KEY` environment variable is set and non-empty.
   - If `--ai-provider openai` is passed: Check that `OPENAI_API_KEY` is set instead.
   - If `--ai-provider ollama` is passed: No API key required, but verify Ollama is reachable at `http://localhost:11434`.
   - If the required key is missing, stop and tell the user which variable to export.

## Build Step

1. Check if the `argus-complete` image already exists:
   ```
   docker image inspect argus-complete > /dev/null 2>&1
   ```
2. If the image exists AND `--rebuild` was NOT passed, skip the build and report the existing image tag/size.
3. If the image does not exist OR `--rebuild` was passed, build it:
   ```
   docker build -f Dockerfile.complete -t argus-complete .
   ```
   Run this from the Argus-Security repo root (`/Users/waseem.ahmed/Repos/Argus-Security`).

## Prepare Target

1. Parse `<target-repo-path>` from arguments.
   - If it looks like a URL (starts with `http://`, `https://`, or `git@`): clone it to `/tmp/argus-target-rw/`.
     ```
     rm -rf /tmp/argus-target-rw
     git clone <url> /tmp/argus-target-rw
     ```
   - If it is a local path: create a writable copy.
     ```
     rm -rf /tmp/argus-target-rw
     cp -r <local-path> /tmp/argus-target-rw
     ```
2. Verify `/tmp/argus-target-rw` exists and is non-empty before proceeding.
3. Create the output directory:
   ```
   mkdir -p /tmp/argus-output
   ```

## Run Step

Determine the AI provider (default: `anthropic`). Then run:

```
docker run --rm \
  -v /tmp/argus-target-rw:/workspace \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /tmp/argus-output:/output \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  --entrypoint python \
  argus-complete \
  /app/scripts/hybrid_analyzer.py /workspace \
  --output-dir /output \
  --enable-ai-enrichment \
  --ai-provider anthropic
```

Adjustments based on arguments:
- If `--ai-provider openai`: replace `-e ANTHROPIC_API_KEY=...` with `-e OPENAI_API_KEY="$OPENAI_API_KEY"` and set `--ai-provider openai`.
- If `--ai-provider ollama`: remove the API key env var, add `--network host` to the docker run flags, and set `--ai-provider ollama`.

## Post-Run

1. Check the exit code. If non-zero, read the container logs and diagnose the failure.
2. List the output files:
   ```
   ls -la /tmp/argus-output/
   ```
3. Read the output JSON report (e.g., `/tmp/argus-output/argus-report.json` or similar) and the Markdown report if present.
4. Summarize to the user:
   - **Phase timings**: How long each of the 6 phases took.
   - **Finding counts by severity**: Critical, High, Medium, Low, Info.
   - **Scanner breakdown**: Findings per scanner (Semgrep, Trivy, Checkov, TruffleHog, Gitleaks).
   - **AI triage results**: How many findings were marked as false positives, noise-filtered count.
   - **Policy gate status**: Pass or fail, and which gates triggered.
   - **Output file paths**: Full paths to all generated reports (SARIF, JSON, Markdown).
5. If any BLOCKER-level findings exist, highlight them prominently and recommend immediate action.
