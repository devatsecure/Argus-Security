# ⚠️ ALWAYS USE DOCKER FOR SCANS ⚠️

## Why This Document Exists

To prevent repeating the same mistakes:
- ❌ Missing dependencies (`tenacity` issue)
- ❌ Environment inconsistencies
- ❌ Incomplete feature availability

## ✅ The Solution: ALWAYS USE DOCKER

### Quick Command

```bash
# Use the wrapper script (RECOMMENDED)
./scan-complete-docker.sh /path/to/repo

# Or use Docker directly
docker run --rm \
  -v /path/to/repo:/workspace:ro \
  -v /tmp/results:/output \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  -e ENABLE_VULNERABILITY_CHAINING=true \
  argus:complete \
  /workspace \
  --output-dir /output \
  --enable-semgrep \
  --enable-trivy \
  --enable-checkov \
  --enable-api-security \
  --enable-supply-chain \
  --enable-threat-intel \
  --enable-ai-enrichment \
  --enable-remediation \
  --enable-regression-testing \
  --ai-provider anthropic
```

## 🎯 What's Included (VERIFIED ✅)

### Python Dependencies
- ✅ **tenacity** - AI retry logic (fixes Phase 2 issues)
- ✅ **networkx** - Vulnerability chaining graphs
- ✅ **anthropic** - Claude AI integration
- ✅ **openai** - OpenAI integration
- ✅ **docker** - Sandbox validation
- ✅ **pytm** - Threat modeling

### Security Tools
- ✅ **Semgrep 1.149.0** - SAST with 2,000+ rules
- ✅ **Trivy 0.68.2** - CVE scanning
- ✅ **Checkov 3.2.499** - IaC security
- ✅ **Nuclei 3.1.0** - DAST scanner
- ✅ **Gitleaks 8.18.1** - Secrets detection
- ✅ **TruffleHog 3.92.5** - Verified secrets
- ✅ **OWASP ZAP 2.14.0** - DAST scanner

### Argus Features
- ✅ **Phase 1:** Static Analysis (SAST, CVE, IaC, Secrets)
- ✅ **Phase 2:** AI Enrichment (Claude/OpenAI) ← **FIXED!**
- ✅ **Phase 2.5:** Automated Remediation
- ✅ **Phase 2.6:** Spontaneous Discovery
- ✅ **Phase 3:** Multi-Agent Persona Review
- ✅ **Phase 4:** Sandbox Validation
- ✅ **Phase 5:** Policy Gates
- ✅ **Phase 5.5:** Vulnerability Chaining ← **NEW!**
- ✅ **DAST:** Nuclei + ZAP ← **NEW!**

## 📋 Checklist Before Scanning

- [ ] Docker image built: `docker image inspect argus:complete`
- [ ] API key set: `echo $ANTHROPIC_API_KEY`
- [ ] Using Docker command (not direct Python)
- [ ] All phases enabled in command

## 🚨 If You Need to Rebuild

```bash
cd /Users/waseem.ahmed/Repos/Argus-Security
docker build -f Dockerfile.complete -t argus:complete --platform linux/amd64 .
```

## 📚 Documentation

- **Complete Guide:** `DOCKER_COMPLETE_GUIDE.md`
- **Scan Script:** `scan-complete-docker.sh`
- **Dockerfile:** `Dockerfile.complete`

---

**Remember: Docker = No surprises, All features, Every time! 🐳**
