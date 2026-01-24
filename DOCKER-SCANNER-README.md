# Argus Complete Security Scanner - Docker Edition

**All-in-one Docker container with ALL security scanners pre-installed!**

## 🎯 What's Included

✅ **Semgrep** - SAST scanning (2,000+ security rules)
✅ **Trivy** - CVE/dependency scanning  
✅ **Checkov** - Infrastructure-as-Code security  
✅ **TruffleHog** - Verified secret detection  
✅ **Gitleaks** - Pattern-based secret scanning  
✅ **pytm** - Threat modeling  
✅ **Claude AI** - AI-powered triage and enrichment  

## 🚀 Quick Start

### 1. Build the Docker Image

```bash
docker build -f Dockerfile.complete -t argus:complete .
```

### 2. Set Your API Key

```bash
export ANTHROPIC_API_KEY=your-key-here
```

Get a key from: https://console.anthropic.com/

### 3. Scan Any Repository

**Option A: Use the simple wrapper script:**

```bash
./scan-repo.sh /path/to/your/repo
```

**Option B: Run Docker directly:**

```bash
docker run --rm \
  -v /path/to/your/repo:/workspace \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  argus:complete \
  . security --provider anthropic
```

## 📋 Examples

### Scan UltraRAG repository:

```bash
./scan-repo.sh /tmp/UltraRAG
```

### Scan with custom output directory:

```bash
./scan-repo.sh /tmp/UltraRAG ./my-reports
```

### Direct Docker command:

```bash
docker run --rm \
  -v /tmp/UltraRAG:/workspace \
  -v ./reports:/output \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  argus:complete \
  . security --provider anthropic
```

## 📊 What You Get

After scanning, you'll get these reports:

- **security-report.md** - Comprehensive markdown report with all findings
- **results.sarif** - SARIF format for GitHub Code Scanning
- **results.json** - Structured JSON for programmatic access
- **metrics.json** - Scan statistics and metrics
- **threat-model.json** - Generated threat model

## 🔧 All Available Scanners

The Docker image includes:

| Scanner | Version | Purpose |
|---------|---------|---------|
| Semgrep | Latest | SAST - Static Application Security Testing |
| Trivy | 0.67.2 | CVE scanning for dependencies |
| Checkov | Latest | Infrastructure-as-Code security |
| TruffleHog | Latest | Verified secret detection |
| Gitleaks | 8.18.1 | Pattern-based secret scanning |
| pytm | Latest | Threat modeling (STRIDE) |

## 🎨 Advanced Usage

### Enable all phases explicitly:

```bash
docker run --rm \
  -v /tmp/UltraRAG:/workspace \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  argus:complete \
  . security \
  --provider anthropic \
  --enable-semgrep \
  --enable-trivy \
  --enable-checkov \
  --debug
```

### Scan with different AI provider (OpenAI):

```bash
docker run --rm \
  -v /path/to/repo:/workspace \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  argus:complete \
  . security --provider openai
```

### Use with Ollama (free, local):

```bash
# Start Ollama first
ollama run llama3

# Then run scanner
docker run --rm \
  -v /path/to/repo:/workspace \
  --network host \
  -e OLLAMA_ENDPOINT=http://localhost:11434 \
  argus:complete \
  . security --provider ollama
```

## 🐛 Troubleshooting

### "ANTHROPIC_API_KEY not set"
```bash
export ANTHROPIC_API_KEY=sk-ant-...your-key
```

### "Permission denied" when mounting volumes
```bash
# Make sure the paths are absolute
docker run --rm \
  -v $(pwd)/repo:/workspace \
  ...
```

### Image not found
```bash
# Rebuild the image
docker build -f Dockerfile.complete -t argus:complete .
```

## 📈 Performance

- **Typical scan time:** 2-5 minutes for ~100 files
- **Memory usage:** ~2GB RAM
- **Disk space:** ~3GB for image + databases
- **Cost:** ~$0.15-0.25 per scan (with Claude AI)

## 🔒 Security Features

**6-Phase Security Pipeline:**

1. **Phase 1:** Fast deterministic scanning (Semgrep, Trivy, Checkov, TruffleHog, Gitleaks)
2. **Phase 2:** AI enrichment with threat modeling
3. **Phase 2.5:** Automated remediation suggestions
4. **Phase 2.6:** Spontaneous discovery (find issues beyond scanner rules)
5. **Phase 3:** Multi-agent persona review
6. **Phase 4:** Sandbox validation (Docker-in-Docker exploit verification)
7. **Phase 5:** Policy gates
8. **Phase 6:** Report generation

**Phase 4 Sandbox Validation:**
- Validates exploits in isolated Docker containers
- Proves vulnerabilities are actually exploitable
- Supports Python, JavaScript, Java, Go
- Automatically enabled when Docker socket is available

## 📝 License

Apache-2.0

## 🙋 Support

For issues or questions, create an issue on GitHub or check the main README.md

## 🎉 You're All Set!

Just run:

```bash
./scan-repo.sh /path/to/your/repo
```

And watch the magic happen! ✨
