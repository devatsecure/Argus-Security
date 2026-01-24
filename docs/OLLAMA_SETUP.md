# 🦙 Ollama Setup Guide

Run Argus with **free, local LLMs** using Ollama. No API keys, no cloud costs!

---

## Why Ollama?

✅ **Free** - No API costs  
✅ **Private** - Your code never leaves your machine  
✅ **Fast** - Local inference (with GPU)  
✅ **Offline** - Works without internet  
✅ **Open Source** - Fully transparent  

---

## Quick Start

### 1. Install Ollama

```bash
# macOS
curl -fsSL https://ollama.ai/install.sh | sh

# Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Windows
# Download from: https://ollama.ai/download
```

### 2. Download a Model

```bash
# Recommended: CodeLlama 7B (best for code)
ollama pull codellama

# Alternative: Llama 3 8B (general purpose)
ollama pull llama3

# Alternative: Mistral 7B (fast and good)
ollama pull mistral

# Large: CodeLlama 34B (if you have 32GB+ RAM/VRAM)
ollama pull codellama:34b
```

### 3. Start Ollama Server

```bash
# Starts on http://localhost:11434
ollama serve
```

### 4. Run Argus with Ollama

```bash
docker run --rm \
  -v $(pwd):/workspace \
  -e AI_PROVIDER=ollama \
  -e OLLAMA_ENDPOINT=http://host.docker.internal:11434 \
  -e MODEL=codellama \
  ghcr.io/devatsecure/argus-action:latest \
  /workspace audit
```

---

## Configuration

### Option 1: Environment Variables

```bash
export AI_PROVIDER=ollama
export OLLAMA_ENDPOINT=http://localhost:11434
export MODEL=codellama

python scripts/run_ai_audit.py /path/to/repo audit
```

### Option 2: Config File

Create `.argus.yml`:

```yaml
# Use Ollama provider
ai_provider: ollama
ollama_endpoint: http://localhost:11434
model: codellama

# Use lite mode for faster scans
agent_profile: lite
multi_agent_mode: sequential

# Cost is $0, but still limit resources
max_files: 50
max_tokens: 4000
```

### Option 3: GitHub Actions

```yaml
name: Security Scan with Ollama

on:
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    
    services:
      ollama:
        image: ollama/ollama:latest
        ports:
          - 11434:11434
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Download model
        run: |
          docker exec ${{ job.services.ollama.id }} ollama pull codellama
      
      - name: Run Argus with Ollama
        uses: devatsecure/argus-action@v1
        with:
          ai_provider: ollama
          ollama_endpoint: http://ollama:11434
          model: codellama
          agent_profile: lite
```

---

## Model Recommendations

### For Code Security Analysis

| Model | Size | RAM Required | Speed | Quality |
|-------|------|--------------|-------|---------|
| **CodeLlama 7B** | 4GB | 8GB | Fast | ⭐⭐⭐⭐ |
| CodeLlama 13B | 7GB | 16GB | Medium | ⭐⭐⭐⭐⭐ |
| CodeLlama 34B | 19GB | 32GB | Slow | ⭐⭐⭐⭐⭐ |

### For General Purpose

| Model | Size | RAM Required | Speed | Quality |
|-------|------|--------------|-------|---------|
| Llama 3 8B | 4.7GB | 8GB | Fast | ⭐⭐⭐⭐ |
| Llama 3 70B | 40GB | 64GB | Very Slow | ⭐⭐⭐⭐⭐ |
| Mistral 7B | 4.1GB | 8GB | Very Fast | ⭐⭐⭐⭐ |

**Recommendation:** Start with **CodeLlama 7B** for best balance of speed and quality.

---

## Performance Comparison

### Cloud API (Anthropic Claude)
- **Cost:** $0.35-1.00 per scan
- **Speed:** 3-5 minutes
- **Quality:** ⭐⭐⭐⭐⭐
- **Privacy:** Code sent to cloud

### Ollama (CodeLlama 7B)
- **Cost:** $0.00
- **Speed:** 5-8 minutes (CPU) or 2-4 minutes (GPU)
- **Quality:** ⭐⭐⭐⭐
- **Privacy:** 100% local

### Ollama (CodeLlama 34B)
- **Cost:** $0.00
- **Speed:** 15-20 minutes (CPU) or 6-10 minutes (GPU)
- **Quality:** ⭐⭐⭐⭐⭐
- **Privacy:** 100% local

---

## GPU Acceleration

### Enable GPU Support

```bash
# Check if GPU is available
ollama list

# NVIDIA GPUs are automatically detected
# For Mac M1/M2/M3, Metal is automatically used

# Check GPU usage
nvidia-smi  # NVIDIA
ioreg -l | grep "Metal"  # macOS
```

### Docker with GPU

```bash
docker run --rm \
  --gpus all \
  -v $(pwd):/workspace \
  -e AI_PROVIDER=ollama \
  -e OLLAMA_ENDPOINT=http://host.docker.internal:11434 \
  ghcr.io/devatsecure/argus-action:latest \
  /workspace audit
```

---

## Troubleshooting

### Issue 1: "Connection refused"

```bash
# Solution 1: Check if Ollama is running
curl http://localhost:11434/api/version

# Solution 2: Start Ollama
ollama serve

# Solution 3: Check firewall
sudo ufw allow 11434  # Linux
```

### Issue 2: "Model not found"

```bash
# Solution: Download the model
ollama pull codellama

# List downloaded models
ollama list
```

### Issue 3: "Out of memory"

```bash
# Solution 1: Use smaller model
ollama pull codellama  # Instead of codellama:34b

# Solution 2: Reduce context size
export MAX_TOKENS=2000  # Default: 4000

# Solution 3: Use lite mode
export AGENT_PROFILE=lite
```

### Issue 4: "Too slow"

```bash
# Solution 1: Use GPU acceleration (see above)

# Solution 2: Use smaller model
ollama pull mistral  # Fastest

# Solution 3: Reduce files analyzed
export MAX_FILES=20

# Solution 4: Use lite mode
export AGENT_PROFILE=lite
```

### Issue 5: Docker can't reach Ollama

```bash
# Solution: Use host.docker.internal instead of localhost
-e OLLAMA_ENDPOINT=http://host.docker.internal:11434

# Linux alternative: Use host network
docker run --network=host ...
```

---

## Advanced Configuration

### Custom Model

```bash
# Create custom model with specific instructions
ollama create security-scanner -f Modelfile

# Modelfile example:
FROM codellama
PARAMETER temperature 0.1
PARAMETER top_p 0.9
SYSTEM You are a security code reviewer. Focus on finding vulnerabilities.
```

### Quantization for Speed

```bash
# Use quantized models for faster inference
ollama pull codellama:7b-code-q4_0  # 4-bit quantization
ollama pull codellama:7b-code-q8_0  # 8-bit quantization

# Trade-off: 2-3x faster, slightly lower quality
```

### Multiple Models

```bash
# Run different models for different agent types
export SECURITY_MODEL=codellama
export PERFORMANCE_MODEL=mistral
export QUALITY_MODEL=llama3
```

---

## Comparison: Ollama vs Cloud

### When to Use Ollama

✅ **Free tier expired** - No API costs  
✅ **Privacy required** - Code can't leave premises  
✅ **Offline work** - No internet connection  
✅ **High volume** - Scanning many repos  
✅ **Learning/testing** - Try Argus for free  

### When to Use Cloud APIs

✅ **Best quality** - Claude 3.5 Sonnet is better  
✅ **Faster scans** - Cloud GPUs are faster  
✅ **No hardware** - Works on any machine  
✅ **Easy setup** - Just add API key  
✅ **Production use** - More reliable  

---

## Cost Savings Example

### Scenario: 100 scans per month

**With Claude API:**
- Cost per scan: $0.50
- Monthly cost: **$50.00**
- Annual cost: **$600.00**

**With Ollama:**
- Hardware: $0 (use existing)
- Electricity: ~$2/month (GPU)
- Monthly cost: **$2.00**
- Annual cost: **$24.00**

**Savings: $576/year** 💰

---

## Getting Help

- **Ollama Docs:** https://github.com/ollama/ollama
- **Argus Docs:** [README.md](../README.md)
- **Issues:** [GitHub Issues](https://github.com/devatsecure/argus-action/issues)
- **Discussions:** [GitHub Discussions](https://github.com/devatsecure/argus-action/discussions)

---

## Next Steps

1. ✅ **Install Ollama** (5 minutes)
2. ✅ **Download CodeLlama** (5 minutes)
3. ✅ **Run your first scan** (5 minutes)
4. 📊 **Review dashboard** ([dashboard guide](../QUICKSTART.md))
5. ⚙️ **Optimize settings** (for your hardware)
6. 🚀 **Add to CI/CD** (GitHub Actions example above)

**Ready to scan with Ollama?** Follow the Quick Start above! 🦙
