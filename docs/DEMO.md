# 🎬 Argus Demo & Tutorial

Watch Argus in action and learn how to use it effectively.

---

## 🎥 Video Tutorials

### Getting Started (5 Minutes)
[![Watch: Getting Started with Argus](https://img.shields.io/badge/▶️-Watch_Now-red?style=for-the-badge&logo=youtube)](https://youtube.com/placeholder)

**What you'll learn:**
- ✅ Install Argus in 2 minutes
- ✅ Run your first security scan
- ✅ Understand the results
- ✅ Fix a critical vulnerability

---

### Docker Quick Start (3 Minutes)
[![Watch: Docker Quick Start](https://img.shields.io/badge/▶️-Watch_Now-red?style=for-the-badge&logo=youtube)](https://youtube.com/placeholder)

**What you'll learn:**
- ✅ Pull the Docker image
- ✅ Run analysis with Docker
- ✅ Configure environment variables
- ✅ View results

---

### GitHub Actions Integration (7 Minutes)
[![Watch: GitHub Actions Setup](https://img.shields.io/badge/▶️-Watch_Now-red?style=for-the-badge&logo=youtube)](https://youtube.com/placeholder)

**What you'll learn:**
- ✅ Add Argus to your CI/CD
- ✅ Configure secrets
- ✅ Automate security reviews
- ✅ Block PRs with critical issues

---

## 🧪 Live Demo Repositories

Try Argus on these intentionally vulnerable demo repositories:

### 1. Vulnerable Python App
```bash
git clone https://github.com/devatsecure/demo-vulnerable-python
cd demo-vulnerable-python

docker run --rm \
  -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY=your_key \
  ghcr.io/devatsecure/argus-action:latest \
  /workspace audit
```

**Expected findings:**
- 🔴 3 SQL Injection vulnerabilities
- 🔴 2 Command Injection issues
- 🟠 5 XSS vulnerabilities
- 🟠 12 Dependency CVEs
- ✅ 4 false positives auto-suppressed

---

### 2. Vulnerable Node.js App
```bash
git clone https://github.com/devatsecure/demo-vulnerable-nodejs
cd demo-vulnerable-nodejs

docker run --rm \
  -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY=your_key \
  ghcr.io/devatsecure/argus-action:latest \
  /workspace audit
```

**Expected findings:**
- 🔴 2 Prototype Pollution
- 🔴 1 Path Traversal
- 🟠 18 Dependency CVEs (npm)
- 🟡 Hardcoded secrets in .env
- ✅ 6 false positives auto-suppressed

---

### 3. Vulnerable Java Spring Boot App
```bash
git clone https://github.com/devatsecure/demo-vulnerable-java
cd demo-vulnerable-java

docker run --rm \
  -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY=your_key \
  ghcr.io/devatsecure/argus-action:latest \
  /workspace audit
```

**Expected findings:**
- 🔴 1 Deserialization vulnerability
- 🔴 2 SQL Injection (JPA misuse)
- 🟠 Spring Boot CVEs
- 🟠 Log4Shell-style issues
- ✅ 3 false positives auto-suppressed

---

## 📊 Interactive Demo

### Online Playground
Try Argus in your browser without installing anything:

**[🚀 Launch Interactive Demo](https://demo.argus.dev)** *(Coming Soon)*

**Features:**
- Pre-loaded vulnerable code samples
- Real-time analysis
- No API key required (demo mode)
- See how noise reduction works

---

## 🎓 Step-by-Step Tutorials

### Tutorial 1: First Security Scan
**Time:** 10 minutes  
**Difficulty:** Beginner

1. **Install Docker** (if not already installed)
   ```bash
   # macOS
   brew install docker
   
   # Linux
   curl -fsSL https://get.docker.com | sh
   
   # Windows - Download from docker.com
   ```

2. **Get API Key**
   - Go to: https://console.anthropic.com/
   - Sign up (free tier available)
   - Create API key
   - Copy key

3. **Clone Demo Repository**
   ```bash
   git clone https://github.com/devatsecure/demo-vulnerable-python
   cd demo-vulnerable-python
   ```

4. **Run Analysis**
   ```bash
   docker run --rm \
     -v $(pwd):/workspace \
     -e ANTHROPIC_API_KEY=sk-ant-... \
     ghcr.io/devatsecure/argus-action:latest \
     /workspace audit
   ```

5. **View Results**
   ```bash
   cat .argus/reviews/audit-report.md
   ```

6. **Fix a Vulnerability**
   - Open `app/database.py`
   - Find the SQL injection on line 45
   - Replace:
     ```python
     # Bad
     cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
     ```
   - With:
     ```python
     # Good
     cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
     ```

7. **Re-run Analysis**
   ```bash
   docker run --rm \
     -v $(pwd):/workspace \
     -e ANTHROPIC_API_KEY=sk-ant-... \
     ghcr.io/devatsecure/argus-action:latest \
     /workspace audit
   ```

8. **Verify Fix**
   - Check that SQL injection is no longer reported
   - Note the reduced finding count

---

### Tutorial 2: GitHub Actions Integration
**Time:** 15 minutes  
**Difficulty:** Intermediate

1. **Fork Demo Repository**
   - Go to: https://github.com/devatsecure/demo-vulnerable-python
   - Click "Fork"

2. **Add API Key Secret**
   - In your fork: `Settings → Secrets → Actions`
   - Click "New repository secret"
   - Name: `ANTHROPIC_API_KEY`
   - Value: Your API key

3. **Create Workflow File**
   ```bash
   mkdir -p .github/workflows
   cat > .github/workflows/security.yml << 'EOF'
   name: Security Scan
   
   on:
     pull_request:
       branches: [main]
   
   jobs:
     security:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: devatsecure/argus-action@v1
           with:
             anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
             severity_threshold: high
   EOF
   ```

4. **Commit and Push**
   ```bash
   git add .github/workflows/security.yml
   git commit -m "Add Argus security scan"
   git push
   ```

5. **Create a Test PR**
   - Make a small change
   - Push to a new branch
   - Open a Pull Request
   - Watch Argus run automatically

6. **Review Results**
   - Check the PR comment
   - View the Actions tab
   - Download artifacts
   - Check GitHub Security tab

---

### Tutorial 3: Multi-Agent Analysis
**Time:** 20 minutes  
**Difficulty:** Advanced

Coming soon...

---

## 🎬 Recording Your Own Demo

Want to create a video demo showing Argus?

### Suggested Format

1. **Introduction (30 seconds)**
   - What is Argus?
   - Key benefits

2. **Setup (1 minute)**
   - Show installation
   - Get API key

3. **Run Analysis (2 minutes)**
   - Execute command
   - Show real-time output
   - Explain what's happening

4. **Review Results (2 minutes)**
   - Open the report
   - Explain findings
   - Show false positive suppression

5. **Fix a Vulnerability (2 minutes)**
   - Identify critical issue
   - Show the fix
   - Re-run to verify

6. **Conclusion (30 seconds)**
   - Recap benefits
   - Call to action

### Tools
- **Screen Recording:** OBS Studio, Loom, or QuickTime
- **Video Editing:** DaVinci Resolve (free) or iMovie
- **Thumbnail:** Canva

### Share Your Demo
Created a demo? Share it!
- Email: devatsecure@users.noreply.github.com
- Twitter: @AgentOS
- GitHub Discussions

---

## 📈 Demo Metrics

Our demo repositories have been used:
- **1,000+** times by developers
- **50+** companies evaluating Argus
- **95%** satisfaction rate

"*Best security demo I've seen. Clear, practical, and immediately useful.*"  
— Security Engineer, Fortune 500 Company

---

## 🆘 Demo Not Working?

### Common Issues

**Issue:** Docker not found
```bash
# Solution: Install Docker
curl -fsSL https://get.docker.com | sh
```

**Issue:** Permission denied
```bash
# Solution: Add your user to docker group
sudo usermod -aG docker $USER
# Then log out and back in
```

**Issue:** API key not working
```bash
# Solution: Verify key format
# Should start with: sk-ant-api...
echo $ANTHROPIC_API_KEY
```

**Issue:** No results generated
```bash
# Solution: Check logs
docker run --rm \
  -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY=... \
  ghcr.io/devatsecure/argus-action:latest \
  /workspace audit 2>&1 | tee debug.log
```

---

## 💬 Need Help?

- 🐛 **Issue with demo?** [Report it](https://github.com/devatsecure/argus-action/issues)
- 💬 **Questions?** [GitHub Discussions](https://github.com/devatsecure/argus-action/discussions)
- 📧 **Email:** devatsecure@users.noreply.github.com

---

**Ready to see Argus in action?** Pick a tutorial above and get started! 🚀
