#!/bin/bash
# Automated setup for Hybrid Security Analyzer
# Run this script to install all dependencies

set -e

echo "🔧 Setting up Hybrid Security Analyzer..."
echo ""

# Check Python version
echo "📋 Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || [ "$PYTHON_MAJOR" -eq 3 -a "$PYTHON_MINOR" -lt 9 ]; then
    echo "❌ Python 3.9+ required (found $PYTHON_VERSION)"
    echo "   Install Python 3.9+: https://www.python.org/downloads/"
    exit 1
fi

echo "✅ Python $PYTHON_VERSION detected"
echo ""

# Install Python dependencies
echo "📦 Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt --quiet
    echo "✅ Python dependencies installed"
else
    echo "⚠️  requirements.txt not found, installing core dependencies..."
    pip3 install anthropic openai tenacity --quiet
fi
echo ""

# Install Semgrep
echo "📦 Installing Semgrep..."
if command -v semgrep &> /dev/null; then
    SEMGREP_VERSION=$(semgrep --version 2>&1 | head -1)
    echo "✅ Semgrep already installed: $SEMGREP_VERSION"
else
    pip3 install semgrep --quiet
    echo "✅ Semgrep installed successfully"
fi
echo ""

# Install Trivy
echo "📦 Installing Trivy..."
if command -v trivy &> /dev/null; then
    TRIVY_VERSION=$(trivy --version 2>&1 | head -1)
    echo "✅ Trivy already installed: $TRIVY_VERSION"
else
    echo "   Installing Trivy..."
    
    # Detect OS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            echo "   Using Homebrew to install Trivy..."
            brew install trivy
        else
            echo "   Homebrew not found. Installing Trivy manually..."
            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
        fi
    else
        # Linux
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    fi
    
    echo "✅ Trivy installed successfully"
fi
echo ""

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p .argus/hybrid-results
mkdir -p .argus/cache
mkdir -p scripts/providers
echo "✅ Directories created"
echo ""

# Optional: Install Foundation-Sec dependencies
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🤖 Foundation-Sec-8B (Optional AI Enhancement)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Foundation-Sec-8B provides AI-powered security analysis:"
echo "  • CWE mapping for vulnerabilities"
echo "  • Exploitability assessment"
echo "  • Intelligent remediation suggestions"
echo ""
echo "⚠️  Requirements:"
echo "  • 16GB model download (first run: 20-30 minutes)"
echo "  • 4GB RAM minimum (with quantization)"
echo "  • GPU recommended but not required"
echo ""

read -p "Install Foundation-Sec-8B dependencies? [y/N] " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "📦 Installing Foundation-Sec dependencies..."
    pip3 install transformers torch accelerate bitsandbytes --quiet
    echo "✅ Foundation-Sec dependencies installed"
    echo ""
    echo "💡 Note: Model will download on first use (~16GB, 20-30 min)"
else
    echo "⏭️  Skipping Foundation-Sec installation"
    echo "   You can install later with: pip3 install transformers torch accelerate bitsandbytes"
fi
echo ""

# Optional: Check Docker for sandbox validation
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🐳 Docker (Optional Sandbox Validation)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if command -v docker &> /dev/null; then
    if docker ps &> /dev/null; then
        echo "✅ Docker is installed and running"
        pip3 install docker --quiet
        echo "✅ Docker Python SDK installed"
    else
        echo "⚠️  Docker is installed but not running"
        echo "   Start Docker to enable sandbox validation"
    fi
else
    echo "ℹ️  Docker not found (optional)"
    echo "   Install Docker to enable exploit sandbox validation:"
    echo "   • macOS: https://docs.docker.com/desktop/install/mac-install/"
    echo "   • Linux: https://docs.docker.com/engine/install/"
fi
echo ""

# Health check
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🏥 Health Check"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check Semgrep
if command -v semgrep &> /dev/null; then
    echo "✅ Semgrep: OK"
else
    echo "❌ Semgrep: NOT FOUND"
fi

# Check Trivy
if command -v trivy &> /dev/null; then
    echo "✅ Trivy: OK"
else
    echo "❌ Trivy: NOT FOUND"
fi

# Check Python packages
if python3 -c "import anthropic" 2>/dev/null; then
    echo "✅ Anthropic SDK: OK"
else
    echo "⚠️  Anthropic SDK: NOT FOUND (optional)"
fi

if python3 -c "import transformers" 2>/dev/null; then
    echo "✅ Foundation-Sec dependencies: OK"
else
    echo "ℹ️  Foundation-Sec dependencies: NOT INSTALLED (optional)"
fi

if command -v docker &> /dev/null && docker ps &> /dev/null 2>&1; then
    echo "✅ Docker: OK"
else
    echo "ℹ️  Docker: NOT AVAILABLE (optional)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Setup Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🚀 Quick Start:"
echo ""
echo "   # Basic scan (Semgrep + Trivy)"
echo "   python3 scripts/hybrid_analyzer.py ."
echo ""
echo "   # With AI enrichment (requires Foundation-Sec)"
echo "   python3 scripts/hybrid_analyzer.py . --enable-foundation-sec"
echo ""
echo "   # Full pipeline (all features)"
echo "   python3 scripts/hybrid_analyzer.py . \\"
echo "     --enable-semgrep \\"
echo "     --enable-trivy \\"
echo "     --enable-foundation-sec \\"
echo "     --enable-argus \\"
echo "     --severity-filter critical,high"
echo ""
echo "📚 Documentation:"
echo "   • README: HYBRID_ANALYZER_README.md"
echo "   • Troubleshooting: docs/TROUBLESHOOTING.md"
echo "   • Examples: examples/"
echo ""
echo "Happy scanning! 🔒"









