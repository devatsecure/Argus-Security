#!/bin/bash
# Quick Demo: Vulnerability Chaining System
# Shows how multiple vulnerabilities chain into critical attacks

set -e

echo "🔗 Vulnerability Chaining System - Quick Demo"
echo "=============================================="
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "📦 Installing dependencies..."
pip install -q networkx 2>/dev/null || echo "   ℹ️  networkx already installed"

echo ""
echo "🧪 Running test suite..."
python tests/test_vulnerability_chaining.py

echo ""
echo "📊 Running examples..."
python examples/vulnerability_chaining_example.py

echo ""
echo "✅ Demo complete!"
echo ""
echo "📚 Next steps:"
echo "   1. Read docs/VULNERABILITY_CHAINING_GUIDE.md"
echo "   2. Try with real scan results:"
echo "      python scripts/vulnerability_chaining_engine.py --input findings.json"
echo "   3. Enable in hybrid analyzer:"
echo "      export ENABLE_VULNERABILITY_CHAINING=true"
echo "      python scripts/hybrid_analyzer.py /path/to/repo"
