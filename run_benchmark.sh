#!/bin/bash
# Argus v4.1.0 Quick Benchmark Script

set -e

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                                                                  ║"
echo "║         Argus v4.1.0 Benchmark Scan                           ║"
echo "║                                                                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Check API key
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "❌ ERROR: ANTHROPIC_API_KEY not set"
    echo ""
    echo "Please set your API key:"
    echo "  export ANTHROPIC_API_KEY='your-key-here'"
    echo ""
    exit 1
fi

# Repository info
REPO_PATH="${1:-.}"
cd "$REPO_PATH"

echo "📁 Repository: $(basename $(pwd))"
echo "📊 Python files: $(find . -name '*.py' | wc -l)"
echo "📝 Lines of code: $(wc -l **/*.py 2>/dev/null | tail -1 | awk '{print $1}')"
echo ""

# Create results directory
mkdir -p benchmark_results
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="benchmark_results/$TIMESTAMP"
mkdir -p "$RESULTS_DIR"

echo "📂 Results directory: $RESULTS_DIR"
echo ""

# Test 1: Full scan with AI
echo "════════════════════════════════════════════════════════════════════"
echo "🔬 Test 1: Full Scan (with AI triage)"
echo "════════════════════════════════════════════════════════════════════"
START1=$(date +%s)

python scripts/run_ai_audit.py \
    --project-type backend-api \
    --ai-provider anthropic \
    --output-file "$RESULTS_DIR/full_scan.json" \
    2>&1 | tee "$RESULTS_DIR/full_scan.log"

END1=$(date +%s)
DURATION1=$((END1 - START1))

echo ""
echo "✅ Test 1 complete: ${DURATION1}s ($(echo "scale=2; $DURATION1/60" | bc) minutes)"
echo ""

# Test 2: Cached re-scan
echo "════════════════════════════════════════════════════════════════════"
echo "🔬 Test 2: Cached Re-scan"
echo "════════════════════════════════════════════════════════════════════"
START2=$(date +%s)

python scripts/run_ai_audit.py \
    --project-type backend-api \
    --ai-provider anthropic \
    --output-file "$RESULTS_DIR/cached_scan.json" \
    2>&1 | tee "$RESULTS_DIR/cached_scan.log"

END2=$(date +%s)
DURATION2=$((END2 - START2))
SPEEDUP=$(echo "scale=2; $DURATION1/$DURATION2" | bc)

echo ""
echo "✅ Test 2 complete: ${DURATION2}s (${SPEEDUP}x faster)"
echo ""

# Summary
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                    BENCHMARK SUMMARY                             ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "Performance:"
echo "  • Full scan: ${DURATION1}s ($(echo "scale=2; $DURATION1/60" | bc) min)"
echo "  • Cached scan: ${DURATION2}s"
echo "  • Cache speedup: ${SPEEDUP}x"
echo ""
echo "Results saved to: $RESULTS_DIR/"
echo ""
echo "Next steps:"
echo "  1. Review: cat $RESULTS_DIR/full_scan.json"
echo "  2. Check cost: grep -i 'tokens\|cost' $RESULTS_DIR/full_scan.log"
echo "  3. See guide: cat BENCHMARK_GUIDE.md"
echo ""

