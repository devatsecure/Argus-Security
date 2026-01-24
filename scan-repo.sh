#!/bin/bash
# Argus Complete Security Scanner - Simple Wrapper
# Usage: ./scan-repo.sh /path/to/repo [output-dir]

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

REPO_PATH="${1:-.}"
OUTPUT_DIR="${2:-./security-reports}"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         Argus Complete Security Scanner                  ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if API key is set
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "❌ Error: ANTHROPIC_API_KEY environment variable not set"
    echo ""
    echo "Set it with:"
    echo "  export ANTHROPIC_API_KEY=your-key-here"
    echo ""
    echo "Get a key from: https://console.anthropic.com/"
    exit 1
fi

# Check if repo path exists
if [ ! -d "$REPO_PATH" ]; then
    echo "❌ Error: Repository path not found: $REPO_PATH"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo -e "${GREEN}📂 Repository:${NC} $(realpath $REPO_PATH)"
echo -e "${GREEN}📁 Output:${NC} $(realpath $OUTPUT_DIR)"
echo -e "${GREEN}🔑 API Key:${NC} ****${ANTHROPIC_API_KEY:  -8}"
echo ""
echo "🚀 Starting security scan..."
echo ""

# Run the scan (with Docker socket for Phase 4 sandbox validation)
docker run --rm \
    -v "$(realpath $REPO_PATH):/workspace" \
    -v "$(realpath $OUTPUT_DIR):/output" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
    argus:complete \
    . security --provider anthropic

echo ""
echo -e "${GREEN}✅ Scan complete!${NC}"
echo ""
echo "📊 Reports generated:"
echo "  - Security Report: $OUTPUT_DIR/security-report.md"
echo "  - SARIF: $OUTPUT_DIR/results.sarif"
echo "  - JSON: $OUTPUT_DIR/results.json"
echo ""
