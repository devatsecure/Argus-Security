#!/bin/bash
# Complete Argus Security Scan using Docker
# Includes: ALL 6 Phases + DAST + Vulnerability Chaining

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     🔒 ARGUS SECURITY - COMPLETE 6-PHASE ANALYSIS 🔒        ║
║                                                              ║
║  ✅ Phase 1: Static Analysis (SAST, CVE, IaC, Secrets)     ║
║  ✅ Phase 2: AI Enrichment (Claude/OpenAI)                 ║
║  ✅ Phase 2.5: Automated Remediation                        ║
║  ✅ Phase 2.6: Spontaneous Discovery                        ║
║  ✅ Phase 3: Multi-Agent Persona Review                     ║
║  ✅ Phase 4: Sandbox Validation (Docker)                    ║
║  ✅ Phase 5: Policy Gates                                   ║
║  ✅ Phase 5.5: Vulnerability Chaining                       ║
║  ✅ DAST: Dynamic Security Testing (Nuclei + ZAP)           ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
${NC}"

# Check arguments
if [ "$#" -lt 1 ]; then
    echo -e "${RED}Usage: $0 <target_path_or_url> [options]${NC}"
    echo ""
    echo "Examples:"
    echo "  $0 /path/to/repo                           # Full scan of repository"
    echo "  $0 /path/to/repo --dast-url http://app:8080  # Include DAST scan"
    echo "  $0 https://github.com/user/repo            # Scan remote repository"
    echo ""
    exit 1
fi

TARGET="$1"
shift

# Parse additional arguments
DAST_URL=""
OUTPUT_DIR="/tmp/argus-scan-results"
AI_PROVIDER="${AI_PROVIDER:-anthropic}"
EXTRA_ARGS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --dast-url)
            DAST_URL="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --ai-provider)
            AI_PROVIDER="$2"
            shift 2
            ;;
        *)
            EXTRA_ARGS="$EXTRA_ARGS $1"
            shift
            ;;
    esac
done

# Check if Docker image exists
if ! docker image inspect argus:complete >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Docker image 'argus:complete' not found. Building...${NC}"
    echo ""
    docker build -f Dockerfile.complete -t argus:complete --platform linux/amd64 .
    echo -e "${GREEN}✅ Docker image built successfully${NC}"
    echo ""
fi

# Check for API key
if [ -z "$ANTHROPIC_API_KEY" ] && [ -z "$OPENAI_API_KEY" ]; then
    echo -e "${YELLOW}⚠️  Warning: No API key found (ANTHROPIC_API_KEY or OPENAI_API_KEY)${NC}"
    echo -e "${YELLOW}   AI enrichment phases (2, 2.6, 3) will be skipped${NC}"
    echo ""
fi

# Prepare target (clone if URL)
SCAN_TARGET="$TARGET"
if [[ "$TARGET" == http* ]]; then
    echo -e "${BLUE}📥 Cloning repository: $TARGET${NC}"
    REPO_NAME=$(basename "$TARGET" .git)
    SCAN_TARGET="/tmp/argus-scan-$REPO_NAME"
    rm -rf "$SCAN_TARGET"
    git clone --depth 1 "$TARGET" "$SCAN_TARGET"
    echo -e "${GREEN}✅ Repository cloned${NC}"
    echo ""
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build Docker run command
DOCKER_CMD="docker run --rm \
    -v \"$SCAN_TARGET:/workspace:ro\" \
    -v \"$OUTPUT_DIR:/output\" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -e ANTHROPIC_API_KEY=\"${ANTHROPIC_API_KEY:-}\" \
    -e OPENAI_API_KEY=\"${OPENAI_API_KEY:-}\" \
    -e ENABLE_VULNERABILITY_CHAINING=true \
    -e CHAIN_MAX_LENGTH=4 \
    -e CHAIN_MIN_RISK=0.0 \
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
    --ai-provider $AI_PROVIDER"

# Add DAST if URL provided
if [ -n "$DAST_URL" ]; then
    DOCKER_CMD="$DOCKER_CMD --enable-dast --dast-target-url $DAST_URL"
    echo -e "${BLUE}🌐 DAST enabled for: $DAST_URL${NC}"
    echo ""
fi

# Add extra arguments
if [ -n "$EXTRA_ARGS" ]; then
    DOCKER_CMD="$DOCKER_CMD $EXTRA_ARGS"
fi

# Show configuration
echo -e "${BLUE}📊 Scan Configuration:${NC}"
echo -e "   Target:       $SCAN_TARGET"
echo -e "   Output:       $OUTPUT_DIR"
echo -e "   AI Provider:  $AI_PROVIDER"
if [ -n "$DAST_URL" ]; then
    echo -e "   DAST URL:     $DAST_URL"
fi
echo ""

# Run scan
echo -e "${GREEN}🚀 Starting complete security scan...${NC}"
echo ""

eval "$DOCKER_CMD"

SCAN_EXIT_CODE=$?

echo ""
if [ $SCAN_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}
╔══════════════════════════════════════════════════════════════╗
║                    ✅ SCAN COMPLETE ✅                       ║
╚══════════════════════════════════════════════════════════════╝
${NC}"
    echo -e "${BLUE}📁 Results saved to: $OUTPUT_DIR${NC}"
    echo ""
    echo -e "${BLUE}📊 Available reports:${NC}"
    ls -lh "$OUTPUT_DIR"/*.{json,sarif,md} 2>/dev/null || echo "   (No report files found)"
    echo ""
else
    echo -e "${RED}
╔══════════════════════════════════════════════════════════════╗
║                    ❌ SCAN FAILED ❌                         ║
╚══════════════════════════════════════════════════════════════╝
${NC}"
    exit $SCAN_EXIT_CODE
fi
