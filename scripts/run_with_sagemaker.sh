#!/bin/bash
#
# Run Agent OS with SageMaker Foundation-Sec endpoint
# 
# Usage:
#   1. Create .env file with your credentials (see .env.example)
#   2. Run: bash scripts/run_with_sagemaker.sh /path/to/repo
#

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Agent OS - SageMaker Mode${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if .env exists
if [ ! -f ".env" ]; then
    echo -e "${RED}❌ .env file not found${NC}"
    echo ""
    echo "Create .env file with your AWS credentials:"
    echo "  cp .env.example .env"
    echo "  # Edit .env with your values"
    exit 1
fi

# Load environment variables
echo "📥 Loading configuration..."
export $(grep -v '^#' .env | xargs)

# Validate required variables
if [ -z "$SAGEMAKER_ENDPOINT" ]; then
    echo -e "${RED}❌ SAGEMAKER_ENDPOINT not set in .env${NC}"
    exit 1
fi

if [ -z "$AWS_ACCESS_KEY_ID" ]; then
    echo -e "${YELLOW}⚠️  AWS_ACCESS_KEY_ID not set - using default credentials${NC}"
fi

# Target repository
TARGET_REPO="${1:-.}"
if [ ! -d "$TARGET_REPO" ]; then
    echo -e "${RED}❌ Target repository not found: $TARGET_REPO${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Configuration loaded${NC}"
echo "   Endpoint: $SAGEMAKER_ENDPOINT"
echo "   Region: ${AWS_REGION:-us-east-1}"
echo "   Target: $TARGET_REPO"
echo ""

# Test SageMaker endpoint
echo "🔍 Testing SageMaker endpoint..."
python3 scripts/providers/sagemaker_foundation_sec.py
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Endpoint test failed${NC}"
    exit 1
fi
echo ""

# Run hybrid analyzer
echo "🎯 Starting AI-Enriched Security Scan..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cd "$TARGET_REPO"
python3 /Users/waseem.ahmed/Repos/argus/scripts/hybrid_analyzer.py . \
    --enable-semgrep \
    --enable-trivy \
    --enable-foundation-sec \
    --severity-filter critical,high,medium \
    --output-dir .argus/sagemaker-scan \
    2>&1 | tee .argus/sagemaker-scan.log

# Check results
if [ -f ".argus/sagemaker-scan/summary.json" ]; then
    echo ""
    echo -e "${GREEN}✅ Scan complete!${NC}"
    echo ""
    echo "📊 Results:"
    python3 -c "
import json
with open('.argus/sagemaker-scan/summary.json') as f:
    data = json.load(f)
    print(f'   Total findings: {data.get(\"total_findings\", 0)}')
    print(f'   Critical: {data.get(\"critical\", 0)}')
    print(f'   High: {data.get(\"high\", 0)}')
    print(f'   Medium: {data.get(\"medium\", 0)}')
    print(f'   AI enriched: {data.get(\"ai_enriched\", 0)}')
"
    echo ""
    echo "📁 Full report: .argus/sagemaker-scan/"
else
    echo -e "${RED}❌ Scan failed - no results generated${NC}"
    exit 1
fi








