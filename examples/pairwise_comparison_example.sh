#!/bin/bash
# Example: Running Pairwise Comparison Analysis
# This script demonstrates how to use the pairwise comparison tool

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}Pairwise Comparison Example${NC}"
echo -e "${BLUE}================================${NC}\n"

# Configuration
REPO_PATH="${1:-.}"
PROJECT_TYPE="${2:-backend-api}"
OUTPUT_DIR="${REPO_PATH}/.argus/pairwise-comparison"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
REPORT_DIR="${OUTPUT_DIR}/${TIMESTAMP}"

echo -e "${GREEN}Configuration:${NC}"
echo "  Repository: $REPO_PATH"
echo "  Project Type: $PROJECT_TYPE"
echo "  Output: $REPORT_DIR"
echo ""

# Create output directory
mkdir -p "${REPORT_DIR}"

# Step 1: Run dual audit (if not already done)
ARGUS_FINDINGS="${REPO_PATH}/.argus/dual-audit/*/argus_results.json"
CODEX_FINDINGS="${REPO_PATH}/.argus/dual-audit/*/codex_validation.json"

# Find latest dual audit results
LATEST_DUAL_AUDIT=$(find "${REPO_PATH}/.argus/dual-audit" -type d -maxdepth 1 | sort | tail -1)

if [ -z "$LATEST_DUAL_AUDIT" ] || [ "$LATEST_DUAL_AUDIT" = "${REPO_PATH}/.argus/dual-audit" ]; then
    echo -e "${BLUE}Step 1: Running Dual Audit${NC}"
    python scripts/dual_audit.py "$REPO_PATH" --project-type "$PROJECT_TYPE"
    echo -e "${GREEN}✅ Dual audit completed${NC}\n"

    LATEST_DUAL_AUDIT=$(find "${REPO_PATH}/.argus/dual-audit" -type d -maxdepth 1 | sort | tail -1)
fi

ARGUS_FINDINGS="${LATEST_DUAL_AUDIT}/argus_results.json"
CODEX_FINDINGS="${LATEST_DUAL_AUDIT}/codex_validation.json"

if [ ! -f "$ARGUS_FINDINGS" ]; then
    echo -e "${RED}❌ Argus findings not found: $ARGUS_FINDINGS${NC}"
    exit 1
fi

echo -e "${BLUE}Step 2: Running Pairwise Comparison${NC}"
echo "  Argus findings: $ARGUS_FINDINGS"
echo "  Codex findings: $CODEX_FINDINGS"
echo ""

# Run pairwise comparison with Anthropic Claude as judge
python scripts/pairwise_comparison.py \
    --argus-findings "$ARGUS_FINDINGS" \
    --codex-findings "$CODEX_FINDINGS" \
    --output "${REPORT_DIR}/comparison_report.json" \
    --output-markdown "${REPORT_DIR}/comparison_report.md" \
    --judge-model anthropic \
    --match-threshold 0.7

echo -e "${GREEN}✅ Pairwise comparison completed${NC}\n"

# Display results summary
echo -e "${BLUE}Step 3: Displaying Results${NC}"
echo ""
echo -e "${GREEN}Report Files:${NC}"
echo "  JSON: ${REPORT_DIR}/comparison_report.json"
echo "  Markdown: ${REPORT_DIR}/comparison_report.md"
echo ""

# Extract and display key metrics
if [ -f "${REPORT_DIR}/comparison_report.json" ]; then
    echo -e "${GREEN}Key Metrics:${NC}"

    WINNER=$(jq -r '.aggregation.overall_winner' "${REPORT_DIR}/comparison_report.json")
    ARGUS_SCORE=$(jq -r '.aggregation.avg_argus_score' "${REPORT_DIR}/comparison_report.json")
    CODEX_SCORE=$(jq -r '.aggregation.avg_codex_score' "${REPORT_DIR}/comparison_report.json")
    MATCHED=$(jq -r '.aggregation.matched_findings' "${REPORT_DIR}/comparison_report.json")
    ARGUS_ONLY=$(jq -r '.aggregation.argus_only' "${REPORT_DIR}/comparison_report.json")
    CODEX_ONLY=$(jq -r '.aggregation.codex_only' "${REPORT_DIR}/comparison_report.json")

    echo "  Winner: ${WINNER^^}"
    echo "  Argus Average Score: $ARGUS_SCORE / 5"
    echo "  Codex Average Score: $CODEX_SCORE / 5"
    echo ""
    echo "  Matched Findings: $MATCHED"
    echo "  Argus Only: $ARGUS_ONLY"
    echo "  Codex Only: $CODEX_ONLY"
    echo ""
fi

# Display markdown report if available
if [ -f "${REPORT_DIR}/comparison_report.md" ]; then
    echo -e "${BLUE}Markdown Report Preview:${NC}"
    echo "---"
    head -50 "${REPORT_DIR}/comparison_report.md"
    echo "..."
    echo "---"
    echo ""
fi

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Analysis Complete!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "Next steps:"
echo "1. Review the detailed markdown report: ${REPORT_DIR}/comparison_report.md"
echo "2. Check for key differences between tools"
echo "3. Prioritize findings confirmed by both tools"
echo "4. Follow up on unique findings from each tool"
echo ""
