#!/bin/bash
# Run all feedback loop examples and tests

echo "=================================================="
echo "Feedback Loop System - Example Runner"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 1. Run tests
echo -e "${BLUE}[1/5] Running test suite...${NC}"
python -m pytest tests/test_feedback_loop.py -v --cov=scripts/feedback_loop.py
echo ""

# 2. Test CLI - stats
echo -e "${BLUE}[2/5] Testing CLI - stats${NC}"
python scripts/feedback_cli.py stats
echo ""

# 3. Test CLI - record
echo -e "${BLUE}[3/5] Testing CLI - record verdict${NC}"
python scripts/feedback_cli.py record \
  --finding-id "example-001" \
  --automated "false_positive" \
  --human "false_positive" \
  --confidence 0.85 \
  --pattern "oauth2_localhost_pattern" \
  --category "oauth2" \
  --reasoning "Example verdict"
echo ""

# 4. Test CLI - stats again
echo -e "${BLUE}[4/5] Testing CLI - stats (with data)${NC}"
python scripts/feedback_cli.py stats
echo ""

# 5. Run integration examples
echo -e "${BLUE}[5/5] Running integration examples...${NC}"
python scripts/feedback_integration_example.py
echo ""

# Clean up test data
echo -e "${BLUE}Cleaning up test data...${NC}"
rm -rf .argus/feedback
echo ""

echo -e "${GREEN}=================================================="
echo "All examples completed successfully!"
echo "==================================================${NC}"
echo ""
echo "Next steps:"
echo "1. Read: FEEDBACK_LOOP_IMPLEMENTATION.md"
echo "2. Read: docs/FEEDBACK_LOOP_QUICK_START.md"
echo "3. Integrate with Enhanced FP Detector"
echo "4. Start recording real verdicts"
echo ""
