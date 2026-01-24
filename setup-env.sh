#!/bin/bash
# Setup script to securely configure environment variables for argus

set -e

echo "🔐 Argus Environment Setup"
echo "=============================="
echo ""

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "✅ Created .env file"
    echo ""
    echo "⚠️  Please edit .env and add your API keys:"
    echo "    nano .env"
    echo "    # or"
    echo "    code .env"
    echo ""
    exit 0
fi

# Load .env file
echo "📂 Loading environment variables from .env..."
export $(cat .env | grep -v '^#' | grep -v '^$' | xargs)

# Validate required keys
if [ -z "$ANTHROPIC_API_KEY" ] || [ "$ANTHROPIC_API_KEY" = "your_api_key_here" ]; then
    echo "❌ ANTHROPIC_API_KEY is not set in .env"
    echo "   Please edit .env and add your Anthropic API key"
    echo "   Get it from: https://console.anthropic.com/settings/keys"
    exit 1
fi

echo "✅ ANTHROPIC_API_KEY is set (${#ANTHROPIC_API_KEY} chars)"

# Optional: Check if OpenAI key is set
if [ -n "$OPENAI_API_KEY" ] && [ "$OPENAI_API_KEY" != "your_openai_key_here" ]; then
    echo "✅ OPENAI_API_KEY is set (${#OPENAI_API_KEY} chars)"
fi

echo ""
echo "✅ Environment configured successfully!"
echo ""
echo "To use these variables in your current shell, run:"
echo "    source setup-env.sh"
echo "    # or"
echo "    export \$(cat .env | grep -v '^#' | grep -v '^\$' | xargs)"
