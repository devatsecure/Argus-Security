#!/bin/bash

# Argus Security - Global Installation Script
# Installs the security platform globally for use across all repositories

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Function to show usage
show_usage() {
    echo "Argus Security - Global Installation"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --argus-path PATH       Path to Argus base installation (default: ~/.argus)"
    echo "  --install-path PATH     Path to install global script (default: ~/.local/bin)"
    echo "  --help                  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Install with defaults"
    echo "  $0 --argus-path /custom/path          # Custom Argus path"
    echo "  $0 --install-path /usr/local/bin      # Custom install path"
}

# Default values
ARGUS_PATH="$HOME/.argus"
INSTALL_PATH="$HOME/.local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --argus-path)
            ARGUS_PATH="$2"
            shift 2
            ;;
        --install-path)
            INSTALL_PATH="$2"
            shift 2
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

print_info "Installing Argus Security globally..."

# Create directories if they don't exist
mkdir -p "$ARGUS_PATH/profiles/default/agents"
mkdir -p "$ARGUS_PATH/profiles/default/workflows"
mkdir -p "$ARGUS_PATH/profiles/default/standards"
mkdir -p "$ARGUS_PATH/profiles/default/commands"
mkdir -p "$ARGUS_PATH/profiles/default/roles"
mkdir -p "$INSTALL_PATH"

print_info "Copying Argus Security to base installation..."

# Copy agents
if [ -d "$SCRIPT_DIR/profiles/default/agents" ]; then
    cp -r "$SCRIPT_DIR/profiles/default/agents"/* "$ARGUS_PATH/profiles/default/agents/"
    print_status "Agents copied successfully"
fi

# Copy workflows
if [ -d "$SCRIPT_DIR/profiles/default/workflows/review" ]; then
    mkdir -p "$ARGUS_PATH/profiles/default/workflows"
    cp -r "$SCRIPT_DIR/profiles/default/workflows/review" "$ARGUS_PATH/profiles/default/workflows/"
    print_status "Workflows copied successfully"
fi

# Copy standards
if [ -d "$SCRIPT_DIR/profiles/default/standards/review" ]; then
    mkdir -p "$ARGUS_PATH/profiles/default/standards"
    cp -r "$SCRIPT_DIR/profiles/default/standards/review" "$ARGUS_PATH/profiles/default/standards/"
    print_status "Standards copied successfully"
fi

# Copy commands
if [ -d "$SCRIPT_DIR/profiles/default/commands" ]; then
    cp -r "$SCRIPT_DIR/profiles/default/commands/audit-codebase" "$ARGUS_PATH/profiles/default/commands/" 2>/dev/null || true
    cp -r "$SCRIPT_DIR/profiles/default/commands/review-changes" "$ARGUS_PATH/profiles/default/commands/" 2>/dev/null || true
    cp -r "$SCRIPT_DIR/profiles/default/commands/security-scan" "$ARGUS_PATH/profiles/default/commands/" 2>/dev/null || true
    print_status "Commands copied successfully"
fi

# Copy roles
if [ -f "$SCRIPT_DIR/profiles/default/roles/reviewers.yml" ]; then
    cp "$SCRIPT_DIR/profiles/default/roles/reviewers.yml" "$ARGUS_PATH/profiles/default/roles/"
    print_status "Roles copied successfully"
fi

# Create global wrapper script
print_info "Creating global wrapper script..."

cat > "$INSTALL_PATH/argus-scan" << 'EOF'
#!/bin/bash

# Argus Security - Global Scanner
# Usage: argus-scan [audit|security|review] [project-path]

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}✅ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }

show_usage() {
    echo "Argus Security - Global Scanner"
    echo ""
    echo "Usage: argus-scan [COMMAND] [PROJECT_PATH]"
    echo ""
    echo "Commands:"
    echo "  audit        - Run full codebase audit (6-phase pipeline)"
    echo "  security     - Run quick security scan"
    echo "  review       - Review specific changes"
    echo "  help         - Show this help message"
    echo ""
    echo "Examples:"
    echo "  argus-scan audit                    # Audit current directory"
    echo "  argus-scan security /path/to/repo   # Security scan specific repo"
    echo "  argus-scan review                   # Review changes in current dir"
    echo ""
    echo "Global installation path: ~/.argus"
}

PROJECT_PATH="${2:-$(pwd)}"

if [ ! -d "$PROJECT_PATH" ]; then
    print_error "Project path does not exist: $PROJECT_PATH"
    exit 1
fi

cd "$PROJECT_PATH"
print_info "Project path: $PROJECT_PATH"

case "${1:-help}" in
    "audit")
        print_info "Running full 6-phase security audit..."
        mkdir -p .argus/reviews
        python scripts/run_ai_audit.py --project-type backend-api 2>/dev/null || \
            print_warning "Run from Argus Security installation directory"
        ;;
    "security")
        print_info "Running quick security scan..."
        mkdir -p .argus/reviews
        python scripts/run_ai_audit.py --project-type backend-api --quick 2>/dev/null || \
            print_warning "Run from Argus Security installation directory"
        ;;
    "review")
        print_info "Running code review..."
        mkdir -p .argus/reviews
        python scripts/run_ai_audit.py --only-changed 2>/dev/null || \
            print_warning "Run from Argus Security installation directory"
        ;;
    "help"|*)
        show_usage
        ;;
esac
EOF

chmod +x "$INSTALL_PATH/argus-scan"
print_status "Global wrapper script created at $INSTALL_PATH/argus-scan"

# Add to PATH if not already there
if [[ ":$PATH:" != *":$INSTALL_PATH:"* ]]; then
    print_warning "Adding $INSTALL_PATH to PATH..."
    echo "export PATH=\"$INSTALL_PATH:\$PATH\"" >> "$HOME/.bashrc"
    echo "export PATH=\"$INSTALL_PATH:\$PATH\"" >> "$HOME/.zshrc"
    print_info "Please restart your shell or run: source ~/.bashrc"
fi

print_status "Argus Security installed successfully!"
echo ""
print_info "Usage:"
echo "  argus-scan audit                    # Audit current directory"
echo "  argus-scan security /path/to/repo   # Security scan specific repo"
echo "  argus-scan review                   # Review changes in current dir"
echo "  argus-scan help                     # Show help"
echo ""
print_info "Installation locations:"
echo "  Argus base: $ARGUS_PATH"
echo "  Global script: $INSTALL_PATH/argus-scan"
echo ""
print_info "Ready to use from any repository! 🚀"
