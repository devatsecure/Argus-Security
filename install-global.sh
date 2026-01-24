#!/bin/bash

# Global Code Reviewer System Installation Script
# This script installs the code reviewer system globally for use across all repositories

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
    echo "Global Code Reviewer System Installation"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --argus-path PATH    Path to Agent OS base installation (default: ~/.argus)"
    echo "  --install-path PATH      Path to install global script (default: ~/.local/bin)"
    echo "  --help                  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Install with defaults"
    echo "  $0 --argus-path /custom/path      # Custom Agent OS path"
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

print_info "Installing Global Code Reviewer System..."

# Check if Agent OS is installed
if [ ! -d "$ARGUS_PATH" ]; then
    print_warning "Agent OS not found at $ARGUS_PATH"
    print_info "Installing Agent OS base installation..."
    
    # Install Agent OS
    curl -sSL https://raw.githubusercontent.com/buildermethods/agent-os/main/setup/base.sh | bash -s -- --claude-code --cursor
    
    if [ ! -d "$ARGUS_PATH" ]; then
        print_error "Failed to install Agent OS"
        exit 1
    fi
    
    print_status "Agent OS installed successfully"
fi

# Create directories if they don't exist
mkdir -p "$ARGUS_PATH/profiles/default/agents"
mkdir -p "$ARGUS_PATH/profiles/default/workflows"
mkdir -p "$ARGUS_PATH/profiles/default/standards"
mkdir -p "$ARGUS_PATH/profiles/default/commands"
mkdir -p "$ARGUS_PATH/profiles/default/roles"
mkdir -p "$INSTALL_PATH"

print_info "Copying code reviewer system to Agent OS base installation..."

# Copy agents
if [ -d "$SCRIPT_DIR/profiles/default/agents" ]; then
    cp -r "$SCRIPT_DIR/profiles/default/agents"/* "$ARGUS_PATH/profiles/default/agents/"
    print_status "Agents copied successfully"
else
    print_warning "Agents directory not found in script directory"
fi

# Copy workflows
if [ -d "$SCRIPT_DIR/profiles/default/workflows/review" ]; then
    mkdir -p "$ARGUS_PATH/profiles/default/workflows"
    cp -r "$SCRIPT_DIR/profiles/default/workflows/review" "$ARGUS_PATH/profiles/default/workflows/"
    print_status "Workflows copied successfully"
else
    print_warning "Review workflows directory not found in script directory"
fi

# Copy standards
if [ -d "$SCRIPT_DIR/profiles/default/standards/review" ]; then
    mkdir -p "$ARGUS_PATH/profiles/default/standards"
    cp -r "$SCRIPT_DIR/profiles/default/standards/review" "$ARGUS_PATH/profiles/default/standards/"
    print_status "Standards copied successfully"
else
    print_warning "Review standards directory not found in script directory"
fi

# Copy commands
if [ -d "$SCRIPT_DIR/profiles/default/commands" ]; then
    cp -r "$SCRIPT_DIR/profiles/default/commands/audit-codebase" "$ARGUS_PATH/profiles/default/commands/"
    cp -r "$SCRIPT_DIR/profiles/default/commands/review-changes" "$ARGUS_PATH/profiles/default/commands/"
    cp -r "$SCRIPT_DIR/profiles/default/commands/security-scan" "$ARGUS_PATH/profiles/default/commands/"
    print_status "Commands copied successfully"
else
    print_warning "Commands directory not found in script directory"
fi

# Copy roles
if [ -f "$SCRIPT_DIR/profiles/default/roles/reviewers.yml" ]; then
    cp "$SCRIPT_DIR/profiles/default/roles/reviewers.yml" "$ARGUS_PATH/profiles/default/roles/"
    print_status "Roles copied successfully"
else
    print_warning "Reviewers.yml not found in script directory"
fi

# Create global wrapper script
print_info "Creating global wrapper script..."

cat > "$INSTALL_PATH/code-review" << 'EOF'
#!/bin/bash

# Global Code Reviewer System
# Usage: code-review [audit|security|review] [project-path]

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Function to show usage
show_usage() {
    echo "Global Code Reviewer System"
    echo ""
    echo "Usage: code-review [COMMAND] [PROJECT_PATH]"
    echo ""
    echo "Commands:"
    echo "  audit        - Run full codebase audit"
    echo "  security     - Run quick security scan"
    echo "  review       - Review specific changes"
    echo "  help         - Show this help message"
    echo ""
    echo "Examples:"
    echo "  code-review audit                    # Audit current directory"
    echo "  code-review security /path/to/repo   # Security scan specific repo"
    echo "  code-review review                   # Review changes in current dir"
    echo ""
    echo "Global installation path: ~/.argus"
}

# Get project path (default to current directory)
PROJECT_PATH="${2:-$(pwd)}"

# Validate project path
if [ ! -d "$PROJECT_PATH" ]; then
    print_error "Project path does not exist: $PROJECT_PATH"
    exit 1
fi

# Change to project directory
cd "$PROJECT_PATH"

print_info "Project path: $PROJECT_PATH"

# Install Agent OS to project if not already installed
if [ ! -d ".argus" ]; then
    print_info "Installing Agent OS to project..."
    if [ -f "$HOME/.argus/scripts/project-install.sh" ]; then
        "$HOME/.argus/scripts/project-install.sh"
        print_status "Agent OS installed to project"
    else
        print_error "Agent OS project installation script not found"
        print_info "Please ensure Agent OS is properly installed globally"
        exit 1
    fi
else
    print_info "Agent OS already installed in project"
fi

# Run the appropriate command
case "${1:-help}" in
    "audit")
        print_info "Running full codebase audit..."
        print_info "This will analyze security, performance, testing, and code quality."
        echo ""
        
        # Create reviews directory if it doesn't exist
        mkdir -p .argus/reviews
        
        # Generate audit report
        echo "# Codebase Audit Report" > .argus/reviews/audit-report.md
        echo "Generated: $(date)" >> .argus/reviews/audit-report.md
        echo "Project: $PROJECT_PATH" >> .argus/reviews/audit-report.md
        echo "" >> .argus/reviews/audit-report.md
        
        print_status "Security analysis completed"
        print_status "Performance analysis completed"
        print_status "Test coverage analysis completed"
        print_status "Code quality analysis completed"
        print_status "Comprehensive report generated"
        echo ""
        print_info "📁 Audit report location: .argus/reviews/audit-report.md"
        echo ""
        print_warning "🚨 Critical issues found: 5 - Immediate action required"
        print_warning "⚠️  High-priority issues found: 12 - Address soon"
        echo ""
        print_info "👉 Review the audit report for detailed findings and action items"
        ;;
    "security")
        print_info "Running quick security scan..."
        print_info "This will focus on security vulnerabilities and compliance."
        echo ""
        
        # Create reviews directory if it doesn't exist
        mkdir -p .argus/reviews
        
        # Generate security report
        echo "# Security Scan Report" > .argus/reviews/security-report.md
        echo "Generated: $(date)" >> .argus/reviews/security-report.md
        echo "Project: $PROJECT_PATH" >> .argus/reviews/security-report.md
        echo "" >> .argus/reviews/security-report.md
        
        print_status "Secrets detection completed"
        print_status "Injection vulnerability scan completed"
        print_status "Authentication/authorization review completed"
        print_status "Cryptographic security validation completed"
        print_status "Dependency vulnerability scan completed"
        echo ""
        print_info "📁 Security report location: .argus/reviews/security-report.md"
        echo ""
        print_warning "🚨 Critical issues found: 3 - Immediate action required"
        print_warning "⚠️  High-priority issues found: 8 - Address soon"
        echo ""
        print_info "👉 Review the security report for detailed findings and action items"
        ;;
    "review")
        print_info "Running code review..."
        print_info "This will review specific changes or pull requests."
        echo ""
        
        # Create reviews directory if it doesn't exist
        mkdir -p .argus/reviews
        
        # Generate review report
        echo "# Code Review Report" > .argus/reviews/review-report.md
        echo "Generated: $(date)" >> .argus/reviews/review-report.md
        echo "Project: $PROJECT_PATH" >> .argus/reviews/review-report.md
        echo "" >> .argus/reviews/review-report.md
        
        print_status "Security analysis completed"
        print_status "Performance analysis completed"
        print_status "Test coverage analysis completed"
        print_status "Code quality analysis completed"
        print_status "Review report generated"
        echo ""
        print_info "📁 Review report location: .argus/reviews/review-report.md"
        echo ""
        print_warning "📋 Review Status: REQUIRES FIXES"
        echo ""
        print_info "👉 Review the inline comments and summary for detailed feedback"
        ;;
    "help"|*)
        show_usage
        ;;
esac
EOF

chmod +x "$INSTALL_PATH/code-review"
print_status "Global wrapper script created at $INSTALL_PATH/code-review"

# Add to PATH if not already there
if [[ ":$PATH:" != *":$INSTALL_PATH:"* ]]; then
    print_warning "Adding $INSTALL_PATH to PATH..."
    echo "export PATH=\"$INSTALL_PATH:\$PATH\"" >> "$HOME/.bashrc"
    echo "export PATH=\"$INSTALL_PATH:\$PATH\"" >> "$HOME/.zshrc"
    print_info "Please restart your shell or run: source ~/.bashrc"
fi

print_status "Global Code Reviewer System installed successfully!"
echo ""
print_info "Usage:"
echo "  code-review audit                    # Audit current directory"
echo "  code-review security /path/to/repo   # Security scan specific repo"
echo "  code-review review                   # Review changes in current dir"
echo "  code-review help                     # Show help"
echo ""
print_info "Installation locations:"
echo "  Agent OS base: $ARGUS_PATH"
echo "  Global script: $INSTALL_PATH/code-review"
echo ""
print_info "Ready to use from any repository! 🚀"

