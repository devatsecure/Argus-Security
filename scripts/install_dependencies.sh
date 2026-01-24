#!/bin/bash
# Argus Security Action - Dependency Installation Script
# Version: 1.1.0
# Updated: 2026-01-15
#
# This script automates the installation of all required dependencies for Argus
# Supports: macOS, Linux (Ubuntu/Debian, RHEL/CentOS)
#
# Usage:
#   ./scripts/install_dependencies.sh [OPTIONS]
#
# Options:
#   --skip-python     Skip Python dependency installation
#   --skip-tools      Skip external tool installation
#   --skip-optional   Skip optional tools (nuclei, falco, opa)
#   --dry-run         Show what would be installed without installing
#   -h, --help        Show this help message

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SKIP_PYTHON=false
SKIP_TOOLS=false
SKIP_OPTIONAL=false
DRY_RUN=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-python)
            SKIP_PYTHON=true
            shift
            ;;
        --skip-tools)
            SKIP_TOOLS=true
            shift
            ;;
        --skip-optional)
            SKIP_OPTIONAL=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            echo "Argus Security Action - Dependency Installation"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-python     Skip Python dependency installation"
            echo "  --skip-tools      Skip external tool installation"
            echo "  --skip-optional   Skip optional tools (nuclei, falco, opa)"
            echo "  --dry-run         Show what would be installed without installing"
            echo "  -h, --help        Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Helper functions
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

run_cmd() {
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}[DRY RUN]${NC} Would execute: $*"
    else
        "$@"
    fi
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        info "Detected macOS"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            if [[ "$ID" == "ubuntu" ]] || [[ "$ID" == "debian" ]]; then
                OS="ubuntu"
                info "Detected Ubuntu/Debian Linux"
            elif [[ "$ID" == "rhel" ]] || [[ "$ID" == "centos" ]] || [[ "$ID" == "fedora" ]]; then
                OS="rhel"
                info "Detected RHEL/CentOS/Fedora Linux"
            else
                OS="linux"
                info "Detected Generic Linux"
            fi
        else
            OS="linux"
            info "Detected Generic Linux"
        fi
    else
        error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install Python dependencies
install_python_deps() {
    if [ "$SKIP_PYTHON" = true ]; then
        warning "Skipping Python dependencies"
        return
    fi

    info "Installing Python dependencies..."

    # Check if pip is available
    if ! command_exists pip && ! command_exists pip3; then
        error "pip not found. Please install Python 3.9+ and pip first."
        exit 1
    fi

    # Use pip3 if available, otherwise pip
    PIP_CMD="pip3"
    if ! command_exists pip3; then
        PIP_CMD="pip"
    fi

    # Upgrade pip
    info "Upgrading pip..."
    run_cmd $PIP_CMD install --upgrade pip

    # Install requirements
    info "Installing production dependencies..."
    run_cmd $PIP_CMD install -r requirements.txt

    info "Installing development dependencies..."
    run_cmd $PIP_CMD install -r requirements-dev.txt

    success "Python dependencies installed"
}

# Install Homebrew (macOS)
install_homebrew() {
    if command_exists brew; then
        info "Homebrew already installed"
        return
    fi

    info "Installing Homebrew..."
    run_cmd /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    success "Homebrew installed"
}

# Install external tools - macOS
install_tools_macos() {
    if [ "$SKIP_TOOLS" = true ]; then
        warning "Skipping external tools"
        return
    fi

    info "Installing security tools for macOS..."

    # Ensure Homebrew is installed
    install_homebrew

    # Core tools
    info "Installing core security scanners..."

    if ! command_exists semgrep; then
        run_cmd brew install semgrep
    else
        info "semgrep already installed"
    fi

    if ! command_exists trivy; then
        run_cmd brew install trivy
    else
        info "trivy already installed"
    fi

    if ! command_exists trufflehog; then
        run_cmd brew install trufflehog
    else
        info "trufflehog already installed"
    fi

    if ! command_exists gitleaks; then
        run_cmd brew install gitleaks
    else
        info "gitleaks already installed"
    fi

    if ! command_exists checkov; then
        run_cmd brew install checkov
    else
        info "checkov already installed"
    fi

    if ! command_exists docker; then
        run_cmd brew install --cask docker
        warning "Docker Desktop installed. Please start Docker Desktop manually."
    else
        info "docker already installed"
    fi

    # Optional tools
    if [ "$SKIP_OPTIONAL" = false ]; then
        info "Installing optional security tools..."

        if ! command_exists nuclei; then
            run_cmd brew install nuclei
        else
            info "nuclei already installed"
        fi

        if ! command_exists opa; then
            run_cmd brew install opa
        else
            info "opa already installed"
        fi

        if ! command_exists falco; then
            warning "falco: Limited support on macOS. Consider using Docker instead."
        fi
    fi

    success "macOS tools installed"
}

# Install external tools - Ubuntu/Debian
install_tools_ubuntu() {
    if [ "$SKIP_TOOLS" = true ]; then
        warning "Skipping external tools"
        return
    fi

    info "Installing security tools for Ubuntu/Debian..."

    # Update package list
    info "Updating package list..."
    run_cmd sudo apt-get update

    # Install core dependencies
    info "Installing core dependencies..."
    run_cmd sudo apt-get install -y curl wget apt-transport-https gnupg lsb-release ca-certificates

    # Semgrep (via pip)
    if ! command_exists semgrep; then
        info "Installing semgrep..."
        run_cmd pip3 install semgrep
    else
        info "semgrep already installed"
    fi

    # Trivy
    if ! command_exists trivy; then
        info "Installing trivy..."
        run_cmd wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
        run_cmd echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
        run_cmd sudo apt-get update
        run_cmd sudo apt-get install -y trivy
    else
        info "trivy already installed"
    fi

    # TruffleHog
    if ! command_exists trufflehog; then
        info "Installing trufflehog..."
        run_cmd curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin
    else
        info "trufflehog already installed"
    fi

    # Gitleaks
    if ! command_exists gitleaks; then
        info "Installing gitleaks..."
        GITLEAKS_VERSION="8.18.0"
        run_cmd wget "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
        run_cmd tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
        run_cmd sudo mv gitleaks /usr/local/bin/
        run_cmd rm "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
    else
        info "gitleaks already installed"
    fi

    # Checkov
    if ! command_exists checkov; then
        info "Installing checkov..."
        run_cmd pip3 install checkov
    else
        info "checkov already installed"
    fi

    # Docker
    if ! command_exists docker; then
        info "Installing Docker..."
        run_cmd curl -fsSL https://get.docker.com -o get-docker.sh
        run_cmd sudo sh get-docker.sh
        run_cmd sudo usermod -aG docker "$USER"
        run_cmd rm get-docker.sh
        warning "Docker installed. You may need to log out and back in for group changes to take effect."
    else
        info "docker already installed"
    fi

    # Optional tools
    if [ "$SKIP_OPTIONAL" = false ]; then
        info "Installing optional security tools..."

        # Nuclei
        if ! command_exists nuclei; then
            info "Installing nuclei..."
            NUCLEI_VERSION="3.6.0"
            run_cmd wget "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
            run_cmd unzip "nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
            run_cmd sudo mv nuclei /usr/local/bin/
            run_cmd rm "nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
        else
            info "nuclei already installed"
        fi

        # OPA
        if ! command_exists opa; then
            info "Installing OPA..."
            run_cmd curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
            run_cmd chmod 755 ./opa
            run_cmd sudo mv opa /usr/local/bin/
        else
            info "opa already installed"
        fi

        # Falco
        if ! command_exists falco; then
            info "Installing Falco..."
            run_cmd curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | sudo apt-key add -
            run_cmd echo "deb https://download.falco.org/packages/deb stable main" | sudo tee -a /etc/apt/sources.list.d/falcosecurity.list
            run_cmd sudo apt-get update -y
            run_cmd sudo apt-get install -y falco
        else
            info "falco already installed"
        fi
    fi

    success "Ubuntu/Debian tools installed"
}

# Install external tools - RHEL/CentOS
install_tools_rhel() {
    if [ "$SKIP_TOOLS" = true ]; then
        warning "Skipping external tools"
        return
    fi

    info "Installing security tools for RHEL/CentOS..."

    # Install core dependencies
    info "Installing core dependencies..."
    run_cmd sudo yum install -y curl wget

    # Semgrep (via pip)
    if ! command_exists semgrep; then
        info "Installing semgrep..."
        run_cmd pip3 install semgrep
    else
        info "semgrep already installed"
    fi

    # Trivy
    if ! command_exists trivy; then
        info "Installing trivy..."
        TRIVY_VERSION="0.48.0"
        run_cmd wget "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
        run_cmd tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
        run_cmd sudo mv trivy /usr/local/bin/
        run_cmd rm "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
    else
        info "trivy already installed"
    fi

    # TruffleHog
    if ! command_exists trufflehog; then
        info "Installing trufflehog..."
        run_cmd curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin
    else
        info "trufflehog already installed"
    fi

    # Gitleaks
    if ! command_exists gitleaks; then
        info "Installing gitleaks..."
        GITLEAKS_VERSION="8.18.0"
        run_cmd wget "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
        run_cmd tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
        run_cmd sudo mv gitleaks /usr/local/bin/
        run_cmd rm "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
    else
        info "gitleaks already installed"
    fi

    # Checkov
    if ! command_exists checkov; then
        info "Installing checkov..."
        run_cmd pip3 install checkov
    else
        info "checkov already installed"
    fi

    # Docker
    if ! command_exists docker; then
        info "Installing Docker..."
        run_cmd curl -fsSL https://get.docker.com -o get-docker.sh
        run_cmd sudo sh get-docker.sh
        run_cmd sudo usermod -aG docker "$USER"
        run_cmd rm get-docker.sh
        warning "Docker installed. You may need to log out and back in for group changes to take effect."
    else
        info "docker already installed"
    fi

    # Optional tools
    if [ "$SKIP_OPTIONAL" = false ]; then
        info "Installing optional security tools..."

        # Nuclei
        if ! command_exists nuclei; then
            info "Installing nuclei..."
            NUCLEI_VERSION="3.6.0"
            run_cmd wget "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
            run_cmd unzip "nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
            run_cmd sudo mv nuclei /usr/local/bin/
            run_cmd rm "nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
        else
            info "nuclei already installed"
        fi

        # OPA
        if ! command_exists opa; then
            info "Installing OPA..."
            run_cmd curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
            run_cmd chmod 755 ./opa
            run_cmd sudo mv opa /usr/local/bin/
        else
            info "opa already installed"
        fi

        # Falco (RHEL/CentOS)
        if ! command_exists falco; then
            warning "Falco installation on RHEL/CentOS requires manual setup. See: https://falco.org/docs/"
        fi
    fi

    success "RHEL/CentOS tools installed"
}

# Main installation flow
main() {
    echo "================================================================================"
    echo "Argus Security Action - Dependency Installation"
    echo "================================================================================"
    echo ""

    # Detect OS
    detect_os

    echo ""
    echo "Installation Options:"
    echo "  Skip Python:   $SKIP_PYTHON"
    echo "  Skip Tools:    $SKIP_TOOLS"
    echo "  Skip Optional: $SKIP_OPTIONAL"
    echo "  Dry Run:       $DRY_RUN"
    echo ""

    if [ "$DRY_RUN" = true ]; then
        warning "DRY RUN MODE - No changes will be made"
        echo ""
    fi

    # Install Python dependencies
    install_python_deps

    # Install external tools based on OS
    case $OS in
        macos)
            install_tools_macos
            ;;
        ubuntu)
            install_tools_ubuntu
            ;;
        rhel)
            install_tools_rhel
            ;;
        *)
            error "Tool installation not supported for OS: $OS"
            error "Please install tools manually. See: docs/INSTALLATION.md"
            exit 1
            ;;
    esac

    echo ""
    echo "================================================================================"
    echo "Installation Complete!"
    echo "================================================================================"
    echo ""

    if [ "$DRY_RUN" = false ]; then
        info "Running health check to verify installation..."
        echo ""

        if [ -f "scripts/health_check.py" ]; then
            python3 scripts/health_check.py
        else
            warning "Health check script not found. Skipping verification."
        fi
    fi

    echo ""
    success "All dependencies installed successfully!"
    echo ""
    echo "Next steps:"
    echo "  1. Set up API keys (ANTHROPIC_API_KEY or OPENAI_API_KEY)"
    echo "  2. Run: python scripts/health_check.py"
    echo "  3. Try: python scripts/run_ai_audit.py --help"
    echo ""
}

# Run main function
main
