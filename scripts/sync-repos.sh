#!/bin/bash
# Sync script for argus-action repository
# Usage: ./scripts/sync-repos.sh
#
# Note: argus is now a symbolic link to argus-action
# There is only ONE repository to sync.

set -e

REPO_DIR="/Users/waseem.ahmed/Repos/argus-action"

echo "🔄 Syncing argus-action repository..."

# Function to sync repo
sync_repo() {
    local dir=$1
    local name=$2

    echo ""
    echo "📂 Syncing $name..."
    cd "$dir"

    # Fetch latest from remote
    git fetch origin

    # Check for uncommitted changes
    if ! git diff-index --quiet HEAD --; then
        echo "⚠️  Warning: $name has uncommitted changes"
        git status --short
        return 1
    fi

    # Check if behind remote
    LOCAL=$(git rev-parse @)
    REMOTE=$(git rev-parse @{u})

    if [ "$LOCAL" != "$REMOTE" ]; then
        echo "⬇️  Pulling latest from origin/main..."
        git reset --hard origin/main
        echo "✅ $name synced to $(git rev-parse --short HEAD)"
    else
        echo "✅ $name already up to date ($(git rev-parse --short HEAD))"
    fi
}

# Sync repository
sync_repo "$REPO_DIR" "argus-action"

echo ""
echo "✅ Sync complete!"
echo ""
echo "💡 Note: /Users/waseem.ahmed/Repos/argus is a symlink to argus-action"
