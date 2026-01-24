# Docker Testing Guide

This guide explains how to test the new Docker container and release workflows.

## 🐳 Testing the Dockerfile Locally

### Prerequisites
- Docker installed and running
- At least 2GB free disk space

### Build the Image

```bash
# Build for local testing
docker build -t argus-action:test .

# Build with build cache disabled (clean build)
docker build --no-cache -t argus-action:test .

# Build for specific platform
docker build --platform linux/amd64 -t argus-action:test .
docker build --platform linux/arm64 -t argus-action:test .
```

### Test the Container

```bash
# Test help command
docker run --rm argus-action:test --help

# Test on a sample repository
docker run --rm \
  -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  argus-action:test \
  /workspace audit

# Interactive shell for debugging
docker run --rm -it \
  -v $(pwd):/workspace \
  --entrypoint /bin/bash \
  argus-action:test

# Check image size
docker images argus-action:test
```

### Expected Results

- ✅ Image builds successfully
- ✅ Image size < 500MB
- ✅ Python and all dependencies installed
- ✅ Help command shows usage
- ✅ Can run audits on mounted directories

## 🚀 Testing Release Workflows

### Test Workflow Validation

```bash
# Validate YAML syntax
python -c "
import yaml
with open('.github/workflows/publish-container.yml', 'r') as f:
    yaml.safe_load(f)
print('✅ publish-container.yml is valid')
"

python -c "
import yaml
with open('.github/workflows/release.yml', 'r') as f:
    yaml.safe_load(f)
print('✅ release.yml is valid')
"
```

### Test Release Creation (Dry Run)

```bash
# Create a test tag locally (don't push yet)
git tag v0.0.1-test
git log --oneline v0.0.1-test | head -10

# Generate release notes locally
git log --pretty=format:"- %s (@%an)" --no-merges HEAD~10..HEAD > test-changelog.txt
cat test-changelog.txt

# Clean up test tag
git tag -d v0.0.1-test
```

### Trigger Real Release

```bash
# Create and push a new version tag
VERSION="1.0.16"  # Increment from current 1.0.15

git tag -a "v${VERSION}" -m "Release v${VERSION}"
git push origin "v${VERSION}"

# This will trigger:
# 1. .github/workflows/release.yml - Creates GitHub release
# 2. .github/workflows/publish-container.yml - Builds and pushes container
```

### Monitor Release Progress

```bash
# Watch workflow runs
gh run list --workflow=release.yml
gh run list --workflow=publish-container.yml

# View logs
gh run view --log

# Check release was created
gh release view v${VERSION}

# Verify container was published
gh api /user/packages/container/argus-action/versions
```

## 🔍 Testing Container Publishing

### Test Multi-Platform Build Locally

```bash
# Set up buildx for multi-platform
docker buildx create --name mybuilder --use
docker buildx inspect --bootstrap

# Build for multiple platforms (local only, no push)
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t argus-action:multi \
  .

# Build and push to local registry
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t localhost:5000/argus-action:test \
  --push \
  .
```

### Pull and Test Published Image

```bash
# After workflow completes, pull the image
docker pull ghcr.io/devatsecure/argus-action:latest

# Verify signature
cosign verify \
  --certificate-identity-regexp="https://github.com/devatsecure/argus-action" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/devatsecure/argus-action:latest

# Run the published image
docker run --rm \
  -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  ghcr.io/devatsecure/argus-action:latest \
  /workspace audit
```

## 📊 Workflow Verification Checklist

### Before Pushing Tag

- [ ] All tests passing on main branch
- [ ] Version bumped in pyproject.toml
- [ ] CHANGELOG.md updated (if exists)
- [ ] No uncommitted changes

### After Pushing Tag

- [ ] Release workflow completes successfully
- [ ] Container publishing workflow completes successfully
- [ ] GitHub Release created with correct notes
- [ ] Container images available in GHCR
- [ ] Both amd64 and arm64 images built
- [ ] SBOM generated and attached
- [ ] Image signed with cosign
- [ ] Trivy scan completed

### Testing Published Release

- [ ] Docker image pulls successfully
- [ ] Image signature verifies
- [ ] Container runs successfully
- [ ] Help command works
- [ ] Can analyze repositories
- [ ] Size reasonable (<500MB)

## 🐛 Troubleshooting

### Image Build Fails

```bash
# Check for syntax errors in Dockerfile
docker build --progress=plain -t argus-action:test . 2>&1 | grep -i error

# Build with verbose output
docker build --progress=plain --no-cache -t argus-action:test .
```

### Workflow Fails

```bash
# View detailed logs
gh run view <run-id> --log

# Check for common issues
# - Missing secrets (ANTHROPIC_API_KEY, GITHUB_TOKEN)
# - Insufficient permissions
# - Network/registry issues
# - Invalid YAML syntax
```

### Container Won't Run

```bash
# Check container logs
docker logs <container-id>

# Debug interactively
docker run -it --entrypoint /bin/bash argus-action:test

# Check Python installation
docker run --rm argus-action:test python --version

# Check installed packages
docker run --rm argus-action:test pip list
```

## 📈 Performance Testing

### Measure Build Times

```bash
# Time a clean build
time docker build --no-cache -t argus-action:test .

# Time an incremental build
time docker build -t argus-action:test .
```

### Measure Image Size

```bash
# Check image size
docker images argus-action:test

# Analyze layers
docker history argus-action:test

# Use dive for detailed analysis
dive argus-action:test
```

### Expected Performance

- **Build Time (cold)**: ~3-5 minutes
- **Build Time (cached)**: ~30 seconds
- **Image Size**: ~300-400MB
- **Startup Time**: <2 seconds
- **Memory Usage**: ~200-500MB during analysis

## 🎯 Success Metrics

A successful release should have:

1. ✅ Clean workflow run (all jobs green)
2. ✅ Release created with detailed notes
3. ✅ Multi-platform images available
4. ✅ SBOM and provenance attached
5. ✅ Image signature verifiable
6. ✅ No critical vulnerabilities in scan
7. ✅ Image size < 500MB
8. ✅ Container runs successfully

## 📝 Next Steps

After successful testing:

1. Update README.md with Docker usage examples
2. Add Docker badge to README
3. Announce new container distribution
4. Update documentation with Docker commands
5. Consider automating more of the release process
