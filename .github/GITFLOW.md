# Git Flow Branching Strategy

Argus follows the **Git Flow** branching model, a robust workflow designed for projects with scheduled releases and continuous development.

---

## 📋 Branch Structure

### Main Branches

#### `main`
- **Purpose**: Production-ready code
- **Stability**: Always stable and deployable
- **Updates**: Only from `release/*` or `hotfix/*` branches
- **Tags**: All releases are tagged here (e.g., `v3.1.0`)
- **Protection**: Direct commits prohibited

#### `develop`
- **Purpose**: Integration branch for next release
- **Stability**: Generally stable, but may contain new features
- **Updates**: From `feature/*`, `bugfix/*`, and `release/*` branches
- **Base**: All feature branches start from here
- **Protection**: Direct commits discouraged (use feature branches)

---

## 🌿 Supporting Branches

### Feature Branches (`feature/*`)

**Purpose**: Develop new features or enhancements

```bash
# Start a new feature
git flow feature start <feature-name>

# Work on your feature
git add .
git commit -m "feat: add new feature"

# Finish feature (merges to develop)
git flow feature finish <feature-name>

# Or manually:
git checkout develop
git merge --no-ff feature/<feature-name>
git branch -d feature/<feature-name>
```

**Naming Convention**:
- `feature/noise-scoring-engine`
- `feature/correlation-engine`
- `feature/soc2-compliance`

**Rules**:
- Branch from: `develop`
- Merge back to: `develop`
- Naming: `feature/<descriptive-name>`
- Lifetime: Delete after merge

---

### Bugfix Branches (`bugfix/*`)

**Purpose**: Fix bugs in the development branch

```bash
# Start a bugfix
git flow bugfix start <bug-name>

# Fix the bug
git add .
git commit -m "fix: resolve issue with..."

# Finish bugfix (merges to develop)
git flow bugfix finish <bug-name>
```

**Naming Convention**:
- `bugfix/policy-gate-path-resolution`
- `bugfix/foundation-sec-analyze-code`

**Rules**:
- Branch from: `develop`
- Merge back to: `develop`
- Naming: `bugfix/<descriptive-name>`
- Lifetime: Delete after merge

---

### Release Branches (`release/*`)

**Purpose**: Prepare for a production release

```bash
# Start a release
git flow release start <version>

# Prepare release (bump version, update changelog, etc.)
git add .
git commit -m "chore: prepare release v3.2.0"

# Finish release (merges to main and develop, tags main)
git flow release finish <version>

# Push everything
git push origin main develop --tags
```

**Naming Convention**:
- `release/3.2.0`
- `release/4.0.0`

**Rules**:
- Branch from: `develop`
- Merge back to: `main` AND `develop`
- Naming: `release/<version>`
- Activities:
  - Version bumps
  - Changelog updates
  - Documentation finalization
  - Bug fixes only (no new features)
- Tags: Create version tag on `main` after merge
- Lifetime: Delete after merge

---

### Hotfix Branches (`hotfix/*`)

**Purpose**: Emergency fixes for production issues

```bash
# Start a hotfix
git flow hotfix start <version>

# Fix the critical issue
git add .
git commit -m "fix: critical security patch"

# Finish hotfix (merges to main and develop, tags main)
git flow hotfix finish <version>

# Push everything
git push origin main develop --tags
```

**Naming Convention**:
- `hotfix/3.1.1`
- `hotfix/3.1.2-security-patch`

**Rules**:
- Branch from: `main`
- Merge back to: `main` AND `develop`
- Naming: `hotfix/<version>`
- Purpose: Critical production fixes only
- Tags: Create patch version tag on `main`
- Lifetime: Delete after merge

---

## 🔄 Complete Workflow

### 1. Daily Development

```bash
# 1. Start from develop
git checkout develop
git pull origin develop

# 2. Create feature branch
git flow feature start my-awesome-feature

# 3. Develop and commit
git add .
git commit -m "feat: implement awesome feature"

# 4. Keep feature updated with develop
git checkout develop
git pull origin develop
git checkout feature/my-awesome-feature
git merge develop

# 5. Finish feature
git flow feature finish my-awesome-feature

# 6. Push develop
git push origin develop
```

---

### 2. Release Process

```bash
# 1. Start release from develop
git checkout develop
git pull origin develop
git flow release start 3.2.0

# 2. Prepare release
# - Update version in files
# - Update CHANGELOG.md
# - Update README.md
# - Run final tests
git add .
git commit -m "chore: prepare release v3.2.0"

# 3. Finish release
git flow release finish 3.2.0
# This will:
# - Merge release/3.2.0 into main
# - Tag main with v3.2.0
# - Merge release/3.2.0 back into develop
# - Delete release/3.2.0

# 4. Push everything
git push origin main
git push origin develop
git push origin --tags

# 5. Create GitHub Release
gh release create v3.2.0 \
  --title "Argus v3.2.0 - [Title]" \
  --notes-file RELEASE_NOTES.md \
  --latest
```

---

### 3. Hotfix Process

```bash
# 1. Start hotfix from main
git checkout main
git pull origin main
git flow hotfix start 3.1.1

# 2. Fix the critical issue
git add .
git commit -m "fix: critical security vulnerability in secret detector"

# 3. Finish hotfix
git flow hotfix finish 3.1.1
# This will:
# - Merge hotfix/3.1.1 into main
# - Tag main with v3.1.1
# - Merge hotfix/3.1.1 back into develop
# - Delete hotfix/3.1.1

# 4. Push everything
git push origin main
git push origin develop
git push origin --tags

# 5. Create GitHub Release
gh release create v3.1.1 \
  --title "Argus v3.1.1 - Security Hotfix" \
  --notes "Critical security patch for secret detector" \
  --latest
```

---

## 📊 Branch Diagram

```
main        ──●────────────────●────────●──────────────●──
              │                ↑        ↑              ↑
              │            (merge)  (merge)        (merge)
              │                │        │              │
              │         release/3.1.0   │       hotfix/3.1.1
              │                │        │              │
develop     ──●────●────●──────●────●───●────●─────────●──
              │    ↑    ↑             ↑     ↑
              │    │    │             │     │
              │  (merge)(merge)    (merge)(merge)
              │    │    │             │     │
feature/*     └────●    └─────────────●     │
bugfix/*                                    └─────────────●

Legend:
● = Commit
─ = Branch timeline
↑ = Merge direction
```

---

## 🎯 Best Practices

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add noise scoring engine
fix: resolve policy gate path issue
docs: update Git Flow documentation
chore: bump version to 3.2.0
refactor: simplify correlation algorithm
test: add unit tests for risk scorer
perf: optimize multi-repo coordinator
style: format code with black
ci: update GitHub Actions workflow
```

### Branch Naming

- **Feature**: `feature/descriptive-name`
- **Bugfix**: `bugfix/issue-description`
- **Release**: `release/X.Y.Z`
- **Hotfix**: `hotfix/X.Y.Z`

Use lowercase and hyphens, be descriptive.

### Pull Requests

- **Title**: Clear and descriptive
- **Description**: What, why, and how
- **Labels**: `feature`, `bugfix`, `release`, `hotfix`
- **Reviewers**: At least 1 reviewer required
- **Checks**: All CI/CD checks must pass
- **Conflicts**: Resolve before merge

### Version Numbers

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (X.0.0): Breaking changes
- **MINOR** (x.Y.0): New features (backward compatible)
- **PATCH** (x.y.Z): Bug fixes (backward compatible)

Examples:
- `3.1.0` → `3.2.0`: New features added
- `3.1.0` → `3.1.1`: Bug fixes only
- `3.1.0` → `4.0.0`: Breaking changes

---

## 🔒 Branch Protection Rules

### `main` Branch

- ✅ Require pull request reviews (1+ approvers)
- ✅ Require status checks to pass
- ✅ Require branches to be up to date
- ✅ Require conversation resolution
- ✅ Require signed commits (optional)
- ❌ Allow force pushes: **NEVER**
- ❌ Allow deletions: **NEVER**

### `develop` Branch

- ✅ Require pull request reviews (1+ approvers)
- ✅ Require status checks to pass
- ✅ Require branches to be up to date
- ❌ Allow force pushes: **NEVER**
- ❌ Allow deletions: **NEVER**

### Feature/Bugfix Branches

- ⚠️ No protection (developers have freedom)
- ✅ Delete after merge (keep repo clean)

---

## 🚀 Quick Reference

### Common Commands

```bash
# Feature workflow
git flow feature start <name>
git flow feature finish <name>

# Bugfix workflow
git flow bugfix start <name>
git flow bugfix finish <name>

# Release workflow
git flow release start <version>
git flow release finish <version>

# Hotfix workflow
git flow hotfix start <version>
git flow hotfix finish <version>

# Check current branch
git branch --show-current

# List all branches
git branch -a

# Update from remote
git fetch origin
git pull origin <branch>

# Clean up old branches
git fetch --prune
git branch -d <branch-name>
```

---

## 📚 Additional Resources

- [Git Flow Cheatsheet](https://danielkummer.github.io/git-flow-cheatsheet/)
- [A Successful Git Branching Model](https://nvie.com/posts/a-successful-git-branching-model/)
- [Semantic Versioning](https://semver.org/)
- [Conventional Commits](https://www.conventionalcommits.org/)

---

## 🤝 Contributing

All contributors must follow this Git Flow workflow. See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

---

**Questions?** Open a GitHub Discussion or contact the maintainers.

**Version**: 1.0.0  
**Last Updated**: November 7, 2025  
**Maintainer**: Argus Community

