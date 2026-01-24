# Contributing to Argus

Thanks for considering a contribution! Argus is free and open source, and we welcome contributions from the community.

---

## 🎯 How to Contribute

### Reporting Bugs

1. **Check existing issues** to see if the bug has already been reported
2. **Create a new issue** with:
   - Clear description of the bug
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)
   - Relevant logs or screenshots

### Suggesting Features

1. **Check existing discussions** to see if the feature has been proposed
2. **Open a discussion** in the Ideas section with:
   - Problem statement and motivation
   - Proposed solution
   - Alternative approaches considered
   - Impact on existing functionality

### Submitting Pull Requests

We follow **Git Flow** branching strategy. See [GITFLOW.md](GITFLOW.md) for complete details.

#### 1. Fork and Clone

```bash
# Fork the repository on GitHub
git clone https://github.com/YOUR_USERNAME/argus.git
cd argus
```

#### 2. Set Up Git Flow

```bash
# Install git-flow
brew install git-flow-avh  # macOS
# or: apt-get install git-flow  # Linux

# Initialize Git Flow (already configured)
git flow init -d
```

#### 3. Create a Feature Branch

```bash
# Always start from develop
git checkout develop
git pull origin develop

# Create feature branch using Git Flow
git flow feature start your-feature-name

# This creates: feature/your-feature-name
```

**Branch Types:**
- `feature/*` - New features (from `develop`)
- `bugfix/*` - Bug fixes (from `develop`)
- `hotfix/*` - Production fixes (from `main`)

#### 3. Make Your Changes

- Write clean, readable code
- Follow existing code style (PEP 8 for Python)
- Add tests for new functionality
- Update documentation as needed

#### 4. Test Your Changes

```bash
# Run tests
pytest tests/

# Run linters
flake8 scripts/
black scripts/ --check

# Test your changes manually
python3 scripts/run_ai_audit.py /path/to/test/repo audit
```

#### 5. Commit Your Changes

```bash
git add .
git commit -m "feat: Add amazing feature"
# or
git commit -m "fix: Fix critical bug"
```

**Commit Message Format:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Adding or updating tests
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

#### 6. Finish Feature and Push

```bash
# Finish feature (merges to develop)
git flow feature finish your-feature-name

# Push develop to your fork
git push origin develop
```

#### 7. Create Pull Request

Create a Pull Request on GitHub:
- **Base branch**: `develop` (NOT `main`)
- **Compare branch**: `your-fork:develop`
- **Title**: Clear and descriptive
- **Description**: What, why, and how
- **Reference**: Link related issues
- **Screenshots**: If applicable

**Important**: All PRs should target `develop` branch, not `main`.

---

## 📋 Pull Request Checklist

Before submitting your PR, ensure:

- [ ] Code follows project style guidelines
- [ ] All tests pass (`pytest tests/`)
- [ ] New tests added for new functionality
- [ ] Documentation updated (README, docstrings)
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] No merge conflicts with `develop` branch
- [ ] PR targets `develop` branch (not `main`)
- [ ] PR description explains the changes
- [ ] Git Flow workflow followed (see [GITFLOW.md](GITFLOW.md))

---

## 🎨 Code Style Guidelines

### Python

- Follow **PEP 8** style guide
- Use **type hints** for function parameters and return values
- Write **docstrings** for all functions and classes
- Keep functions **small and focused** (single responsibility)
- Use **meaningful variable names**

Example:
```python
def calculate_risk_score(
    cvss_score: float,
    exploitability: str,
    reachability: bool
) -> float:
    """
    Calculate risk score based on multiple factors.
    
    Args:
        cvss_score: CVSS base score (0-10)
        exploitability: Exploitability level (trivial/moderate/complex)
        reachability: Whether vulnerable code is reachable
        
    Returns:
        Normalized risk score (0-10)
    """
    # Implementation
    pass
```

### Rego (Policy Files)

- Use **descriptive rule names**
- Add **comments** explaining complex logic
- Keep policies **modular and reusable**

---

## 🧪 Testing Guidelines

### Writing Tests

- Write tests for **all new functionality**
- Use **descriptive test names** that explain what is being tested
- Follow **Arrange-Act-Assert** pattern
- Mock external dependencies (API calls, file I/O)

Example:
```python
def test_noise_scorer_identifies_test_files():
    """Test that noise scorer correctly identifies test files as high noise."""
    # Arrange
    scorer = NoiseScorer()
    finding = {
        "path": "tests/test_example.py",
        "severity": "low"
    }
    
    # Act
    score = scorer.calculate_noise_score(finding)
    
    # Assert
    assert score > 0.7, "Test files should have high noise score"
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/unit/test_noise_scorer.py

# Run with coverage
pytest --cov=scripts --cov-report=html tests/

# Run only fast tests
pytest -m "not slow" tests/
```

---

## 📚 Documentation Guidelines

### Code Documentation

- Add **docstrings** to all public functions and classes
- Include **type hints** for parameters and return values
- Provide **usage examples** in docstrings for complex functions

### README Updates

- Keep main README focused on **getting started** and **core features**
- Add detailed examples to **examples/** directory
- Update **table of contents** if adding new sections

---

## 🔍 Code Review Process

### What We Look For

1. **Functionality**: Does it work as intended?
2. **Tests**: Are there adequate tests?
3. **Code Quality**: Is it readable and maintainable?
4. **Documentation**: Is it well-documented?
5. **Performance**: Are there any performance concerns?
6. **Security**: Are there any security implications?

### Review Timeline

- **Initial review**: Within 3-5 business days
- **Follow-up**: Within 2 business days after updates
- **Merge**: After approval from at least 1 maintainer

---

## 🤝 Community Guidelines

### Be Respectful

- Use welcoming and inclusive language
- Be respectful of differing viewpoints
- Accept constructive criticism gracefully
- Focus on what is best for the community

### Be Collaborative

- Help others learn and grow
- Share knowledge and expertise
- Give credit where credit is due
- Celebrate successes together

### Be Professional

- Keep discussions on-topic
- Avoid personal attacks or harassment
- Respect maintainer decisions
- Follow the Code of Conduct

---

## 📞 Getting Help

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community support
- **Documentation**: See main README and inline code docs

---

## 🏆 Recognition

Contributors are recognized in:
- GitHub contributors list
- Release notes for significant contributions
- Special mentions for major features

---

## 📄 License

By contributing to Argus, you agree that your contributions will be licensed under the [MIT License](../LICENSE).

---

**Thank you for contributing to Argus!** 🎉

Your contributions help make security analysis better for everyone.

