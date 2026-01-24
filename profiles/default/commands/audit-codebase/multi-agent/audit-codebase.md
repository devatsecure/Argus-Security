# Comprehensive Codebase Audit Process

You are conducting a comprehensive codebase audit to identify security vulnerabilities, performance issues, testing gaps, and code quality problems. This audit will analyze the entire codebase and generate a detailed report with actionable recommendations.

## Multi-Phase Audit Process

### PHASE 1: Initialize Audit and Analyze Codebase

Use the **review-orchestrator** subagent to initialize the audit and analyze the codebase patterns.

The review-orchestrator will:
- Analyze the codebase structure and technology stack
- Identify key areas for review
- Plan the audit approach
- Create audit directory structure

### PHASE 2: Delegate to Specialized Reviewers

Delegate specific review tasks to specialized reviewers:

#### Security Review
Use the **security-reviewer** subagent to perform comprehensive security analysis:
- Scan for hardcoded secrets and credentials
- Detect injection vulnerabilities (SQL, NoSQL, Command, Template)
- Review authentication and authorization implementation
- Validate cryptographic security practices
- Check dependency vulnerabilities
- Analyze input/output sanitization

#### Performance Review
Use the **performance-reviewer** subagent to analyze performance:
- Detect N+1 query patterns
- Identify memory leaks and resource management issues
- Analyze algorithm efficiency
- Review I/O performance and streaming
- Check resource management and connection pooling
- Assess scalability concerns

#### Test Coverage Review
Use the **test-coverage-reviewer** subagent to evaluate testing:
- Analyze test coverage for critical business logic
- Check for regression tests for bug fixes
- Review test quality and organization
- Validate critical user workflow testing
- Assess test performance and reliability

#### Code Quality Review
Use the **code-quality-reviewer** subagent to assess code quality:
- Check linting and style compliance
- Review code maintainability and readability
- Analyze documentation quality
- Assess architecture and design patterns
- Validate error handling practices

### PHASE 3: Aggregate Findings and Generate Report

Use the **review-orchestrator** subagent to:
- Collect findings from all specialized reviewers
- Classify issues by severity (merge blockers, suggestions, nits)
- Generate comprehensive audit report
- Create prioritized action items
- Provide overall audit assessment

## Audit Output

Upon completion, the following files will be created in `argus/reviews/[date]-codebase-audit/`:

### Audit Report Files
- `executive-summary.md` - High-level audit overview
- `security-findings.md` - Detailed security analysis
- `performance-findings.md` - Performance optimization recommendations
- `testing-findings.md` - Test coverage and quality assessment
- `code-quality-findings.md` - Code maintainability analysis
- `action-items.md` - Prioritized action items
- `audit-metadata.json` - Audit configuration and metadata

### Detailed Findings
- `merge-blockers.md` - Critical issues that must be fixed
- `suggestions.md` - Recommended improvements
- `nits.md` - Minor issues that can be ignored
- `recommendations.md` - Long-term improvement recommendations

## Audit Scope

The audit will cover:

### Security Analysis
- Secrets and credentials management
- Injection vulnerability detection
- Authentication and authorization review
- Cryptographic security validation
- Dependency security audit
- Input/output security review

### Performance Analysis
- Database query optimization
- Memory management review
- Algorithm efficiency analysis
- I/O performance validation
- Resource management assessment
- Scalability evaluation

### Testing Analysis
- Test coverage assessment
- Critical path testing validation
- Regression test review
- Test quality evaluation
- Test organization analysis
- Test performance assessment

### Code Quality Analysis
- Linting and style compliance
- Code maintainability review
- Documentation quality assessment
- Architecture evaluation
- Error handling review
- Configuration management

## Audit Standards

All reviews will be conducted according to:

{{standards/review/merge-blockers}}
{{standards/review/security-checklist}}
{{standards/review/performance-checklist}}
{{standards/review/testing-checklist}}
{{standards/review/observability-checklist}}

## Audit Timeline

- **Phase 1 (Analysis):** 15-30 minutes
- **Phase 2 (Specialized Reviews):** 30-60 minutes
- **Phase 3 (Report Generation):** 15-30 minutes
- **Total Estimated Time:** 1-2 hours

## Success Criteria

The audit is considered successful when:
- All critical security vulnerabilities are identified
- Performance bottlenecks are documented
- Test coverage gaps are identified
- Code quality issues are catalogued
- Actionable recommendations are provided
- Human review and approval is obtained

## Next Steps

After the audit is complete:
1. Review the comprehensive audit report
2. Prioritize critical issues (merge blockers)
3. Create implementation plan for fixes
4. Schedule follow-up reviews
5. Implement continuous monitoring

## Output to User

Upon completion, display:

"Codebase audit completed successfully!

✅ Security analysis completed
✅ Performance analysis completed  
✅ Test coverage analysis completed
✅ Code quality analysis completed
✅ Comprehensive report generated

📁 Audit report location: `argus/reviews/[date]-codebase-audit/`

👉 Review the executive summary and action items to prioritize fixes."
