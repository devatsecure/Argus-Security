# Code Review Report Template

## Executive Summary

**Review Date:** [YYYY-MM-DD]  
**Reviewer:** [Reviewer Name/System]  
**Overall Status:** [APPROVE | APPROVE WITH FOLLOW-UP | REQUIRES FIXES]  
**Risk Level:** [High | Medium | Low]

### Summary Statistics
- **Total Issues Found:** [X]
- **Merge Blockers:** [Y] (Must fix before merge)
- **Suggestions:** [Z] (Good to have improvements)
- **Nits:** [W] (Can ignore)

### Critical Action Items
1. [Critical issue 1]
2. [Critical issue 2]
3. [Critical issue 3]

---

## Merge Blockers (Must Fix Before Merge)

### Security Issues
- **[BLOCKER]** [Issue description]
  - **Location:** [File:line]
  - **Impact:** [Security risk description]
  - **Fix:** [Recommended solution]

### Performance Issues
- **[BLOCKER]** [Issue description]
  - **Location:** [File:line]
  - **Impact:** [Performance impact description]
  - **Fix:** [Recommended solution]

### Testing Issues
- **[BLOCKER]** [Issue description]
  - **Location:** [File:line]
  - **Impact:** [Testing gap description]
  - **Fix:** [Recommended solution]

### Build/CI Issues
- **[BLOCKER]** [Issue description]
  - **Location:** [File:line]
  - **Impact:** [Build failure description]
  - **Fix:** [Recommended solution]

---

## Suggestions (Good to Have)

### Code Quality Improvements
- **[SUGGESTION]** [Improvement description]
  - **Location:** [File:line]
  - **Benefit:** [Improvement benefit]
  - **Effort:** [Low | Medium | High]

### Performance Optimizations
- **[SUGGESTION]** [Optimization description]
  - **Location:** [File:line]
  - **Benefit:** [Performance improvement]
  - **Effort:** [Low | Medium | High]

### Documentation Enhancements
- **[SUGGESTION]** [Documentation improvement]
  - **Location:** [File:line]
  - **Benefit:** [Documentation benefit]
  - **Effort:** [Low | Medium | High]

### Architecture Improvements
- **[SUGGESTION]** [Architecture improvement]
  - **Location:** [File:line]
  - **Benefit:** [Architecture benefit]
  - **Effort:** [Low | Medium | High]

---

## Nits (Can Ignore)

### Style Issues
- **[NIT]** [Style issue description]
  - **Location:** [File:line]
  - **Note:** [Optional improvement]

### Documentation Nits
- **[NIT]** [Documentation nit]
  - **Location:** [File:line]
  - **Note:** [Optional improvement]

### Minor Improvements
- **[NIT]** [Minor improvement]
  - **Location:** [File:line]
  - **Note:** [Optional improvement]

---

## Detailed Findings by Category

### Security Review Results
- **Secrets Detection:** [Pass | Issues found]
- **Injection Vulnerabilities:** [Pass | Issues found]
- **Authentication/Authorization:** [Pass | Issues found]
- **Cryptographic Security:** [Pass | Issues found]
- **Dependency Security:** [Pass | Issues found]

### Performance Review Results
- **Database Queries:** [Pass | Issues found]
- **Memory Management:** [Pass | Issues found]
- **Algorithm Efficiency:** [Pass | Issues found]
- **I/O Performance:** [Pass | Issues found]
- **Resource Management:** [Pass | Issues found]

### Test Coverage Results
- **Critical Path Coverage:** [Pass | Issues found]
- **Regression Tests:** [Pass | Issues found]
- **Test Quality:** [Pass | Issues found]
- **Test Organization:** [Pass | Issues found]
- **Test Performance:** [Pass | Issues found]

### Code Quality Results
- **Linting/Style:** [Pass | Issues found]
- **Maintainability:** [Pass | Issues found]
- **Documentation:** [Pass | Issues found]
- **Architecture:** [Pass | Issues found]
- **Error Handling:** [Pass | Issues found]

---

## Action Items

### Immediate Actions (Merge Blockers)
1. **[Priority: High]** [Action item 1]
   - **Assignee:** [Team/Person]
   - **Due Date:** [Date]
   - **Status:** [Pending | In Progress | Complete]

2. **[Priority: High]** [Action item 2]
   - **Assignee:** [Team/Person]
   - **Due Date:** [Date]
   - **Status:** [Pending | In Progress | Complete]

### Follow-up Actions (Suggestions)
1. **[Priority: Medium]** [Action item 1]
   - **Assignee:** [Team/Person]
   - **Due Date:** [Date]
   - **Status:** [Pending | In Progress | Complete]

2. **[Priority: Low]** [Action item 2]
   - **Assignee:** [Team/Person]
   - **Due Date:** [Date]
   - **Status:** [Pending | In Progress | Complete]

### Monitoring Recommendations
1. **Metrics to Track:** [List of metrics]
2. **Review Frequency:** [Weekly | Monthly | Quarterly]
3. **Quality Gates:** [List of quality gates]
4. **Follow-up Review:** [Date]

---

## Recommendations

### Immediate Recommendations
1. **Fix all merge blockers before proceeding**
2. **Address critical security vulnerabilities**
3. **Resolve performance bottlenecks**
4. **Add missing critical tests**

### Long-term Recommendations
1. **Implement continuous code quality monitoring**
2. **Establish regular security review processes**
3. **Create performance benchmarking**
4. **Develop comprehensive testing strategy**

### Process Improvements
1. **Integrate automated security scanning**
2. **Add performance testing to CI/CD**
3. **Implement code quality gates**
4. **Establish review best practices**

---

## Conclusion

**Overall Assessment:** [Summary of review results]

**Recommendation:** [APPROVE | APPROVE WITH FOLLOW-UP | REQUIRES FIXES]

**Next Steps:** [List of immediate next steps]

**Follow-up Required:** [Yes | No] - [Details if yes]

---

*Report generated by Argus Code Review System*  
*For questions or clarifications, contact the development team*
