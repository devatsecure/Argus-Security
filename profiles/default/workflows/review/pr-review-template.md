# PR Review Template

## PR Review Summary

**PR Title:** [PR Title]  
**Author:** [Author Name]  
**Reviewer:** [Reviewer Name]  
**Review Date:** [YYYY-MM-DD]  
**Overall Status:** [APPROVE | APPROVE WITH FOLLOW-UP | REQUIRES FIXES]

### Quick Stats
- **Files Changed:** [X]
- **Lines Added:** [Y]
- **Lines Removed:** [Z]
- **Issues Found:** [A] blockers, [B] suggestions, [C] nits

---

## Inline Comments

### [BLOCKER] Critical Issues (Must Fix)

#### File: `path/to/file.js`
```javascript
// Line 42: [BLOCKER] Hardcoded API key detected
const apiKey = "sk-1234567890abcdef"; // ❌ SECURITY RISK
```

**Issue:** Hardcoded API key in source code  
**Risk:** High - API key could be exposed in version control  
**Fix:** Use environment variable: `process.env.API_KEY`

---

#### File: `path/to/query.js`
```javascript
// Line 15: [BLOCKER] N+1 query pattern detected
users.forEach(user => {
    const posts = db.query(`SELECT * FROM posts WHERE user_id = ${user.id}`); // ❌ PERFORMANCE RISK
});
```

**Issue:** N+1 query pattern in loop  
**Risk:** High - Could cause database performance issues  
**Fix:** Use batch query or include posts in initial user query

---

### [SUGGESTION] Improvements (Good to Have)

#### File: `path/to/utils.js`
```javascript
// Line 8: [SUGGESTION] Consider adding input validation
function processUserData(data) {
    // Add validation for required fields
    if (!data.email || !data.name) {
        throw new Error('Missing required fields');
    }
}
```

**Suggestion:** Add input validation for better error handling  
**Benefit:** Prevents runtime errors and improves user experience

---

#### File: `path/to/api.js`
```javascript
// Line 25: [SUGGESTION] Consider adding rate limiting
app.get('/api/users', (req, res) => {
    // Add rate limiting middleware
});
```

**Suggestion:** Implement rate limiting for API endpoints  
**Benefit:** Prevents abuse and improves system stability

---

### [NIT] Minor Issues (Can Ignore)

#### File: `path/to/component.jsx`
```javascript
// Line 12: [NIT] Consider more descriptive variable name
const d = new Date(); // Could be 'currentDate' or 'now'
```

**Nit:** Variable name could be more descriptive  
**Note:** This is a minor style preference

---

## Summary by Category

### Security Review
- ✅ **Authentication:** Properly implemented
- ❌ **Secrets:** Hardcoded API key found
- ✅ **Input Validation:** Generally good
- ⚠️ **Authorization:** Could be improved

### Performance Review
- ❌ **Database Queries:** N+1 query pattern detected
- ✅ **Memory Usage:** No obvious leaks
- ✅ **Algorithm Efficiency:** Good
- ⚠️ **Caching:** Could benefit from caching

### Test Coverage
- ✅ **Unit Tests:** Good coverage for new functions
- ⚠️ **Integration Tests:** Missing for API endpoints
- ✅ **Regression Tests:** Added for bug fixes
- ❌ **Critical Path:** Missing tests for user authentication

### Code Quality
- ✅ **Linting:** Passes all linter checks
- ✅ **Style:** Consistent formatting
- ⚠️ **Documentation:** Could use more inline comments
- ✅ **Error Handling:** Proper exception handling

---

## Action Items

### Must Fix Before Merge
1. **[BLOCKER]** Remove hardcoded API key and use environment variable
2. **[BLOCKER]** Fix N+1 query pattern in user posts query
3. **[BLOCKER]** Add tests for user authentication flow

### Should Fix (Follow-up)
1. **[SUGGESTION]** Add input validation to processUserData function
2. **[SUGGESTION]** Implement rate limiting for API endpoints
3. **[SUGGESTION]** Add integration tests for new API endpoints

### Nice to Have
1. **[NIT]** Improve variable naming in component.jsx
2. **[NIT]** Add more inline documentation

---

## Review Decision

### Overall Assessment
**Status:** [APPROVE | APPROVE WITH FOLLOW-UP | REQUIRES FIXES]

### Reasoning
- **Security:** [Good | Needs attention | Critical issues]
- **Performance:** [Good | Needs attention | Critical issues]
- **Testing:** [Good | Needs attention | Critical issues]
- **Quality:** [Good | Needs attention | Critical issues]

### Next Steps
1. **If REQUIRES FIXES:** Address all [BLOCKER] issues before requesting re-review
2. **If APPROVE WITH FOLLOW-UP:** Address [SUGGESTION] items in follow-up PR
3. **If APPROVE:** Ready to merge

### Follow-up Required
- [ ] Security review after API key fix
- [ ] Performance testing after query optimization
- [ ] Test coverage review after adding missing tests

---

## Additional Notes

### Positive Aspects
- Clean, readable code structure
- Good error handling patterns
- Consistent coding style
- Proper git commit messages

### Areas for Improvement
- Security awareness (no hardcoded secrets)
- Performance optimization (database queries)
- Test coverage (critical paths)
- Documentation (inline comments)

### Questions for Author
1. Is there a specific reason for the hardcoded API key?
2. Have you considered the performance impact of the N+1 query?
3. Are there any edge cases not covered by the current tests?

---

*Review conducted by Argus Code Review System*  
*For questions about this review, contact the development team*
