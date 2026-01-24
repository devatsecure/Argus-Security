# Case Study Template

Use this template to share how Argus helped your team.

---

## Company/Organization

**Name:** [Your Company/Team Name or "Anonymous"]  
**Industry:** [e.g., FinTech, Healthcare, E-commerce, Open Source]  
**Team Size:** [Number of developers]  
**Location:** [City, Country]

---

## Challenge

### What was the problem?

Describe your security/code review challenges before Argus:

- **Manual Processes:** [Time spent on manual reviews]
- **Tool Limitations:** [Issues with existing tools]
- **False Positives:** [% of alerts that were noise]
- **Bottlenecks:** [What slowed down development]
- **Costs:** [Security audit costs, if applicable]

### Specific Pain Points

1. [Pain point #1]
2. [Pain point #2]
3. [Pain point #3]

---

## Solution

### How did you implement Argus?

- **Setup Time:** [How long did it take?]
- **Integration:** [GitHub Actions, pre-commit hooks, CI/CD?]
- **Configuration:** [Lite mode, full mode, custom agents?]
- **AI Provider:** [Anthropic, OpenAI, Ollama, Foundation-Sec?]

### Implementation Details

```yaml
# Share your .argus.yml (optional)
ai_provider: anthropic
agent_profile: lite
multi_agent_mode: sequential
cost_limit: 0.50
```

---

## Results

### Quantitative Metrics

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| **Review Time** | [X hours] | [Y minutes] | [Z% faster] |
| **False Positive Rate** | [X%] | [Y%] | [Z% reduction] |
| **Vulnerabilities Found** | [X/month] | [Y/month] | [+Z%] |
| **Cost per Scan** | [X] | [Y] | [Z% savings] |
| **Developer Satisfaction** | [X/10] | [Y/10] | [+Z points] |

### Qualitative Impact

- **Developer Experience:** [How did it affect your team?]
- **Security Posture:** [How did security improve?]
- **Velocity:** [Did you ship faster?]
- **Compliance:** [Did it help with compliance?]

---

## Key Findings

### Notable Discoveries

Share 2-3 interesting vulnerabilities Argus found:

1. **[Vulnerability Type]**
   - **File:** `path/to/file.py`
   - **Severity:** Critical
   - **Description:** [Brief description]
   - **Impact:** [What could have happened]
   - **Fix:** [How you fixed it]

2. **[Vulnerability Type]**
   - ...

---

## Lessons Learned

### What Worked Well

1. [Success factor #1]
2. [Success factor #2]
3. [Success factor #3]

### Challenges & Solutions

1. **Challenge:** [What didn't work initially]
   - **Solution:** [How you solved it]

2. **Challenge:** [Another challenge]
   - **Solution:** [How you solved it]

---

## Recommendations

### For Teams Considering Argus

- **Start with:** [Your recommendation for getting started]
- **Focus on:** [What to prioritize]
- **Avoid:** [Common pitfalls]
- **Best practices:** [Tips for success]

### Configuration Tips

```yaml
# Your recommended configuration
# (Share what worked for your team)
```

---

## Future Plans

- [How will you expand use of Argus?]
- [What features would you like to see?]
- [Plans for broader adoption?]

---

## Contact

**Can others contact you?** [Yes/No]  
**Preferred contact method:** [Email, GitHub, LinkedIn]  
**Contact info:** [your-email@company.com or @github-username]

---

## Media

**Screenshots, metrics dashboards, or demos:** [Optional - link to images/videos]

---

*Thank you for sharing your Argus story!*
