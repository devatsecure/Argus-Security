# Responsible Disclosure Quick Start

## Critical Rule

**NEVER create public GitHub issues for security vulnerabilities!**

Always contact maintainers privately first and give 90 days before public disclosure.

---

## Quick Commands

### 1. Find Security Contact
```bash
python scripts/responsible_disclosure.py --repo <github-url> --find-contact
```

### 2. Generate Disclosure Email
```bash
python scripts/responsible_disclosure.py \
  --repo <github-url> \
  --report <findings.json> \
  --generate-email
```

### 3. Create Tracking Entry
```bash
python scripts/responsible_disclosure.py \
  --repo <github-url> \
  --report <findings.json> \
  --severity [critical|high|medium|low] \
  --create
```

### 4. Update Status
```bash
python scripts/responsible_disclosure.py \
  --update <ARGUS-ID> \
  --status [contacted|acknowledged|patched|disclosed] \
  --notes "Your notes here"
```

### 5. List Active Disclosures
```bash
python scripts/responsible_disclosure.py --list
```

### 6. Check for Overdue
```bash
python scripts/responsible_disclosure.py --check-overdue
```

---

## Workflow Summary

```
1. Discover vulnerability
   ↓
2. Find security contact (--find-contact)
   ↓
3. Generate disclosure email (--generate-email)
   ↓
4. Create tracking entry (--create)
   ↓
5. Send email privately (NEVER public GitHub issue!)
   ↓
6. Update status when maintainer responds (--update)
   ↓
7. Share technical details privately
   ↓
8. Wait 90 days OR coordinate earlier disclosure
   ↓
9. Public disclosure with credit to maintainer
```

---

## Timeline

- **Day 0**: Private contact sent
- **Day 7**: If no response, send follow-up
- **Day 30**: If no response, try alternative contact
- **Day 60**: Final notice of upcoming disclosure
- **Day 90**: Public disclosure (unless extended by agreement)

---

## Contact Methods (Priority Order)

1. **SECURITY.md** file in repository
2. **GitHub Security Advisory** (private)
3. **security@domain.com** email
4. **Maintainer email** from git history

---

## Status Values

- `contacted` - Initial email sent
- `acknowledged` - Maintainer confirmed receipt
- `patched` - Fix released
- `disclosed` - Public disclosure completed
- `overdue` - Past 90-day deadline

---

## Examples

### Full Workflow Example
```bash
# Step 1: Find contact
python scripts/responsible_disclosure.py \
  --repo https://github.com/owner/repo \
  --find-contact

# Step 2: Generate email and create tracking
python scripts/responsible_disclosure.py \
  --repo https://github.com/owner/repo \
  --report scan_results.json \
  --severity high \
  --create

# Step 3: Send the generated email privately

# Step 4: When maintainer responds
python scripts/responsible_disclosure.py \
  --update ARGUS-20260129-001 \
  --status acknowledged \
  --notes "Maintainer confirmed, working on patch"

# Step 5: When patch is released
python scripts/responsible_disclosure.py \
  --update ARGUS-20260129-001 \
  --status patched \
  --notes "Fixed in version 2.1.0"

# Step 6: Public disclosure
python scripts/responsible_disclosure.py \
  --update ARGUS-20260129-001 \
  --status disclosed \
  --notes "Public advisory published"
```

---

## What NEVER to Do

- ❌ Create public GitHub issues for security bugs
- ❌ Tweet about vulnerabilities before disclosure deadline
- ❌ Share exploit code publicly before deadline
- ❌ Disclose without contacting maintainer first
- ❌ Ignore maintainer requests for extensions
- ❌ Test vulnerabilities on production systems

---

## What ALWAYS to Do

- ✅ Contact maintainers privately first
- ✅ Give 90 days minimum before public disclosure
- ✅ Use professional, respectful communication
- ✅ Offer to help with remediation
- ✅ Extend deadlines for actively patching maintainers
- ✅ Credit maintainers publicly when disclosing

---

## Documentation

- **Full Process Guide**: [docs/RESPONSIBLE_DISCLOSURE.md](/docs/RESPONSIBLE_DISCLOSURE.md)
- **Email Template**: [templates/security-disclosure-email.md](/templates/security-disclosure-email.md)
- **Example Walkthrough**: [examples/RESPONSIBLE_DISCLOSURE_EXAMPLE.md](/examples/RESPONSIBLE_DISCLOSURE_EXAMPLE.md)

---

## Emergency Contact

For critical vulnerabilities being actively exploited:
- Contact maintainer immediately via multiple channels
- Consider 30-45 day timeline instead of 90 days
- Report to CERT/CC: https://www.kb.cert.org/vuls/report/
- May require immediate public disclosure with mitigations
