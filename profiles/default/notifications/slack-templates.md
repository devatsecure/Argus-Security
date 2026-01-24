# Slack Notification Templates

## Overview

This document defines Slack notification templates for the Argus Code Reviewer system.

---

## Template 1: Audit Complete (No Blockers)

**Channel**: #code-reviews  
**Severity**: Info  
**Trigger**: Audit completes successfully with no critical issues

```json
{
  "text": "✅ Code Review Complete: {{repository}}",
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "✅ Code Review Complete"
      }
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Repository:*\n{{repository}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Branch:*\n{{branch}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Review Type:*\n{{review_type}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Status:*\n✅ Passed"
        }
      ]
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Blockers:*\n0"
        },
        {
          "type": "mrkdwn",
          "text": "*Suggestions:*\n{{suggestions_count}}"
        }
      ]
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "<{{workflow_url}}|View Full Report>"
      }
    }
  ]
}
```

---

## Template 2: Critical Blockers Found

**Channel**: #code-reviews + #security-alerts  
**Severity**: Critical  
**Trigger**: Audit finds merge-blocking issues

```json
{
  "text": "🚨 Critical Issues Found: {{repository}}",
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "🚨 Critical Issues Detected"
      }
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Repository:*\n{{repository}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Branch:*\n{{branch}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Review Type:*\n{{review_type}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Status:*\n❌ Requires Fixes"
        }
      ]
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Critical Issues:*\n🚨 {{blockers_count}}"
        },
        {
          "type": "mrkdwn",
          "text": "*High Priority:*\n⚠️ {{high_priority_count}}"
        }
      ]
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*⚠️ Action Required*\nCritical issues must be fixed before merging."
      }
    },
    {
      "type": "divider"
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Top Issues:*\n{{top_issues_list}}"
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "<{{workflow_url}}|View Full Report> | <{{pr_url}}|View Pull Request>"
      }
    }
  ]
}
```

---

## Template 3: Security Vulnerability Alert

**Channel**: #security-alerts  
**Severity**: High  
**Trigger**: Security scan finds vulnerabilities

```json
{
  "text": "🔒 Security Vulnerabilities Found: {{repository}}",
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "🔒 Security Alert"
      }
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Repository:*\n{{repository}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Scan Date:*\n{{timestamp}}"
        }
      ]
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Critical:*\n🔴 {{critical_count}}"
        },
        {
          "type": "mrkdwn",
          "text": "*High:*\n🟠 {{high_count}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Medium:*\n🟡 {{medium_count}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Low:*\n🟢 {{low_count}}"
        }
      ]
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Security Issues Found:*\n{{security_issues_list}}"
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "<{{workflow_url}}|View Security Report>"
      }
    }
  ]
}
```

---

## Template 4: Weekly Summary Digest

**Channel**: #code-reviews  
**Severity**: Info  
**Trigger**: Weekly scheduled summary (Mondays at 9 AM)

```json
{
  "text": "📊 Weekly Code Review Summary",
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "📊 Weekly Code Review Summary"
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Week of {{week_start}} - {{week_end}}*"
      }
    },
    {
      "type": "divider"
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Total Audits:*\n{{total_audits}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Repositories Scanned:*\n{{repos_scanned}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Issues Found:*\n{{total_issues}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Issues Fixed:*\n{{issues_fixed}}"
        }
      ]
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Top Repositories by Issues:*\n{{top_repos_list}}"
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Most Common Issues:*\n{{common_issues_list}}"
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "<{{dashboard_url}}|View Dashboard>"
      }
    }
  ]
}
```

---

## Template 5: PR Review Complete

**Channel**: #code-reviews  
**Severity**: Info  
**Trigger**: Pull request review completes

```json
{
  "text": "📝 PR Review Complete: {{repository}}#{{pr_number}}",
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "📝 Pull Request Review"
      }
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Repository:*\n{{repository}}"
        },
        {
          "type": "mrkdwn",
          "text": "*PR:*\n#{{pr_number}} - {{pr_title}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Author:*\n@{{author}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Status:*\n{{status_emoji}} {{status_text}}"
        }
      ]
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Blockers:*\n{{blockers_count}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Suggestions:*\n{{suggestions_count}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Nits:*\n{{nits_count}}"
        },
        {
          "type": "mrkdwn",
          "text": "*Files Changed:*\n{{files_changed}}"
        }
      ]
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "{{recommendation_text}}"
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "<{{pr_url}}|View Pull Request> | <{{workflow_url}}|View Review Details>"
      }
    }
  ]
}
```

---

## Variable Reference

### Common Variables
- `{{repository}}` - Full repository name (org/repo)
- `{{branch}}` - Branch name
- `{{review_type}}` - audit, security, or review
- `{{timestamp}}` - ISO 8601 timestamp
- `{{workflow_url}}` - Link to GitHub Actions workflow
- `{{pr_url}}` - Link to pull request
- `{{dashboard_url}}` - Link to metrics dashboard

### Count Variables
- `{{blockers_count}}` - Number of critical/blocking issues
- `{{suggestions_count}}` - Number of suggestions
- `{{high_priority_count}}` - Number of high-priority issues
- `{{nits_count}}` - Number of minor nits
- `{{files_changed}}` - Number of files modified

### List Variables
- `{{top_issues_list}}` - Formatted list of top issues
- `{{security_issues_list}}` - Formatted list of security issues
- `{{top_repos_list}}` - Formatted list of repositories
- `{{common_issues_list}}` - Formatted list of common issue types

### Status Variables
- `{{status_emoji}}` - ✅ or ❌
- `{{status_text}}` - "Passed", "Requires Fixes", etc.
- `{{recommendation_text}}` - "Ready to merge", "Fix blockers first", etc.

---

## Usage Instructions

### In Shell Scripts

```bash
# Replace variables in template
NOTIFICATION=$(cat slack-template.json | \
  sed "s|{{repository}}|${REPO_NAME}|g" | \
  sed "s|{{branch}}|${BRANCH_NAME}|g" | \
  sed "s|{{blockers_count}}|${BLOCKERS}|g")

# Send to Slack
curl -X POST -H 'Content-type: application/json' \
  --data "$NOTIFICATION" \
  "$SLACK_WEBHOOK_URL"
```

### In GitHub Actions

```yaml
- name: Send Slack Notification
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
  run: |
    # Load template and replace variables
    # Send to Slack webhook
```

---

## Customization Guidelines

### Color Coding
- 🔴 Red (Critical) - Blockers, critical security issues
- 🟠 Orange (High) - High-priority issues
- 🟡 Yellow (Medium) - Medium-priority suggestions
- 🟢 Green (Low) - Minor nits, passed reviews
- 🔵 Blue (Info) - General information, summaries

### Message Frequency
- **Real-time**: Critical security alerts, PR reviews
- **Daily**: Security scan results
- **Weekly**: Summary digests, trend reports

### Channel Routing
- **#code-reviews**: All review results, general findings
- **#security-alerts**: Critical security only (blockers)
- **DM to PR Author**: PR-specific feedback (optional)

---

## Testing Templates

```bash
# Test notification with sample data
curl -X POST -H 'Content-type: application/json' \
  --data '{
    "text": "Test notification",
    "blocks": [
      {
        "type": "section",
        "text": {
          "type": "mrkdwn",
          "text": "This is a test notification from Argus Code Reviewer"
        }
      }
    ]
  }' \
  "$SLACK_WEBHOOK_URL"
```

