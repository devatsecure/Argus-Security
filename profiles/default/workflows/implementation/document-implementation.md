Using the task number and task title that's been assigned to you, create a file in the current spec's `implementation` folder called `[task-number]-[task-title]-implementation.md`.

For example, if you've been assigned implement the 3rd task from `tasks.md` and that task's title is "Commenting System", then you must create the file: `argus/specs/[this-spec]/implementation/3-commenting-system-implementation.md`.

Use the following structure for the content of your implementation documentation:

```markdown
# Task [number]: [Task Title]

## Overview
**Task Reference:** Task #[number] from `argus/specs/[this-spec]/tasks.md`
**Implemented By:** [Agent Role/Name]
**Date:** [Implementation Date]
**Status:** ✅ Complete | ⚠️ Partial | 🔄 In Progress

### Task Description
[Brief description of what this task was supposed to accomplish]

## Implementation Summary
[High-level overview of the solution implemented - 2-3 short paragraphs explaining the approach taken and why]

## Files Changed/Created

### New Files
- `path/to/file.ext` - [1 short sentence description of purpose]
- `path/to/another/file.ext` - [1 short sentence description of purpose]

### Modified Files
- `path/to/existing/file.ext` - [1 short sentence on what was changed and why]
- `path/to/another/existing/file.ext` - [1 short sentence on what was changed and why]

### Deleted Files
- `path/to/removed/file.ext` - [1 short sentence on why it was removed]

## Key Implementation Details

### [Component/Feature 1]
**Location:** `path/to/file.ext`

[Detailed explanation of this implementation aspect]

**Rationale:** [Why this approach was chosen]

### [Component/Feature 2]
**Location:** `path/to/file.ext`

[Detailed explanation of this implementation aspect]

**Rationale:** [Why this approach was chosen]

## Database Changes (if applicable)

### Migrations
- `[timestamp]_[migration_name].rb` - [What it does]
  - Added tables: [list]
  - Modified tables: [list]
  - Added columns: [list]
  - Added indexes: [list]

### Schema Impact
[Description of how the schema changed and any data implications]

## Dependencies (if applicable)

### New Dependencies Added
- `package-name` (version) - [Purpose/reason for adding]
- `another-package` (version) - [Purpose/reason for adding]

### Configuration Changes
- [Any environment variables, config files, or settings that changed]

## Testing

### Test Files Created/Updated
- `path/to/test/file_spec.rb` - [What is being tested]
- `path/to/feature/test_spec.rb` - [What is being tested]

### Test Coverage
- Unit tests: [✅ Complete | ⚠️ Partial | ❌ None]
- Integration tests: [✅ Complete | ⚠️ Partial | ❌ None]
- Edge cases covered: [List key edge cases tested]

### Manual Testing Performed
[Description of any manual testing done, including steps to verify the implementation]

## User Standards & Preferences Compliance

In your instructions, you were provided with specific user standards and preferences files under the "User Standards & Preferences Compliance" section. Document how your implementation complies with those standards.

Keep it brief and focus only on the specific standards files that were applicable to your implementation tasks.

For each RELEVANT standards file you were instructed to follow:

### [Standard/Preference File Name]
**File Reference:** `path/to/standards/file.md`

**How Your Implementation Complies:**
[1-2 Sentences to explain specifically how your implementation adheres to the guidelines, patterns, or preferences outlined in this standards file. Include concrete examples from your code.]

**Deviations (if any):**
[If you deviated from any standards in this file, explain what, why, and what the trade-offs were]

---

*Repeat the above structure for each RELEVANT standards file you were instructed to follow*

## Integration Points (if applicable)

### APIs/Endpoints
- `[HTTP Method] /path/to/endpoint` - [Purpose]
  - Request format: [Description]
  - Response format: [Description]

### External Services
- [Any external services or APIs integrated]

### Internal Dependencies
- [Other components/modules this implementation depends on or interacts with]

## Known Issues & Limitations

### Issues
1. **[Issue Title]**
   - Description: [What the issue is]
   - Impact: [How significant/what it affects]
   - Workaround: [If any]
   - Tracking: [Link to issue/ticket if applicable]

### Limitations
1. **[Limitation Title]**
   - Description: [What the limitation is]
   - Reason: [Why this limitation exists]
   - Future Consideration: [How this might be addressed later]

## Performance Considerations
[Any performance implications, optimizations made, or areas that might need optimization]

## Security Considerations
[Any security measures implemented, potential vulnerabilities addressed, or security notes]

## Dependencies for Other Tasks
[List any other tasks from the spec that depend on this implementation]

## Notes
[Any additional notes, observations, or context that might be helpful for future reference]
```
