Now that the implementation of this spec is complete, we must generate an ordered series of verification prompt texts, which will be used to verify the implementation of this spec's tasks.

Follow these steps to generate this spec's ordered series of verification prompt texts, each in its own .md file located in `argus/specs/[this-spec]/implementation/prompts/`.

## Verification Prompt Generation Workflow

### Step 1: Determine which verifier roles are needed

1. Read `argus/specs/[this-spec]/tasks.md` to identify all implementer roles that were assigned to task groups.

2. Read `argus/roles/implementers.yml` and for each implementer role that was used:
   - Find that implementer by ID
   - Note the verifier role(s) listed in its `verified_by` field

3. Collect all unique verifier roles from this process (e.g., backend-verifier, frontend-verifier).

4. Read `argus/roles/verifiers.yml` to confirm these verifier roles exist and understand their responsibilities.

### Step 2: Generate verification prompt files for each verifier

For EACH unique verifier role identified in Step 1, create a verification prompt file.

#### Step 2a. Create the verifier prompt markdown file

Create the prompt markdown file using this naming convention:
`argus/specs/[this-spec]/implementation/prompts/[next-number]-verify-[verifier-name].md`

For example, if the last implementation prompt was `4-comment-system.md` and you need to verify backend and frontend:
- Create `5-verify-backend.md`
- Create `6-verify-frontend.md`

#### Step 2b. Populate the verifier prompt file

Populate the verifier prompt markdown file using the following Prompt file content template.

##### Bracket content replacements

In the content template below, replace "[spec-title]" and "[this-spec]" with the current spec's title.

Replace "[verifier-role-name]" with the verifier role's ID (e.g., "backend-verifier").

Replace "[task-groups-list]" with a bulleted list of the task group titles (parent tasks only) that fall under this verifier's purview. To determine which task groups:
1. Look at all task groups in `tasks.md`
2. For each task group, check its assigned implementer
3. If that implementer's `verified_by` field includes this verifier role, include this task group in the list

Replace "[verifier-standards]" using the following logic:
1. Find the verifier role in `argus/roles/verifiers.yml`
2. Check the list of `standards` for that verifier
3. Compile the list of file references to those standards and display the list in place of "[verifier-standards]", one file reference per line. Use this logic for determining the list of files to include:
   a. If the value for `standards` is simply `all`, then include every single file, folder, sub-folder and files within sub-folders in your list of files.
   b. If the item under standards ends with "*" then it means that all files within this folder or sub-folder should be included. For example, `frontend/*` means include all files and sub-folders and their files located inside of `argus/standards/frontend/`.
   c. If a file ends in `.md` then it means this is one specific file you must include in your list of files. For example `backend/api.md` means you must include the file located at `argus/standards/backend/api.md`.
   d. De-duplicate files in your list of file references.

The compiled list of standards should look like this, where each file reference is on its own line and begins with `@`. The exact list of files will vary:

```
@argus/standards/global/coding-style.md
@argus/standards/global/conventions.md
@argus/standards/global/tech-stack.md
@argus/standards/backend/api.md
@argus/standards/backend/migrations.md
@argus/standards/testing/test-writing.md
```

##### Verifier prompt file content template:

```markdown
We're verifying the implementation of [spec-title] by running verification for tasks under the [verifier-role-name] role's purview.

## Task groups under your verification purview

The following task groups have been implemented and need your verification:

[task-groups-list]

## Understand the context

Read @argus/specs/[this-spec]/spec.md to understand the context for this spec and where these tasks fit into it.

## Your verification responsibilities

{{workflows/implementation/verifier-responsibilities}}

## User Standards & Preferences Compliance

IMPORTANT: Ensure that your verification work validates ALIGNMENT and IDENTIFIES CONFLICTS with the user's preferences and standards as detailed in the following files:

[verifier-standards]

```

### Step 3: Generate the final verification prompt

After all verifier-specific prompts have been created, create ONE final verification prompt that will perform the end-to-end verification.

#### Step 3a. Create the final verification prompt markdown file

Create the prompt markdown file using this naming convention:
`argus/specs/[this-spec]/implementation/prompts/[next-number]-verify-implementation.md`

For example, if the last verifier prompt was `6-verify-frontend.md`, create `7-verify-implementation.md`.

#### Step 3b. Populate the final verification prompt file

Use the following content template for the final verification prompt:

```markdown
We're completing the verification process for [spec-title] by performing the final end-to-end verification and producing the final verification report.

## Understand the context

Read @argus/specs/[this-spec]/spec.md to understand the full context of this spec.

## Your role

You are performing the final implementation verification using the **implementation-verifier** role.

## Perform final verification

Follow the implementation-verifier workflow to complete your verification:

### Step 1: Ensure tasks.md has been updated

{{workflows/implementation/verification/verify-tasks}}

### Step 2: Verify that implementations and verifications have been documented

{{workflows/implementation/verification/verify-documentation}}

### Step 3: Update roadmap (if applicable)

{{workflows/implementation/verification/update-roadmap}}

### Step 4: Run entire tests suite

{{workflows/implementation/verification/run-all-tests}}

### Step 5: Create final verification report

{{workflows/implementation/verification/create-verification-report}}

```

### Step 4: Output the list of created verification prompt files

Output to user the following:

"Ready to begin verification of [spec-title]!

Use the following list of verification prompts to direct the verification process:

[list all verification prompt files in order]

Input those prompts into this chat one-by-one or queue them to run in order.

Verification results will be documented in `argus/specs/[this-spec]/verification/`"
