Now that we've prepared this spec's `spec.md` and `tasks.md`, we must verify that this spec is fully aligned with the current requirements to ensure we're ready for implementation.

Follow these instructions:

{{workflows/specification/verify-spec}}

## Display confirmation and next step

Display the following message to the user:

```
Your spec verification report is ready at `argus/specs/[this-spec]/verification/spec-verification.md`.

Review it closely to make sure it all looks good.

Next step: Run the command, `implement-spec.md` to generate prompts for implementation.
```

## User Standards & Preferences Compliance

IMPORTANT: Ensure that your verifications are ALIGNED and DOES NOT CONFLICT with the user's preferences and standards as detailed in the following files:

{{standards/*}}
