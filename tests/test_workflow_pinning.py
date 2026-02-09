"""Test that all GitHub Actions are pinned by SHA."""
import glob
import re


def _is_action_uses_line(line):
    """Check if a line is an actual GitHub Actions uses: directive.

    Filters out uses: references inside run: script blocks (e.g., embedded
    in markdown/YAML strings within release notes).
    """
    stripped = line.strip()
    # Must start with "uses:" (a YAML key) or "- uses:" (a sequence item)
    if not re.match(r"^-?\s*uses:\s+", stripped):
        return False
    # Skip lines with template expressions (dynamic refs inside strings)
    if "${{" in stripped:
        return False
    return True


def test_all_actions_pinned_by_sha():
    """Every uses: directive should reference a full SHA, not a tag."""
    unpinned = []
    for workflow in glob.glob(".github/workflows/*.yml") + glob.glob(
        ".github/workflows/**/*.yml"
    ):
        with open(workflow) as f:
            for i, line in enumerate(f, 1):
                if not _is_action_uses_line(line):
                    continue
                stripped = line.strip()
                if "@" not in stripped:
                    continue
                # Skip local references
                if "uses: ./" in stripped:
                    continue
                # Skip lines with TODO comments (known unresolvable actions)
                if "# TODO:" in stripped:
                    continue
                # Check if pinned by SHA (40 hex chars after @)
                match = re.search(r"uses:\s+\S+@([a-f0-9]{40})", stripped)
                if not match:
                    unpinned.append(f"{workflow}:{i}: {stripped}")
    assert not unpinned, "Unpinned actions found:\n" + "\n".join(unpinned)


def test_pinned_actions_have_tag_comments():
    """Every SHA-pinned action should have a comment with the original tag."""
    missing_comments = []
    for workflow in glob.glob(".github/workflows/*.yml") + glob.glob(
        ".github/workflows/**/*.yml"
    ):
        with open(workflow) as f:
            for i, line in enumerate(f, 1):
                if not _is_action_uses_line(line):
                    continue
                stripped = line.strip()
                if "@" not in stripped:
                    continue
                # Skip local references
                if "uses: ./" in stripped:
                    continue
                # Skip TODO lines
                if "# TODO:" in stripped:
                    continue
                # Check if pinned by SHA
                sha_match = re.search(r"uses:\s+\S+@([a-f0-9]{40})", stripped)
                if sha_match and "#" not in stripped:
                    missing_comments.append(f"{workflow}:{i}: {stripped}")
    assert not missing_comments, (
        "SHA-pinned actions missing tag comments:\n"
        + "\n".join(missing_comments)
    )
