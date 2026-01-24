#!/usr/bin/env python3
"""
Feedback Collection System for Argus
Collects user feedback on finding accuracy to improve AI triage over time

Features:
- Mark findings as true positive (TP) or false positive (FP)
- Store feedback with reasoning for continuous learning
- Retrieve similar past findings for few-shot prompting
- Generate few-shot examples from historical feedback
- Export feedback for model fine-tuning
"""

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FeedbackCollector:
    """Collect user feedback on finding accuracy to improve AI triage"""

    def __init__(self, feedback_dir: str = ".argus/feedback"):
        """
        Initialize feedback collector

        Args:
            feedback_dir: Directory to store feedback logs (default: .argus/feedback)
        """
        self.feedback_dir = Path(feedback_dir)
        self.feedback_file = self.feedback_dir / "feedback.jsonl"

        # Ensure feedback directory exists
        self.feedback_dir.mkdir(parents=True, exist_ok=True)

    def record_feedback(
        self,
        finding_id: str,
        feedback: Literal["tp", "fp"],
        reason: str,
        finding_details: Optional[Dict[str, Any]] = None,
        user: str = "user"
    ) -> bool:
        """
        Store feedback for future model improvement

        Args:
            finding_id: Unique identifier for the finding
            feedback: "tp" (true positive) or "fp" (false positive)
            reason: User's explanation for why this is TP/FP
            finding_details: Optional additional context about the finding
            user: Username/identifier of person providing feedback

        Returns:
            True if feedback recorded successfully, False otherwise
        """
        if feedback not in ["tp", "fp"]:
            logger.error(f"Invalid feedback value: {feedback}. Must be 'tp' or 'fp'")
            return False

        try:
            feedback_entry = {
                "finding_id": finding_id,
                "feedback": feedback,
                "feedback_label": "true_positive" if feedback == "tp" else "false_positive",
                "reason": reason,
                "user": user,
                "timestamp": datetime.utcnow().isoformat(),
            }

            # Include finding details if provided
            if finding_details:
                feedback_entry["finding"] = {
                    "scanner": finding_details.get("scanner"),
                    "finding_type": finding_details.get("type"),
                    "severity": finding_details.get("severity"),
                    "file_path": finding_details.get("file_path"),
                    "description": finding_details.get("description", "")[:200],  # Truncate
                }

            # Append to feedback log (JSONL format)
            with open(self.feedback_file, "a") as f:
                f.write(json.dumps(feedback_entry) + "\n")

            logger.info(
                f"Recorded feedback: finding={finding_id}, "
                f"feedback={feedback}, reason='{reason[:50]}...'"
            )

            return True

        except Exception as e:
            logger.error(f"Failed to record feedback: {e}")
            return False

    def get_all_feedback(
        self,
        feedback_type: Optional[Literal["tp", "fp"]] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve all feedback entries

        Args:
            feedback_type: Filter by "tp" or "fp" (None = all)

        Returns:
            List of feedback entries
        """
        if not self.feedback_file.exists():
            logger.debug("No feedback file found")
            return []

        try:
            feedback_list = []

            with open(self.feedback_file, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line)

                        # Apply filter if specified
                        if feedback_type and entry.get("feedback") != feedback_type:
                            continue

                        feedback_list.append(entry)

                    except json.JSONDecodeError:
                        logger.debug(f"Skipping corrupt feedback line: {line[:50]}")
                        continue

            logger.debug(f"Loaded {len(feedback_list)} feedback entries")
            return feedback_list

        except Exception as e:
            logger.error(f"Failed to load feedback: {e}")
            return []

    def get_feedback_by_id(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve feedback for a specific finding

        Args:
            finding_id: Finding identifier

        Returns:
            Feedback entry or None if not found
        """
        all_feedback = self.get_all_feedback()

        for entry in all_feedback:
            if entry.get("finding_id") == finding_id:
                return entry

        return None

    def get_similar_findings(
        self,
        finding_type: str,
        scanner: str,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Retrieve past feedback for similar findings (for few-shot prompting)

        Similarity is determined by:
        - Same scanner
        - Same finding type
        - Recent feedback preferred

        Args:
            finding_type: Type of finding to match
            scanner: Scanner name to match
            limit: Maximum number of similar findings to return

        Returns:
            List of similar feedback entries (most recent first)
        """
        all_feedback = self.get_all_feedback()

        # Filter by scanner and finding type
        similar = []
        for entry in all_feedback:
            finding = entry.get("finding", {})
            if (finding.get("scanner") == scanner and
                finding.get("finding_type") == finding_type):
                similar.append(entry)

        # Sort by timestamp (most recent first)
        similar.sort(
            key=lambda x: x.get("timestamp", ""),
            reverse=True
        )

        return similar[:limit]

    def generate_few_shot_examples(
        self,
        finding_type: str,
        scanner: str,
        max_examples: int = 3
    ) -> str:
        """
        Generate few-shot prompt examples from historical feedback

        Args:
            finding_type: Type of finding to match
            scanner: Scanner name to match
            max_examples: Maximum number of examples to include

        Returns:
            Formatted few-shot examples string for AI prompts
        """
        similar = self.get_similar_findings(finding_type, scanner, limit=max_examples)

        if not similar:
            return ""

        examples = []
        examples.append("Here are similar findings from the past and user feedback:\n")

        for i, entry in enumerate(similar, 1):
            finding = entry.get("finding", {})
            feedback_label = entry.get("feedback_label", "unknown")
            reason = entry.get("reason", "")

            example = f"""
Example {i}:
Finding Type: {finding.get('finding_type', 'unknown')}
Scanner: {finding.get('scanner', 'unknown')}
Description: {finding.get('description', '')[:150]}
User Feedback: {feedback_label.upper()}
Reason: {reason}
"""
            examples.append(example.strip())

        examples.append("\nUse these examples to inform your analysis of the current finding.\n")

        return "\n".join(examples)

    def get_feedback_stats(self) -> Dict[str, Any]:
        """
        Get statistics about collected feedback

        Returns:
            Dictionary with feedback stats:
            - total_feedback: Total feedback entries
            - true_positives: Count of TP feedback
            - false_positives: Count of FP feedback
            - tp_rate: Percentage of findings marked as TP
            - fp_rate: Percentage of findings marked as FP
            - by_scanner: Per-scanner breakdown
            - by_finding_type: Per-finding-type breakdown
            - recent_feedback: Last 5 feedback entries
        """
        all_feedback = self.get_all_feedback()

        if not all_feedback:
            return {"total_feedback": 0}

        total = len(all_feedback)
        tp_count = sum(1 for f in all_feedback if f.get("feedback") == "tp")
        fp_count = sum(1 for f in all_feedback if f.get("feedback") == "fp")

        # Per-scanner stats
        by_scanner = {}
        for entry in all_feedback:
            scanner = entry.get("finding", {}).get("scanner", "unknown")
            if scanner not in by_scanner:
                by_scanner[scanner] = {"tp": 0, "fp": 0, "total": 0}

            feedback_type = entry.get("feedback")
            if feedback_type in ["tp", "fp"]:
                by_scanner[scanner][feedback_type] += 1
                by_scanner[scanner]["total"] += 1

        # Per-finding-type stats
        by_finding_type = {}
        for entry in all_feedback:
            finding_type = entry.get("finding", {}).get("finding_type", "unknown")
            if finding_type not in by_finding_type:
                by_finding_type[finding_type] = {"tp": 0, "fp": 0, "total": 0}

            feedback_type = entry.get("feedback")
            if feedback_type in ["tp", "fp"]:
                by_finding_type[finding_type][feedback_type] += 1
                by_finding_type[finding_type]["total"] += 1

        # Recent feedback (last 5)
        recent = all_feedback[-5:]

        stats = {
            "total_feedback": total,
            "true_positives": tp_count,
            "false_positives": fp_count,
            "tp_rate": (tp_count / total * 100) if total > 0 else 0.0,
            "fp_rate": (fp_count / total * 100) if total > 0 else 0.0,
            "by_scanner": by_scanner,
            "by_finding_type": by_finding_type,
            "recent_feedback": [
                {
                    "finding_id": f.get("finding_id"),
                    "feedback": f.get("feedback"),
                    "reason": f.get("reason", "")[:50],
                    "timestamp": f.get("timestamp"),
                }
                for f in recent
            ],
        }

        return stats

    def export_for_training(self, output_file: str) -> bool:
        """
        Export feedback in format suitable for model fine-tuning

        Args:
            output_file: Path to output file (JSONL format)

        Returns:
            True if exported successfully, False otherwise
        """
        try:
            all_feedback = self.get_all_feedback()

            if not all_feedback:
                logger.warning("No feedback to export")
                return False

            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w") as f:
                for entry in all_feedback:
                    # Format for fine-tuning (OpenAI/Anthropic format)
                    finding = entry.get("finding", {})
                    feedback_label = entry.get("feedback_label")
                    reason = entry.get("reason", "")

                    training_example = {
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are a security analysis expert. Evaluate if findings are true positives or false positives."
                            },
                            {
                                "role": "user",
                                "content": f"Finding Type: {finding.get('finding_type')}\n"
                                          f"Scanner: {finding.get('scanner')}\n"
                                          f"Description: {finding.get('description')}\n"
                                          f"Is this a true positive or false positive?"
                            },
                            {
                                "role": "assistant",
                                "content": f"{feedback_label.upper()}: {reason}"
                            }
                        ]
                    }

                    f.write(json.dumps(training_example) + "\n")

            logger.info(f"Exported {len(all_feedback)} feedback entries to {output_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to export feedback: {e}")
            return False

    def clear_feedback(self) -> bool:
        """
        Clear all feedback (use with caution!)

        Returns:
            True if cleared successfully, False otherwise
        """
        try:
            if self.feedback_file.exists():
                self.feedback_file.unlink()
                logger.warning("Cleared all feedback entries")

            return True

        except Exception as e:
            logger.error(f"Failed to clear feedback: {e}")
            return False


def main():
    """CLI interface for feedback management"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Manage user feedback on security findings"
    )
    parser.add_argument(
        "--feedback-dir",
        default=".argus/feedback",
        help="Feedback directory path"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Record feedback
    record_parser = subparsers.add_parser("record", help="Record feedback for a finding")
    record_parser.add_argument("finding_id", help="Finding ID")
    record_parser.add_argument(
        "--mark",
        choices=["tp", "fp"],
        required=True,
        help="Mark as true positive (tp) or false positive (fp)"
    )
    record_parser.add_argument("--reason", required=True, help="Reason for feedback")

    # Show stats
    subparsers.add_parser("stats", help="Show feedback statistics")

    # Export for training
    export_parser = subparsers.add_parser("export", help="Export feedback for model training")
    export_parser.add_argument("output_file", help="Output file path")

    # List feedback
    list_parser = subparsers.add_parser("list", help="List all feedback")
    list_parser.add_argument(
        "--type",
        choices=["tp", "fp"],
        help="Filter by feedback type"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    collector = FeedbackCollector(args.feedback_dir)

    if args.command == "record":
        success = collector.record_feedback(
            finding_id=args.finding_id,
            feedback=args.mark,
            reason=args.reason
        )
        if success:
            print(f"✅ Recorded feedback: {args.mark.upper()} for finding {args.finding_id}")
        else:
            print("❌ Failed to record feedback")
            return 1

    elif args.command == "stats":
        stats = collector.get_feedback_stats()

        print("\n" + "=" * 60)
        print("FEEDBACK STATISTICS")
        print("=" * 60)
        print(f"Total Feedback:     {stats.get('total_feedback', 0)}")
        print(f"True Positives:     {stats.get('true_positives', 0)} ({stats.get('tp_rate', 0):.1f}%)")
        print(f"False Positives:    {stats.get('false_positives', 0)} ({stats.get('fp_rate', 0):.1f}%)")

        if stats.get("by_scanner"):
            print(f"\nBy Scanner:")
            for scanner, scanner_stats in stats["by_scanner"].items():
                fp_rate = (scanner_stats["fp"] / scanner_stats["total"] * 100) if scanner_stats["total"] > 0 else 0
                print(f"  {scanner:20s}: {scanner_stats['total']:3d} total, "
                      f"{scanner_stats['fp']:3d} FP ({fp_rate:.0f}%)")

        if stats.get("recent_feedback"):
            print(f"\nRecent Feedback:")
            for fb in stats["recent_feedback"]:
                print(f"  {fb['finding_id'][:16]}: {fb['feedback'].upper()} - {fb['reason']}")

        print("=" * 60 + "\n")

    elif args.command == "export":
        success = collector.export_for_training(args.output_file)
        if success:
            print(f"✅ Exported feedback to {args.output_file}")
        else:
            print("❌ Failed to export feedback")
            return 1

    elif args.command == "list":
        feedback_list = collector.get_all_feedback(feedback_type=args.type)

        print(f"\n{'='*80}")
        print(f"FEEDBACK LIST ({len(feedback_list)} entries)")
        print("=" * 80)

        for entry in feedback_list:
            finding = entry.get("finding", {})
            print(f"\nFinding ID: {entry.get('finding_id')}")
            print(f"Feedback: {entry.get('feedback_label', 'unknown').upper()}")
            print(f"Reason: {entry.get('reason', '')}")
            print(f"Scanner: {finding.get('scanner', 'unknown')}")
            print(f"Type: {finding.get('finding_type', 'unknown')}")
            print(f"Timestamp: {entry.get('timestamp', '')}")
            print("-" * 80)

    return 0


if __name__ == "__main__":
    exit(main())
