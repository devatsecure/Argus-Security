#!/usr/bin/env python3
"""
CLI tool for managing feedback loop
"""

import argparse
import sys
from feedback_loop import FeedbackLoop


def main():
    parser = argparse.ArgumentParser(description="Feedback Loop Management")
    subparsers = parser.add_subparsers(dest="command", help="Command")

    # Record feedback
    record_parser = subparsers.add_parser("record", help="Record human verdict")
    record_parser.add_argument("--finding-id", required=True)
    record_parser.add_argument("--automated", required=True, choices=["confirmed", "false_positive", "uncertain"])
    record_parser.add_argument("--human", required=True, choices=["confirmed", "false_positive"])
    record_parser.add_argument("--confidence", type=float, required=True)
    record_parser.add_argument("--pattern", default=None)
    record_parser.add_argument("--category", required=True)
    record_parser.add_argument("--reasoning", default="")

    # Show statistics
    subparsers.add_parser("stats", help="Show feedback statistics")

    # Show pattern accuracy
    accuracy_parser = subparsers.add_parser("accuracy", help="Show pattern accuracy")
    accuracy_parser.add_argument("--pattern", required=True)

    # Suggest adjustments
    tune_parser = subparsers.add_parser("tune", help="Suggest confidence adjustments")
    tune_parser.add_argument("--min-samples", type=int, default=10)
    tune_parser.add_argument("--apply", action="store_true", help="Apply adjustments (not dry-run)")

    args = parser.parse_args()
    feedback_loop = FeedbackLoop()

    if args.command == "record":
        record = feedback_loop.record_verdict(
            finding_id=args.finding_id,
            automated_verdict=args.automated,
            human_verdict=args.human,
            confidence=args.confidence,
            pattern_used=args.pattern,
            finding_category=args.category,
            reasoning=args.reasoning
        )
        print(f"Recorded: {'Correct' if record.is_correct else 'Incorrect'}")
        if record.error_type:
            print(f"   Error type: {record.error_type}")

    elif args.command == "stats":
        stats = feedback_loop.get_statistics()
        print(f"Total records: {stats['total_records']}")
        if stats['total_records'] > 0:
            print(f"Accuracy: {stats['accuracy']:.1%}")
            print(f"False negatives: {stats['false_negatives']}")
            print(f"False positives: {stats['false_positives']}")
            print(f"Patterns tracked: {stats['patterns_tracked']}")
        else:
            print("No feedback records yet. Use 'record' command to add data.")

    elif args.command == "accuracy":
        accuracy = feedback_loop.calculate_pattern_accuracy(args.pattern, args.pattern)
        print(f"Pattern: {args.pattern}")
        print(f"Samples: {accuracy.total_samples}")
        print(f"Accuracy: {accuracy.accuracy:.1%}")
        print(f"Precision: {accuracy.precision:.1%}")
        print(f"Recall: {accuracy.recall:.1%}")
        print(f"F1 Score: {accuracy.f1_score:.2f}")

    elif args.command == "tune":
        adjustments = feedback_loop.suggest_confidence_adjustments(args.min_samples)
        print(f"Found {len(adjustments)} patterns with sufficient data:\n")

        for adj in adjustments:
            print(f"Pattern: {adj.pattern_id}")
            print(f"  Current: {adj.current_multiplier:.2f}")
            print(f"  Recommended: {adj.recommended_multiplier:.2f}")
            print(f"  Samples: {adj.sample_size}")
            print(f"  Reasoning: {adj.reasoning}")
            print()

        if adjustments and not args.apply:
            print("Run with --apply to apply these adjustments")
        elif adjustments and args.apply:
            feedback_loop.apply_adjustments(adjustments, dry_run=False)
            print("Adjustments applied")


if __name__ == "__main__":
    main()
