import argparse
import sys

from driftguard.detector import detect_drift, load_config
from driftguard.policies import evaluate_findings, should_block
from driftguard.reporter import (
    format_terminal_report,
    generate_report,
    save_json_report,
    save_markdown_report,
)


def main():
    parser = argparse.ArgumentParser(
        description="DriftGuard configuration drift detector"
    )

    parser.add_argument(
        "--expected",
        default="config/expected.yaml",
        help="Path to expected configuration",
    )

    parser.add_argument(
        "--actual",
        default="config/actual.yaml",
        help="Path to actual configuration",
    )

    args = parser.parse_args()

    try:
        expected = load_config(args.expected)
        actual = load_config(args.actual)

        differences = detect_drift(expected, actual)
        findings = evaluate_findings(differences)

        report = generate_report(
            args.expected,
            args.actual,
            findings,
        )

        print(format_terminal_report(report))

        json_path = save_json_report(report)
        markdown_path = save_markdown_report(report)

        print(f"\nJSON report: {json_path}")
        print(f"Markdown report: {markdown_path}")

        if should_block(findings):
            print("\nRESULT: Critical configuration drift detected.")
            return 1

        print("\nRESULT: No critical configuration drift detected.")
        return 0

    except (OSError, ValueError) as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

