from pathlib import Path
from typing import Any

import yaml


def load_config(path: str | Path) -> dict[str, Any]:
    """Load and validate a YAML configuration file."""
    with open(path, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not isinstance(data, dict):
        raise ValueError(
            f"Configuration must contain a YAML mapping: {path}"
        )

    return data


def detect_drift(
    expected: dict[str, Any],
    actual: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detect added, removed, and changed configuration values."""
    differences = []

    def compare(expected_value, actual_value, path=""):
        if isinstance(expected_value, dict) and isinstance(actual_value, dict):
            keys = sorted(set(expected_value) | set(actual_value))

            for key in keys:
                current_path = f"{path}.{key}" if path else key

                if key not in expected_value:
                    differences.append({
                        "setting": current_path,
                        "expected": None,
                        "actual": actual_value[key],
                        "change": "added",
                    })

                elif key not in actual_value:
                    differences.append({
                        "setting": current_path,
                        "expected": expected_value[key],
                        "actual": None,
                        "change": "removed",
                    })

                else:
                    compare(
                        expected_value[key],
                        actual_value[key],
                        current_path,
                    )

        elif expected_value != actual_value:
            differences.append({
                "setting": path,
                "expected": expected_value,
                "actual": actual_value,
                "change": "changed",
            })

    compare(expected, actual)
    return differences

