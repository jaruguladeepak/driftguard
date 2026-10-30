import yaml from "js-yaml";
import { DriftDifference } from "./types";

/**
 * Parse a YAML string into a plain JavaScript object mapping.
 */
export function parseConfig(yamlContent: string, sourceName = "Configuration"): Record<string, any> {
  const data = yaml.load(yamlContent);

  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new ValueError(`${sourceName} must contain a YAML mapping.`);
  }

  return data as Record<string, any>;
}

export class ValueError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValueError";
  }
}

/**
 * Detect added, removed, and changed configuration values between expected and actual maps.
 */
export function detectDrift(
  expected: Record<string, any>,
  actual: Record<string, any>
): DriftDifference[] {
  const differences: DriftDifference[] = [];

  function isPlainObject(val: any): boolean {
    return val !== null && typeof val === "object" && !Array.isArray(val);
  }

  function compare(expectedVal: any, actualVal: any, currentPath = "") {
    if (isPlainObject(expectedVal) && isPlainObject(actualVal)) {
      const keys = Array.from(
        new Set([...Object.keys(expectedVal), ...Object.keys(actualVal)])
      ).sort();

      for (const key of keys) {
        const path = currentPath ? `${currentPath}.${key}` : key;

        if (!(key in expectedVal)) {
          differences.push({
            setting: path,
            expected: null,
            actual: actualVal[key],
            change: "added",
          });
        } else if (!(key in actualVal)) {
          differences.push({
            setting: path,
            expected: expectedVal[key],
            actual: null,
            change: "removed",
          });
        } else {
          compare(expectedVal[key], actualVal[key], path);
        }
      }
    } else if (expectedVal !== actualVal) {
      differences.push({
        setting: currentPath,
        expected: expectedVal,
        actual: actualVal,
        change: "changed",
      });
    }
  }

  compare(expected, actual);
  return differences;
}

