import yaml from "js-yaml";
import { parse as parseToml } from "smol-toml";

export type ConfigFormat = "yaml" | "json" | "toml";

export class ConfigParseError extends Error {
  constructor(message: string, public readonly format?: ConfigFormat) {
    super(message);
    this.name = "ConfigParseError";
  }
}

/**
 * Detect the configuration format from file path or raw string content.
 */
export function detectFormat(content: string, filePath?: string): ConfigFormat {
  if (filePath) {
    const ext = filePath.toLowerCase().split(".").pop();
    if (ext === "json") return "json";
    if (ext === "toml") return "toml";
    if (ext === "yaml" || ext === "yml") return "yaml";
  }

  const trimmed = content.trim();
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    return "json";
  }
  if (/^\s*\[[a-zA-Z0-9_.-]+\]\s*$/m.test(trimmed)) {
    return "toml";
  }

  // Default to YAML since JSON is a subset of YAML
  return "yaml";
}

/**
 * Parse a configuration string in YAML, JSON, or TOML into a plain JavaScript mapping.
 */
export function parseConfig(
  content: string,
  sourceName = "Configuration",
  forcedFormat?: ConfigFormat
): Record<string, any> {
  const format = forcedFormat || detectFormat(content, sourceName);

  try {
    let result: any;

    if (format === "json") {
      result = JSON.parse(content);
    } else if (format === "toml") {
      result = parseToml(content);
    } else {
      result = yaml.load(content);
    }

    if (!result || typeof result !== "object" || Array.isArray(result)) {
      throw new ConfigParseError(
        `${sourceName} must contain a key-value mapping (found ${Array.isArray(result) ? "list" : typeof result}).`,
        format
      );
    }

    return result as Record<string, any>;
  } catch (error: any) {
    if (error instanceof ConfigParseError) {
      throw error;
    }
    throw new ConfigParseError(
      `Failed to parse ${sourceName} as ${format.toUpperCase()}: ${error.message}`,
      format
    );
  }
}
