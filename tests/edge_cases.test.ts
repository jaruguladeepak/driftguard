import { describe, it, expect } from "vitest";
import { parseConfig, ConfigParseError } from "../src/core/parser";
import { detectDrift } from "../src/core/detector";
import { evaluateFindings, shouldBlock } from "../src/core/policies";
import { generateReport, generateMarkdownReport, maskSensitiveValue } from "../src/core/reporter";

describe("Secret Redaction Security Edge Cases", () => {
  it("masks plaintext API keys and secrets", () => {
    expect(maskSensitiveValue("auth.api_key", "sk_live_999999", "CIS-SEC-1")).toBe("[REDACTED_SECRET]");
    expect(maskSensitiveValue("database.password", "p@ssw0rd", "CIS-SEC-1")).toBe("[REDACTED_SECRET]");
    expect(maskSensitiveValue("app.secret_token", "jwt_token_here")).toBe("[REDACTED_SECRET]");
  });

  it("does not redact environment variable placeholders", () => {
    expect(maskSensitiveValue("auth.api_key", "${ENV_STRIPE_KEY}", "CIS-SEC-1")).toBe("${ENV_STRIPE_KEY}");
  });

  it("redacts exposed secrets from generated reports", () => {
    const diffs = detectDrift(
      { auth: { api_key: null } },
      { auth: { api_key: "sk_live_secret_key_12345" } }
    );
    const findings = evaluateFindings(diffs);
    const report = generateReport("exp.yaml", "act.yaml", findings);

    expect(report.findings[0].actual).toBe("[REDACTED_SECRET]");
    const md = generateMarkdownReport(report);
    expect(md).toContain("[REDACTED_SECRET]");
    expect(md).not.toContain("sk_live_secret_key_12345");
  });
});

describe("Parser Error Handling Edge Cases", () => {
  it("handles malformed JSON with clear error", () => {
    expect(() => parseConfig("{ invalid_json: true }", "bad.json", "json")).toThrow(ConfigParseError);
  });

  it("handles malformed TOML with clear error", () => {
    expect(() => parseConfig("[unclosed_table\nval = 1", "bad.toml", "toml")).toThrow(ConfigParseError);
  });

  it("rejects non-object root payloads (e.g. primitive values)", () => {
    expect(() => parseConfig('"plain string"', "scalar.json")).toThrow(ConfigParseError);
    expect(() => parseConfig("42", "number.yaml")).toThrow(ConfigParseError);
  });
});

describe("TLS Version Edge Cases", () => {
  it("identifies TLS 1.0 and 1.1 as critical, allows 1.2 and 1.3", () => {
    const testCases = [
      { version: "1.0", expectedCritical: true },
      { version: "1.1", expectedCritical: true },
      { version: 1.0, expectedCritical: true },
      { version: "1.2", expectedCritical: false },
      { version: "1.3", expectedCritical: false },
    ];

    for (const { version, expectedCritical } of testCases) {
      const diffs = detectDrift(
        { security: { tls_version: "1.3" } },
        { security: { tls_version: version } }
      );
      const findings = evaluateFindings(diffs);
      expect(shouldBlock(findings)).toBe(expectedCritical);
    }
  });
});
