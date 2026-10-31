import { describe, it, expect } from "vitest";
import { parseConfig, ConfigParseError, sanitizeErrorMessage } from "../src/core/parser";
import { detectDrift } from "../src/core/detector";
import { evaluateFindings, shouldBlock } from "../src/core/policies";
import {
  generateReport,
  generateMarkdownReport,
  formatTerminalReport,
  maskSensitiveValue,
} from "../src/core/reporter";

describe("Secret Redaction Security Edge Cases", () => {
  it("masks plaintext API keys, passwords, and tokens", () => {
    expect(maskSensitiveValue("auth.api_key", "sk_live_999999", "CIS-SEC-1")).toBe("[REDACTED_SECRET]");
    expect(maskSensitiveValue("database.password", "p@ssw0rd", "CIS-SEC-1")).toBe("[REDACTED_SECRET]");
    expect(maskSensitiveValue("database.db_pass", "secret123")).toBe("[REDACTED_SECRET]");
    expect(maskSensitiveValue("oauth.client_secret", "client_sec_val")).toBe("[REDACTED_SECRET]");
    expect(maskSensitiveValue("service.auth_token", "jwt_token_here")).toBe("[REDACTED_SECRET]");
    expect(maskSensitiveValue("cloud.credentials", "aws_sec_key")).toBe("[REDACTED_SECRET]");
  });

  it("masks nested secret structures in objects and arrays", () => {
    const nested = {
      user: "alice",
      token: "secret_token_123",
      db: {
        password: "super_secret_db_pass",
        port: 5432,
      },
    };
    const sanitized = maskSensitiveValue("credentials", nested);
    expect(sanitized.user).toBe("alice");
    expect(sanitized.token).toBe("[REDACTED_SECRET]");
    expect(sanitized.db.password).toBe("[REDACTED_SECRET]");
    expect(sanitized.db.port).toBe(5432);

    const arraySecrets = ["regular_val", "another_val"];
    const arraySanitized = maskSensitiveValue("tokens", arraySecrets);
    expect(arraySanitized[0]).toBe("[REDACTED_SECRET]");
    expect(arraySanitized[1]).toBe("[REDACTED_SECRET]");
  });

  it("does not redact environment variable placeholders", () => {
    expect(maskSensitiveValue("auth.api_key", "${ENV_STRIPE_KEY}", "CIS-SEC-1")).toBe("${ENV_STRIPE_KEY}");
    expect(maskSensitiveValue("database.password", "${DB_PASSWORD}")).toBe("${DB_PASSWORD}");
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

    const term = formatTerminalReport(report);
    expect(term).toContain("[REDACTED_SECRET]");
    expect(term).not.toContain("sk_live_secret_key_12345");
  });
});

describe("Parser Error Handling & Secret Leak Prevention", () => {
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

  it("sanitizes potential secret tokens from parser error messages", () => {
    const rawError = "YAML error: api_key: 'sk_live_secret_leaked_token' at line 4";
    const sanitized = sanitizeErrorMessage(rawError);
    expect(sanitized).toContain("[REDACTED_SECRET]");
    expect(sanitized).not.toContain("sk_live_secret_leaked_token");

    const rawPassError = "Syntax error near password: my_raw_database_password";
    const sanitizedPass = sanitizeErrorMessage(rawPassError);
    expect(sanitizedPass).toContain("[REDACTED_SECRET]");
    expect(sanitizedPass).not.toContain("my_raw_database_password");
  });
});

describe("TLS Version Edge Cases", () => {
  it("identifies TLS 1.0, 1.1 and prefix variants as critical", () => {
    const insecureCases = ["1.0", "1.1", 1.0, 1.1, "v1.0", "v1.1", "TLSv1.0", "TLS 1.0", "TLS 1.1"];
    for (const ver of insecureCases) {
      const diffs = detectDrift(
        { security: { tls_version: "1.3" } },
        { security: { tls_version: ver } }
      );
      const findings = evaluateFindings(diffs);
      expect(shouldBlock(findings)).toBe(true);
    }
  });

  it("allows modern TLS 1.2, 1.3 and formatted strings", () => {
    const secureCases = ["1.2", "1.3", 1.2, 1.3, "v1.2", "TLSv1.2", "TLSv1.3", "TLS 1.3"];
    for (const ver of secureCases) {
      const diffs = detectDrift(
        { security: { tls_version: "1.3" } },
        { security: { tls_version: ver } }
      );
      const findings = evaluateFindings(diffs);
      expect(shouldBlock(findings)).toBe(false);
    }
  });

  it("gracefully handles null, empty, or non-numeric TLS values without exceptions", () => {
    const edgeCases = [null, "", true, false, "unknown"];
    for (const val of edgeCases) {
      const diffs = detectDrift(
        { security: { tls_version: "1.3" } },
        { security: { tls_version: val } }
      );
      expect(() => evaluateFindings(diffs)).not.toThrow();
    }
  });
});

describe("Network Port Boundary Edge Cases", () => {
  it("flags insecure management ports 22, 23, 3389", () => {
    const portCases = [
      { setting: "app.port", port: 22 },
      { setting: "server.listen_port", port: 23 },
      { setting: "remote.rdp_port", port: 3389 },
      { setting: "network.ports", port: [80, 22, 443] },
    ];

    for (const { setting, port } of portCases) {
      const diffs = detectDrift({}, { [setting]: port });
      const findings = evaluateFindings(diffs);
      expect(shouldBlock(findings)).toBe(true);
      const portFinding = findings.find((f) => f.ruleId === "CIS-NET-2");
      expect(portFinding).toBeDefined();
    }
  });

  it("does not false-positive on words ending in 'port' (report, export, support)", () => {
    const nonPortSettings = [
      { setting: "analytics.report", val: 22 },
      { setting: "data.export", val: 23 },
      { setting: "customer.support", val: 3389 },
      { setting: "transport.mode", val: 22 },
      { setting: "airport.code", val: 22 },
    ];

    for (const { setting, val } of nonPortSettings) {
      const diffs = detectDrift({}, { [setting]: val });
      const findings = evaluateFindings(diffs);
      const portFinding = findings.find((f) => f.ruleId === "CIS-NET-2");
      expect(portFinding).toBeUndefined();
      expect(shouldBlock(findings)).toBe(false);
    }
  });
});
