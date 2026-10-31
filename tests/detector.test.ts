import { describe, it, expect } from "vitest";
import { detectDrift, parseConfig, ValueError } from "../src/core/detector";
import { detectFormat } from "../src/core/parser";
import { evaluateFindings, shouldBlock } from "../src/core/policies";

describe("detectDrift", () => {
  it("detects changed setting", () => {
    const expected = { app: { port: 8000 } };
    const actual = { app: { port: 9000 } };

    const differences = detectDrift(expected, actual);

    expect(differences).toHaveLength(1);
    expect(differences[0].setting).toBe("app.port");
    expect(differences[0].expected).toBe(8000);
    expect(differences[0].actual).toBe(9000);
    expect(differences[0].change).toBe("changed");
  });

  it("detects added setting", () => {
    const expected = { app: { port: 8000 } };
    const actual = { app: { port: 8000, debug: true } };

    const differences = detectDrift(expected, actual);

    expect(differences).toHaveLength(1);
    expect(differences[0].setting).toBe("app.debug");
    expect(differences[0].change).toBe("added");
    expect(differences[0].actual).toBe(true);
  });

  it("detects removed setting", () => {
    const expected = { app: { port: 8000, debug: false } };
    const actual = { app: { port: 8000 } };

    const differences = detectDrift(expected, actual);

    expect(differences).toHaveLength(1);
    expect(differences[0].setting).toBe("app.debug");
    expect(differences[0].change).toBe("removed");
    expect(differences[0].expected).toBe(false);
  });

  it("identifies critical finding blocks deployment", () => {
    const differences = detectDrift(
      { app: { debug: false } },
      { app: { debug: true } }
    );

    const findings = evaluateFindings(differences);

    expect(findings[0].severity).toBe("CRITICAL");
    expect(shouldBlock(findings)).toBe(true);
  });

  it("reports empty configurations have no drift", () => {
    expect(detectDrift({}, {})).toEqual([]);
  });

  it("detects nested configuration addition", () => {
    const expected = { app: { port: 8000 } };
    const actual = {
      app: {
        port: 8000,
        logging: { level: "debug" },
      },
    };

    const differences = detectDrift(expected, actual);

    expect(differences).toHaveLength(1);
    expect(differences[0].setting).toBe("app.logging");
    expect(differences[0].change).toBe("added");
  });

  it("classifies removed https setting as critical", () => {
    const differences = detectDrift(
      { security: { https_required: true } },
      { security: {} }
    );

    const findings = evaluateFindings(differences);

    expect(findings[0].severity).toBe("CRITICAL");
    expect(shouldBlock(findings)).toBe(true);
  });

  it("rejects invalid YAML shape", () => {
    expect(() => {
      parseConfig("- item1\n- item2\n");
    }).toThrow(ValueError);
  });
});

describe("Multi-format Parser (YAML, JSON, TOML)", () => {
  it("parses valid JSON configuration", () => {
    const jsonStr = '{"app": {"port": 8080, "name": "service"}}';
    const parsed = parseConfig(jsonStr, "config.json");
    expect(parsed.app.port).toBe(8080);
    expect(parsed.app.name).toBe("service");
  });

  it("parses valid TOML configuration", () => {
    const tomlStr = `
[app]
port = 9090
name = "service-toml"

[security]
https_required = true
`;
    const parsed = parseConfig(tomlStr, "config.toml");
    expect(parsed.app.port).toBe(9090);
    expect(parsed.security.https_required).toBe(true);
  });

  it("auto-detects format from extension and content", () => {
    expect(detectFormat("{}", "app.json")).toBe("json");
    expect(detectFormat("[server]\nport = 80", "app.toml")).toBe("toml");
    expect(detectFormat("server:\n  port: 80", "app.yaml")).toBe("yaml");
  });
});

describe("CIS Benchmark Security Policies", () => {
  it("blocks insecure TLS versions (CIS-TLS-1)", () => {
    const diffs = detectDrift(
      { security: { tls_version: "1.3" } },
      { security: { tls_version: "1.0" } }
    );
    const findings = evaluateFindings(diffs);
    expect(findings[0].severity).toBe("CRITICAL");
    expect(findings[0].ruleId).toBe("CIS-TLS-1");
    expect(shouldBlock(findings)).toBe(true);
  });

  it("blocks root user execution (CIS-IAM-1)", () => {
    const diffs = detectDrift(
      { process: { user: "appuser" } },
      { process: { user: "root" } }
    );
    const findings = evaluateFindings(diffs);
    expect(findings[0].severity).toBe("CRITICAL");
    expect(findings[0].ruleId).toBe("CIS-IAM-1");
    expect(shouldBlock(findings)).toBe(true);
  });

  it("blocks plaintext secret exposure in config (CIS-SEC-1)", () => {
    const diffs = detectDrift(
      { auth: { api_key: null } },
      { auth: { api_key: "sk_live_1234567890abcdef" } }
    );
    const findings = evaluateFindings(diffs);
    expect(findings[0].severity).toBe("CRITICAL");
    expect(findings[0].ruleId).toBe("CIS-SEC-1");
    expect(shouldBlock(findings)).toBe(true);
  });

  it("blocks exposure of sensitive management ports (CIS-NET-2)", () => {
    const diffs = detectDrift(
      { server: { port: 8080 } },
      { server: { port: 22 } }
    );
    const findings = evaluateFindings(diffs);
    expect(findings[0].severity).toBe("CRITICAL");
    expect(findings[0].ruleId).toBe("CIS-NET-2");
    expect(shouldBlock(findings)).toBe(true);
  });

  it("blocks wildcard CORS in production (CIS-CORS-1)", () => {
    const diffs = detectDrift(
      { security: { cors_origin: "https://example.com" } },
      { security: { cors_origin: "*" } }
    );
    const findings = evaluateFindings(diffs);
    expect(findings[0].severity).toBe("CRITICAL");
    expect(findings[0].ruleId).toBe("CIS-CORS-1");
    expect(shouldBlock(findings)).toBe(true);
  });
});
