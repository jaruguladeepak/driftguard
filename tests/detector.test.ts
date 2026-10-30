import { describe, it, expect } from "vitest";
import { detectDrift, parseConfig, ValueError } from "../src/core/detector";
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

