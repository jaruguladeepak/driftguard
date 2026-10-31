import { DriftDifference, DriftFinding, Severity } from "./types";

interface PolicyRule {
  id: string;
  name: string;
  matches: (diff: DriftDifference) => boolean;
  severity: Severity;
  reason: string;
}

function isPlainObject(val: any): boolean {
  return val !== null && typeof val === "object" && !Array.isArray(val);
}

function matchesSecretPattern(name: string): boolean {
  const leaf = name.split(".").pop() || name;
  const cleanLeaf = leaf.replace(/\[\d+\]$/, "");
  return /(?:secret|api[-_]?key|private[-_]?key|pass(?:word|wd)?|db[-_]?pass|token|credential)/i.test(
    cleanLeaf
  );
}

function containsSecret(val: any, keyName = ""): boolean {
  if (val === null || val === undefined) return false;

  if (isPlainObject(val)) {
    return Object.entries(val).some(([k, v]) => containsSecret(v, k));
  }

  if (Array.isArray(val)) {
    return val.some((item) => containsSecret(item, keyName));
  }

  if (matchesSecretPattern(keyName)) {
    if (typeof val === "string") {
      return val.length > 0 && !val.startsWith("${");
    }
    if (typeof val === "number" || typeof val === "boolean") {
      return true;
    }
  }

  return false;
}

const CIS_SECURITY_RULES: PolicyRule[] = [
  // CIS-APP-1: Production Debug Mode Disabled
  {
    id: "CIS-APP-1",
    name: "Debug Mode Disabled",
    severity: "CRITICAL",
    reason: "Enabling debug mode in production exposes stack traces, sensitive env vars, and profiling endpoints.",
    matches: (d) => d.setting === "app.debug" && d.actual === true,
  },

  // CIS-NET-1: HTTPS Enforcement
  {
    id: "CIS-NET-1",
    name: "Enforce HTTPS Protocol",
    severity: "CRITICAL",
    reason: "Disabling or removing HTTPS allows unencrypted transmission of credentials and session tokens.",
    matches: (d) =>
      d.setting === "security.https_required" &&
      (d.change === "removed" || d.actual !== true),
  },

  // CIS-TLS-1: Minimum TLS Protocol Version
  {
    id: "CIS-TLS-1",
    name: "Minimum TLS 1.2+",
    severity: "CRITICAL",
    reason: "TLS 1.0 and 1.1 are vulnerable to cryptographic downgrade attacks (e.g. POODLE, BEAST).",
    matches: (d) => {
      if (
        d.setting === "security.tls_version" &&
        d.actual !== null &&
        d.actual !== undefined &&
        d.actual !== ""
      ) {
        const cleaned = String(d.actual)
          .trim()
          .replace(/^tls[_\s-]*v?/i, "")
          .replace(/^v/i, "");
        const parsed = parseFloat(cleaned);
        if (!isNaN(parsed)) {
          return parsed < 1.2;
        }
        return cleaned === "1.0" || cleaned === "1.1";
      }
      return false;
    },
  },

  // CIS-IAM-1: Non-Root Execution
  {
    id: "CIS-IAM-1",
    name: "Prohibit Root Execution",
    severity: "CRITICAL",
    reason: "Containers and processes must not execute as root (UID 0) to prevent host privilege escalation.",
    matches: (d) =>
      (d.setting === "process.user" && String(d.actual).toLowerCase() === "root") ||
      (d.setting === "docker.privileged" && d.actual === true),
  },

  // CIS-SEC-1: Secret Exposure in Config
  {
    id: "CIS-SEC-1",
    name: "Plaintext Secret Detection",
    severity: "CRITICAL",
    reason: "Sensitive credentials or tokens should not be stored in static configuration files.",
    matches: (d) => {
      if (d.actual === null || d.actual === undefined) return false;
      return containsSecret(d.actual, d.setting);
    },
  },

  // CIS-NET-2: Sensitive Insecure Management Ports
  {
    id: "CIS-NET-2",
    name: "Prohibit Insecure Management Ports",
    severity: "CRITICAL",
    reason: "Ports 22 (SSH), 23 (Telnet), and 3389 (RDP) must not be directly exposed in application configurations.",
    matches: (d) => {
      const sensitivePorts = [22, 23, 3389];
      const isPortSetting = /(^|[._])ports?([._]|$)/i.test(d.setting);
      if (!isPortSetting || d.actual === null || d.actual === undefined) return false;

      if (Array.isArray(d.actual)) {
        return d.actual.some((p) => sensitivePorts.includes(Number(p)));
      }
      const num = Number(d.actual);
      return !isNaN(num) && sensitivePorts.includes(num);
    },
  },

  // CIS-CORS-1: Wildcard CORS in Production
  {
    id: "CIS-CORS-1",
    name: "Prohibit Wildcard CORS",
    severity: "CRITICAL",
    reason: "Access-Control-Allow-Origin: '*' allows unauthorized cross-origin requests to access user data.",
    matches: (d) =>
      (d.setting === "security.cors_origin" || d.setting === "cors.allow_origin") &&
      d.actual === "*",
  },

  // Standard Drift Rules
  {
    id: "DRIFT-NET-PORT",
    name: "Application Port Change",
    severity: "MEDIUM",
    reason: "Changing service port affects load balancers, health checks, and ingress routing.",
    matches: (d) => d.setting === "app.port",
  },

  {
    id: "DRIFT-RES-LIMIT",
    name: "Resource Limit Removed",
    severity: "MEDIUM",
    reason: "Removing memory or CPU limits risks noisy-neighbor issues and host exhaustion.",
    matches: (d) =>
      d.setting.startsWith("resources.limits") && d.change === "removed",
  },
];

/**
 * Assign severity to a single configuration difference.
 */
export function assignSeverity(difference: DriftDifference): Severity {
  const match = CIS_SECURITY_RULES.find((rule) => rule.matches(difference));
  return match ? match.severity : "LOW";
}

/**
 * Evaluate a single difference and attach policy metadata.
 */
export function evaluateFinding(difference: DriftDifference): DriftFinding {
  const match = CIS_SECURITY_RULES.find((rule) => rule.matches(difference));
  return {
    ...difference,
    severity: match ? match.severity : "LOW",
    ruleId: match?.id,
    reason: match?.reason,
  };
}

/**
 * Evaluate all differences and attach their risk severity and security benchmark policy.
 */
export function evaluateFindings(differences: DriftDifference[]): DriftFinding[] {
  return differences.map(evaluateFinding);
}

/**
 * Determine whether deployment should be blocked based on findings.
 */
export function shouldBlock(findings: DriftFinding[]): boolean {
  return findings.some((f) => f.severity === "CRITICAL");
}
