import { useState, useMemo } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Download,
  FileText,
  ListFilter,
  Columns,
  RefreshCw,
} from "lucide-react";
import { detectDrift } from "./core/detector";
import { parseConfig, detectFormat, ConfigFormat } from "./core/parser";
import { evaluateFindings, shouldBlock } from "./core/policies";
import { generateReport, generateMarkdownReport } from "./core/reporter";

interface Preset {
  format: ConfigFormat;
  expected: string;
  actual: string;
}

const PRESETS: Record<string, Preset> = {
  "YAML: Clean Baseline": {
    format: "yaml",
    expected: `app:
  port: 8000
  debug: false
  environment: production

security:
  https_required: true
  tls_version: "1.3"`,
    actual: `app:
  port: 8000
  debug: false
  environment: production

security:
  https_required: true
  tls_version: "1.3"`,
  },

  "YAML: Critical Drift (Debug Enabled)": {
    format: "yaml",
    expected: `app:
  port: 8000
  debug: false
  environment: production

security:
  https_required: true`,
    actual: `app:
  port: 9000
  debug: true
  environment: production

security:
  https_required: true`,
  },

  "JSON: Insecure TLS 1.0 Downgrade (CIS-TLS-1)": {
    format: "json",
    expected: `{
  "app": {
    "port": 8000,
    "debug": false
  },
  "security": {
    "https_required": true,
    "tls_version": "1.3"
  }
}`,
    actual: `{
  "app": {
    "port": 9000,
    "debug": false
  },
  "security": {
    "https_required": true,
    "tls_version": "1.0"
  }
}`,
  },

  "TOML: Wildcard CORS Breach (CIS-CORS-1)": {
    format: "toml",
    expected: `[app]
port = 8080
environment = "production"

[security]
https_required = true
cors_origin = "https://app.example.com"`,
    actual: `[app]
port = 8080
environment = "production"

[security]
https_required = true
cors_origin = "*"`,
  },

  "YAML: Container Root Execution (CIS-IAM-1)": {
    format: "yaml",
    expected: `process:
  user: "appuser"
docker:
  privileged: false`,
    actual: `process:
  user: "root"
docker:
  privileged: true`,
  },

  "YAML: Plaintext Secret Exposure (CIS-SEC-1)": {
    format: "yaml",
    expected: `auth:
  api_key: "\${ENV_STRIPE_KEY}"
  secret_token: "\${ENV_SECRET}"`,
    actual: `auth:
  api_key: "sk_live_94820491823901"
  secret_token: "super_secret_unencrypted"`,
  },
};

export default function App() {
  const [presetKey, setPresetKey] = useState<string>("YAML: Critical Drift (Debug Enabled)");
  const [expectedInput, setExpectedInput] = useState<string>(PRESETS["YAML: Critical Drift (Debug Enabled)"].expected);
  const [actualInput, setActualInput] = useState<string>(PRESETS["YAML: Critical Drift (Debug Enabled)"].actual);
  const [activeTab, setActiveTab] = useState<"findings" | "diff" | "reports">("findings");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");

  const handlePresetChange = (name: string) => {
    setPresetKey(name);
    if (PRESETS[name]) {
      setExpectedInput(PRESETS[name].expected);
      setActualInput(PRESETS[name].actual);
    }
  };

  // Live detection & risk evaluation
  const { report, error, isBlocked, detectedFormats } = useMemo(() => {
    try {
      const expFmt = detectFormat(expectedInput);
      const actFmt = detectFormat(actualInput);
      const expObj = parseConfig(expectedInput, "Expected Config", expFmt);
      const actObj = parseConfig(actualInput, "Actual Config", actFmt);
      const diffs = detectDrift(expObj, actObj);
      const findings = evaluateFindings(diffs);
      const blocked = shouldBlock(findings);
      const rep = generateReport(`expected.${expFmt}`, `actual.${actFmt}`, findings);

      return {
        report: rep,
        error: null,
        isBlocked: blocked,
        detectedFormats: { expected: expFmt, actual: actFmt },
      };
    } catch (err: any) {
      return {
        report: null,
        error: err.message,
        isBlocked: true,
        detectedFormats: { expected: "yaml", actual: "yaml" },
      };
    }
  }, [expectedInput, actualInput]);

  // Filtered findings
  const filteredFindings = useMemo(() => {
    if (!report) return [];
    if (severityFilter === "ALL") return report.findings;
    return report.findings.filter((f) => f.severity === severityFilter);
  }, [report, severityFilter]);

  // Download helpers
  const downloadFile = (filename: string, content: string, type: string) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="container">
      {/* Header */}
      <header>
        <div className="title-group">
          <h1>
            <span>🛡️</span> DriftGuard
          </h1>
          <p>Multi-Format Configuration Change Detector & CIS Benchmark Policy Gatekeeper</p>
        </div>

        <div className="preset-controls">
          <label htmlFor="presetSelect">
            <strong>Scenario Preset:</strong>
          </label>
          <select
            id="presetSelect"
            value={presetKey}
            onChange={(e) => handlePresetChange(e.target.value)}
          >
            {Object.keys(PRESETS).map((key) => (
              <option key={key} value={key}>
                {key}
              </option>
            ))}
          </select>
          <button
            className="filter-pill"
            title="Reset configs to preset baseline"
            onClick={() => {
              if (PRESETS[presetKey]) {
                setExpectedInput(PRESETS[presetKey].expected);
                setActualInput(PRESETS[presetKey].actual);
              }
            }}
          >
            <RefreshCw size={14} style={{ display: "inline", verticalAlign: "middle" }} /> Reset
          </button>
        </div>
      </header>

      {/* Parsing error notification */}
      {error && (
        <div className="status-banner blocked">
          <AlertTriangle className="status-icon" />
          <div>
            <strong>Configuration Syntax Error:</strong> {error}
          </div>
        </div>
      )}

      {/* Deployment Status Banner */}
      {!error && report && (
        <>
          {isBlocked ? (
            <div className="status-banner blocked">
              <ShieldAlert className="status-icon" />
              <div>
                <strong>DEPLOYMENT BLOCKED</strong> — Critical security policy violation or baseline drift detected!
                Release gate will halt downstream deployments.
              </div>
            </div>
          ) : report.findings.length > 0 ? (
            <div className="status-banner warning">
              <AlertTriangle className="status-icon" />
              <div>
                <strong>DEPLOYMENT WARNING</strong> — Non-critical configuration drift detected.
                Review modifications before promoting to production.
              </div>
            </div>
          ) : (
            <div className="status-banner passed">
              <ShieldCheck className="status-icon" />
              <div>
                <strong>DEPLOYMENT READY</strong> — Target configuration matches expected baseline with zero security policy violations.
              </div>
            </div>
          )}

          {/* Metrics Grid */}
          <div className="metrics-grid">
            <div className="metric-card total">
              <span className="label">Total Differences</span>
              <span className="value">{report.summary.total}</span>
            </div>
            <div className="metric-card critical">
              <span className="label">Critical Violations</span>
              <span className="value">
                {report.summary.critical}
                {report.summary.critical > 0 && (
                  <span className="badge-blocker">Blocker</span>
                )}
              </span>
            </div>
            <div className="metric-card medium">
              <span className="label">Medium Drift</span>
              <span className="value">{report.summary.medium}</span>
            </div>
            <div className="metric-card low">
              <span className="label">Low Notice</span>
              <span className="value">{report.summary.low}</span>
            </div>
          </div>
        </>
      )}

      {/* Tabs navigation */}
      <div className="tabs-header">
        <button
          className={`tab-btn ${activeTab === "findings" ? "active" : ""}`}
          onClick={() => setActiveTab("findings")}
        >
          <ListFilter size={16} style={{ display: "inline", marginRight: "6px" }} />
          Drift Findings {report ? `(${report.findings.length})` : ""}
        </button>
        <button
          className={`tab-btn ${activeTab === "diff" ? "active" : ""}`}
          onClick={() => setActiveTab("diff")}
        >
          <Columns size={16} style={{ display: "inline", marginRight: "6px" }} />
          Side-by-Side Editor ({detectedFormats ? detectedFormats.expected.toUpperCase() : "YAML"})
        </button>
        <button
          className={`tab-btn ${activeTab === "reports" ? "active" : ""}`}
          onClick={() => setActiveTab("reports")}
        >
          <FileText size={16} style={{ display: "inline", marginRight: "6px" }} />
          Export Reports
        </button>
      </div>

      {/* Tab 1: Findings Table */}
      {activeTab === "findings" && report && (
        <div className="table-container">
          <div className="table-toolbar">
            <div className="filter-pills">
              {["ALL", "CRITICAL", "MEDIUM", "LOW"].map((lvl) => (
                <button
                  key={lvl}
                  className={`filter-pill ${severityFilter === lvl ? "active" : ""}`}
                  onClick={() => setSeverityFilter(lvl)}
                >
                  {lvl}
                </button>
              ))}
            </div>
            <span style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
              Showing {filteredFindings.length} of {report.findings.length} findings
            </span>
          </div>

          {filteredFindings.length === 0 ? (
            <div style={{ padding: "2.5rem", textAlign: "center", color: "var(--text-muted)" }}>
              {report.findings.length === 0
                ? "No configuration differences detected! All policies and values match."
                : "No findings match the selected severity filter."}
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Setting</th>
                  <th>Severity</th>
                  <th>Policy Rule</th>
                  <th>Change</th>
                  <th>Expected</th>
                  <th>Actual</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.map((finding, idx) => (
                  <tr key={idx}>
                    <td>
                      <strong>{finding.setting}</strong>
                    </td>
                    <td>
                      <span className={`tag-severity ${finding.severity}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td>
                      {finding.ruleId ? (
                        <div>
                          <span style={{ fontWeight: 600, color: "var(--text-main)" }}>
                            {finding.ruleId}
                          </span>
                          <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: "2px" }}>
                            {finding.reason}
                          </div>
                        </div>
                      ) : (
                        <span style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
                          General Drift
                        </span>
                      )}
                    </td>
                    <td>
                      <span style={{ textTransform: "capitalize" }}>{finding.change}</span>
                    </td>
                    <td>
                      <span className="code-val">
                        {finding.expected !== null ? String(finding.expected) : "null"}
                      </span>
                    </td>
                    <td>
                      <span className="code-val">
                        {finding.actual !== null ? String(finding.actual) : "null"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Tab 2: Side-by-Side Editor */}
      {activeTab === "diff" && (
        <div className="diff-grid">
          <div className="editor-box">
            <div className="editor-header">
              <span>Expected Baseline</span>
              <span style={{ textTransform: "uppercase" }}>{detectedFormats ? detectedFormats.expected : "YAML"}</span>
            </div>
            <textarea
              value={expectedInput}
              onChange={(e) => setExpectedInput(e.target.value)}
              placeholder="Paste or edit expected YAML, JSON, or TOML..."
              spellCheck={false}
            />
          </div>

          <div className="editor-box">
            <div className="editor-header">
              <span>Actual Target</span>
              <span style={{ textTransform: "uppercase" }}>{detectedFormats ? detectedFormats.actual : "YAML"}</span>
            </div>
            <textarea
              value={actualInput}
              onChange={(e) => {
                setPresetKey("Custom");
                setActualInput(e.target.value);
              }}
              placeholder="Paste or edit actual YAML, JSON, or TOML..."
              spellCheck={false}
            />
          </div>
        </div>
      )}

      {/* Tab 3: Export Reports */}
      {activeTab === "reports" && report && (
        <div className="export-grid">
          <div className="export-card">
            <h3>Structured JSON Audit Report</h3>
            <p>Complete findings payload including rule IDs, reasons, and summary statistics.</p>
            <button
              className="btn-primary"
              onClick={() =>
                downloadFile(
                  "drift-report.json",
                  JSON.stringify(report, null, 2),
                  "application/json"
                )
              }
            >
              <Download size={16} /> Download JSON Report
            </button>
          </div>

          <div className="export-card">
            <h3>Markdown Executive Brief</h3>
            <p>Formatted report ideal for Pull Request annotations, compliance audits, or documentation.</p>
            <button
              className="btn-primary"
              onClick={() =>
                downloadFile(
                  "drift-report.md",
                  generateMarkdownReport(report),
                  "text/markdown"
                )
              }
            >
              <Download size={16} /> Download Markdown Report
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
