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
import { parseConfig, detectDrift } from "./core/detector";
import { evaluateFindings, shouldBlock } from "./core/policies";
import { generateReport, generateMarkdownReport } from "./core/reporter";

const DEFAULT_EXPECTED = `app:
  port: 8000
  debug: false
  environment: production

security:
  https_required: true`;

const PRESETS: Record<string, string> = {
  "Clean Baseline": `app:
  port: 8000
  debug: false
  environment: production

security:
  https_required: true`,

  "Drift Demonstration (Critical)": `app:
  port: 9000
  debug: true
  environment: production

security:
  https_required: true`,

  "Security Policy Breach (HTTPS Disabled)": `app:
  port: 8000
  debug: false
  environment: production

security:
  https_required: false`,
};

export default function App() {
  const [presetKey, setPresetKey] = useState<string>("Drift Demonstration (Critical)");
  const [expectedYaml, setExpectedYaml] = useState<string>(DEFAULT_EXPECTED);
  const [actualYaml, setActualYaml] = useState<string>(PRESETS["Drift Demonstration (Critical)"]);
  const [activeTab, setActiveTab] = useState<"findings" | "diff" | "reports">("findings");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");

  const handlePresetChange = (name: string) => {
    setPresetKey(name);
    if (PRESETS[name]) {
      setActualYaml(PRESETS[name]);
    }
  };

  // Live detection & risk evaluation
  const { report, error, isBlocked } = useMemo(() => {
    try {
      const expObj = parseConfig(expectedYaml, "Expected Config");
      const actObj = parseConfig(actualYaml, "Actual Config");
      const diffs = detectDrift(expObj, actObj);
      const findings = evaluateFindings(diffs);
      const blocked = shouldBlock(findings);
      const rep = generateReport("expected.yaml", "actual.yaml", findings);

      return { report: rep, error: null, isBlocked: blocked };
    } catch (err: any) {
      return { report: null, error: err.message, isBlocked: true };
    }
  }, [expectedYaml, actualYaml]);

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
          <p>Real-Time Configuration Change Detector & Risk Classifier</p>
        </div>

        <div className="preset-controls">
          <label htmlFor="presetSelect">
            <strong>Scenario:</strong>
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
            title="Reset configs to baseline"
            onClick={() => {
              setExpectedYaml(DEFAULT_EXPECTED);
              setActualYaml(PRESETS[presetKey]);
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
            <strong>YAML Parsing Error:</strong> {error}
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
                <strong>DEPLOYMENT BLOCKED</strong> — Critical configuration drift detected!
                Debug mode or security policies do not meet production baseline.
              </div>
            </div>
          ) : report.findings.length > 0 ? (
            <div className="status-banner warning">
              <AlertTriangle className="status-icon" />
              <div>
                <strong>DEPLOYMENT WARNING</strong> — Non-critical configuration drift detected.
                Review changes before promoting to production.
              </div>
            </div>
          ) : (
            <div className="status-banner passed">
              <ShieldCheck className="status-icon" />
              <div>
                <strong>DEPLOYMENT READY</strong> — Configuration matches expected baseline with
                zero drift.
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
              <span className="label">Critical</span>
              <span className="value">
                {report.summary.critical}
                {report.summary.critical > 0 && (
                  <span className="badge-blocker">Blocker</span>
                )}
              </span>
            </div>
            <div className="metric-card medium">
              <span className="label">Medium</span>
              <span className="value">{report.summary.medium}</span>
            </div>
            <div className="metric-card low">
              <span className="label">Low</span>
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
          Side-by-Side YAML
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
                ? "No configuration differences detected! Everything matches."
                : "No findings match the selected severity filter."}
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Setting</th>
                  <th>Severity</th>
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

      {/* Tab 2: Side-by-Side YAML Editor */}
      {activeTab === "diff" && (
        <div className="diff-grid">
          <div className="editor-box">
            <div className="editor-header">
              <span>Expected Configuration (Baseline)</span>
              <span>YAML</span>
            </div>
            <textarea
              value={expectedYaml}
              onChange={(e) => setExpectedYaml(e.target.value)}
              placeholder="Paste or edit expected YAML..."
              spellCheck={false}
            />
          </div>

          <div className="editor-box">
            <div className="editor-header">
              <span>Actual Configuration (Target)</span>
              <span>YAML</span>
            </div>
            <textarea
              value={actualYaml}
              onChange={(e) => {
                setPresetKey("Custom");
                setActualYaml(e.target.value);
              }}
              placeholder="Paste or edit actual YAML..."
              spellCheck={false}
            />
          </div>
        </div>
      )}

      {/* Tab 3: Export Reports */}
      {activeTab === "reports" && report && (
        <div className="export-grid">
          <div className="export-card">
            <h3>Structured JSON Report</h3>
            <p>Export complete findings payload for CI/CD pipelines, APIs, and audit stores.</p>
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
            <h3>Markdown Executive Summary</h3>
            <p>Formatted report ideal for GitHub PR summaries, ticketing systems, or docs.</p>
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

