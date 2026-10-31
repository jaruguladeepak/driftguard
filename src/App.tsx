import { useState, useMemo, useEffect, useCallback } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Download,
  FileText,
  ListFilter,
  Columns,
  RefreshCw,
  Server,
  History,
  Database,
  User,
  LogIn,
  LogOut,
  X,
} from "lucide-react";
import { detectDrift } from "./core/detector";
import { parseConfig, detectFormat, ConfigFormat } from "./core/parser";
import { evaluateFindings, shouldBlock } from "./core/policies";
import { generateReport, generateMarkdownReport } from "./core/reporter";
import { apiClient, AnalysisRunMeta, UserProfile } from "./api/client";

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
  const [activeTab, setActiveTab] = useState<"findings" | "diff" | "reports" | "history">("findings");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [backendOnline, setBackendOnline] = useState<boolean>(false);
  const [currentRunId, setCurrentRunId] = useState<string | null>(null);
  const [historyRuns, setHistoryRuns] = useState<AnalysisRunMeta[]>([]);
  const [isPersisting, setIsPersisting] = useState<boolean>(false);

  // Authentication state
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(() => apiClient.getUser());
  const [showAuthModal, setShowAuthModal] = useState<boolean>(false);
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [authUsername, setAuthUsername] = useState<string>("");
  const [authEmail, setAuthEmail] = useState<string>("");
  const [authPassword, setAuthPassword] = useState<string>("");
  const [authError, setAuthError] = useState<string | null>(null);
  const [authLoading, setAuthLoading] = useState<boolean>(false);

  // Poll backend health status
  const checkBackend = useCallback(async () => {
    const online = await apiClient.checkHealth();
    setBackendOnline(online);
    if (online) {
      const history = await apiClient.getHistory(15);
      setHistoryRuns(history);
    }
  }, []);

  useEffect(() => {
    checkBackend();
    const interval = setInterval(checkBackend, 5000);
    return () => clearInterval(interval);
  }, [checkBackend]);

  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthLoading(true);
    try {
      if (authMode === "register") {
        const { user } = await apiClient.register(authUsername, authEmail, authPassword);
        setCurrentUser(user);
      } else {
        const { user } = await apiClient.login(authUsername, authPassword);
        setCurrentUser(user);
      }
      setShowAuthModal(false);
      setAuthPassword("");
      const history = await apiClient.getHistory(15);
      setHistoryRuns(history);
    } catch (err: any) {
      setAuthError(err.message);
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogout = async () => {
    await apiClient.logout();
    setCurrentUser(null);
    setHistoryRuns([]);
  };

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
        detectedFormats: { expected: "yaml" as ConfigFormat, actual: "yaml" as ConfigFormat },
      };
    }
  }, [expectedInput, actualInput]);

  // Persist analysis to backend
  const handleSaveToBackend = async () => {
    if (!currentUser) {
      setAuthError("Authentication required: Please sign in or register to persist analyses into the SQLite database.");
      setShowAuthModal(true);
      return;
    }

    setIsPersisting(true);
    try {
      const result = await apiClient.analyze(
        expectedInput,
        actualInput,
        detectedFormats?.expected,
        `expected.${detectedFormats?.expected}`,
        `actual.${detectedFormats?.actual}`
      );
      if (result.runId) {
        setCurrentRunId(result.runId);
      }
      setBackendOnline(result.isBackendConnected);
      const history = await apiClient.getHistory(15);
      setHistoryRuns(history);
    } finally {
      setIsPersisting(false);
    }
  };

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
          <p>DevSecOps Multi-Format Configuration Drift Detector & Security Policy Gatekeeper</p>
          <div style={{ marginTop: "6px", display: "flex", alignItems: "center", gap: "10px" }}>
            <span
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "5px",
                fontSize: "0.8rem",
                padding: "3px 8px",
                borderRadius: "12px",
                background: backendOnline ? "rgba(16, 185, 129, 0.15)" : "rgba(245, 158, 11, 0.15)",
                color: backendOnline ? "#10b981" : "#f59e0b",
                fontWeight: 600,
              }}
            >
              <Server size={12} />
              {backendOnline ? "REST API Connected (SQLite Active)" : "Local Engine Mode (Offline)"}
            </span>
            {currentRunId && (
              <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                Run ID: <code>{currentRunId.slice(0, 8)}...</code>
              </span>
            )}
          </div>
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
          <button
            className="filter-pill active"
            title="Persist this analysis run into SQLite database"
            onClick={handleSaveToBackend}
            disabled={isPersisting}
          >
            <Database size={14} style={{ display: "inline", verticalAlign: "middle", marginRight: "4px" }} />
            {isPersisting ? "Saving..." : "Save to Database"}
          </button>

          {currentUser ? (
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginLeft: "6px" }}>
              <span style={{ fontSize: "0.85rem", color: "var(--text-main)", display: "inline-flex", alignItems: "center" }}>
                <User size={13} style={{ marginRight: "4px" }} />
                <strong>{currentUser.username}</strong>
                <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginLeft: "4px" }}>({currentUser.role})</span>
              </span>
              <button
                className="filter-pill"
                title="Log out of session"
                onClick={handleLogout}
              >
                <LogOut size={13} style={{ display: "inline", verticalAlign: "middle" }} /> Log Out
              </button>
            </div>
          ) : (
            <button
              className="filter-pill"
              title="Sign In or Register"
              style={{ marginLeft: "6px" }}
              onClick={() => {
                setAuthError(null);
                setShowAuthModal(true);
              }}
            >
              <LogIn size={13} style={{ display: "inline", verticalAlign: "middle", marginRight: "4px" }} />
              Sign In / Register
            </button>
          )}
        </div>
      </header>

      {/* Authentication Modal */}
      {showAuthModal && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: "rgba(0, 0, 0, 0.7)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
            backdropFilter: "blur(4px)",
          }}
          onClick={() => setShowAuthModal(false)}
        >
          <div
            style={{
              background: "#1e293b",
              border: "1px solid #334155",
              borderRadius: "12px",
              padding: "24px",
              width: "100%",
              maxWidth: "400px",
              boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.5)",
              color: "#f8fafc",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <h3 style={{ margin: 0, fontSize: "1.1rem" }}>
                {authMode === "login" ? "Sign In to DriftGuard" : "Create DriftGuard Account"}
              </h3>
              <button
                onClick={() => setShowAuthModal(false)}
                style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer" }}
              >
                <X size={18} />
              </button>
            </div>

            {authError && (
              <div
                style={{
                  background: "rgba(239, 68, 68, 0.15)",
                  border: "1px solid #ef4444",
                  color: "#fca5a5",
                  padding: "8px 12px",
                  borderRadius: "6px",
                  fontSize: "0.85rem",
                  marginBottom: "12px",
                }}
              >
                {authError}
              </div>
            )}

            <form onSubmit={handleAuthSubmit} style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div>
                <label style={{ display: "block", fontSize: "0.8rem", marginBottom: "4px", color: "#94a3b8" }}>
                  {authMode === "login" ? "Username or Email" : "Username"}
                </label>
                <input
                  type="text"
                  required
                  value={authUsername}
                  onChange={(e) => setAuthUsername(e.target.value)}
                  placeholder={authMode === "login" ? "alice or alice@example.com" : "alice"}
                  style={{
                    width: "100%",
                    padding: "8px 10px",
                    borderRadius: "6px",
                    background: "rgba(15, 23, 42, 0.8)",
                    border: "1px solid #334155",
                    color: "inherit",
                    boxSizing: "border-box",
                  }}
                />
              </div>

              {authMode === "register" && (
                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", marginBottom: "4px", color: "#94a3b8" }}>
                    Email Address
                  </label>
                  <input
                    type="email"
                    required
                    value={authEmail}
                    onChange={(e) => setAuthEmail(e.target.value)}
                    placeholder="alice@example.com"
                    style={{
                      width: "100%",
                      padding: "8px 10px",
                      borderRadius: "6px",
                      background: "rgba(15, 23, 42, 0.8)",
                      border: "1px solid #334155",
                      color: "inherit",
                      boxSizing: "border-box",
                    }}
                  />
                </div>
              )}

              <div>
                <label style={{ display: "block", fontSize: "0.8rem", marginBottom: "4px", color: "#94a3b8" }}>
                  Password
                </label>
                <input
                  type="password"
                  required
                  value={authPassword}
                  onChange={(e) => setAuthPassword(e.target.value)}
                  placeholder="••••••••"
                  style={{
                    width: "100%",
                    padding: "8px 10px",
                    borderRadius: "6px",
                    background: "rgba(15, 23, 42, 0.8)",
                    border: "1px solid #334155",
                    color: "inherit",
                    boxSizing: "border-box",
                  }}
                />
              </div>

              <button
                type="submit"
                className="btn-primary"
                disabled={authLoading}
                style={{ marginTop: "6px", width: "100%", justifyContent: "center" }}
              >
                {authLoading ? "Processing..." : authMode === "login" ? "Sign In" : "Create Account"}
              </button>
            </form>

            <div style={{ marginTop: "14px", textAlign: "center", fontSize: "0.8rem", color: "#94a3b8" }}>
              {authMode === "login" ? (
                <>
                  Don't have an account?{" "}
                  <button
                    onClick={() => {
                      setAuthMode("register");
                      setAuthError(null);
                    }}
                    style={{ background: "none", border: "none", color: "#38bdf8", cursor: "pointer", textDecoration: "underline" }}
                  >
                    Register here
                  </button>
                </>
              ) : (
                <>
                  Already have an account?{" "}
                  <button
                    onClick={() => {
                      setAuthMode("login");
                      setAuthError(null);
                    }}
                    style={{ background: "none", border: "none", color: "#38bdf8", cursor: "pointer", textDecoration: "underline" }}
                  >
                    Sign in here
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      )}

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
                <strong>DEPLOYMENT PERMITTED</strong> — Configuration matches expected baseline with zero policy violations.
              </div>
            </div>
          )}

          {/* Metric cards */}
          <div className="metrics-grid">
            <div className="metric-card">
              <span className="label">Total Differences</span>
              <span className="value">{report.summary.total}</span>
            </div>
            <div className="metric-card critical">
              <span className="label">Critical Findings</span>
              <span className="value">{report.summary.critical}</span>
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
        <button
          className={`tab-btn ${activeTab === "history" ? "active" : ""}`}
          onClick={() => {
            setActiveTab("history");
            checkBackend();
          }}
        >
          <History size={16} style={{ display: "inline", marginRight: "6px" }} />
          Analysis History {historyRuns.length > 0 ? `(${historyRuns.length})` : ""}
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
                        {finding.expected !== null
                          ? typeof finding.expected === "object"
                            ? JSON.stringify(finding.expected)
                            : String(finding.expected)
                          : "null"}
                      </span>
                    </td>
                    <td>
                      <span className="code-val">
                        {finding.actual !== null
                          ? typeof finding.actual === "object"
                            ? JSON.stringify(finding.actual)
                            : String(finding.actual)
                          : "null"}
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

      {/* Tab 4: Analysis History */}
      {activeTab === "history" && (
        <div className="table-container">
          <div className="table-toolbar">
            <span style={{ fontWeight: 600 }}>Persisted SQLite Analysis Runs</span>
            <button className="filter-pill" onClick={checkBackend}>
              <RefreshCw size={12} style={{ display: "inline", verticalAlign: "middle" }} /> Refresh
            </button>
          </div>

          {!currentUser ? (
            <div style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}>
              <div style={{ fontSize: "1.1rem", fontWeight: 600, color: "#f8fafc", marginBottom: "8px" }}>
                🔒 Authentication Required
              </div>
              <p style={{ fontSize: "0.85rem", maxWidth: "450px", margin: "0 auto 16px auto" }}>
                Analysis history is secured under strict multi-tenant authorization policies. Sign in or register to view your persistent SQLite records.
              </p>
              <button
                className="btn-primary"
                style={{ display: "inline-flex", margin: "0 auto" }}
                onClick={() => {
                  setAuthError(null);
                  setShowAuthModal(true);
                }}
              >
                <LogIn size={14} /> Sign In to View History
              </button>
            </div>
          ) : historyRuns.length === 0 ? (
            <div style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}>
              {backendOnline
                ? `Welcome ${currentUser.username}! No persisted runs recorded for your account yet. Click 'Save to Database' above to persist an analysis run.`
                : "Backend is currently offline. Start the backend server (`npm run server`) to view persisted runs."}
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Run ID</th>
                  <th>Date & Time</th>
                  <th>Status</th>
                  <th>Format</th>
                  <th>Differences</th>
                  <th>Execution</th>
                  <th>Reports</th>
                </tr>
              </thead>
              <tbody>
                {historyRuns.map((run) => (
                  <tr key={run.id}>
                    <td>
                      <code>{run.id.slice(0, 8)}</code>
                    </td>
                    <td style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                      {new Date(run.created_at).toLocaleString()}
                    </td>
                    <td>
                      <span className={`tag-severity ${run.status === "BLOCKED" ? "CRITICAL" : "LOW"}`}>
                        {run.status}
                      </span>
                    </td>
                    <td style={{ textTransform: "uppercase", fontSize: "0.85rem" }}>
                      {run.format}
                    </td>
                    <td>
                      <strong>{run.total_diffs}</strong> (Crit: {run.critical_count})
                    </td>
                    <td style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                      {run.execution_duration_ms} ms
                    </td>
                    <td>
                      <div style={{ display: "flex", gap: "6px" }}>
                        <a
                          className="filter-pill"
                          href={apiClient.getReportDownloadUrl(run.id, "json")}
                          target="_blank"
                          rel="noreferrer"
                          style={{ textDecoration: "none" }}
                        >
                          JSON
                        </a>
                        <a
                          className="filter-pill"
                          href={apiClient.getReportDownloadUrl(run.id, "markdown")}
                          target="_blank"
                          rel="noreferrer"
                          style={{ textDecoration: "none" }}
                        >
                          MD
                        </a>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
