import json
from pathlib import Path

import pandas as pd
import streamlit as st
import yaml

from driftguard.detector import detect_drift, load_config
from driftguard.policies import evaluate_findings, should_block
from driftguard.reporter import generate_report

# Page configuration
st.set_page_config(
    page_title="DriftGuard — Configuration Change Detector",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ DriftGuard — Configuration Change Detector")
st.caption(
    "Automated configuration drift detection, risk classification, and deployment readiness"
)

# Sidebar controls
st.sidebar.header("⚙️ Configuration Settings")

expected_path_default = "config/expected.yaml"
available_actual_configs = {
    "Clean Configuration (config/actual.yaml)": "config/actual.yaml",
    "Drifted Demo Configuration (config/demo-actual.yaml)": "config/demo-actual.yaml",
}

selected_option = st.sidebar.selectbox(
    "Select Actual Configuration to Inspect:",
    options=list(available_actual_configs.keys()),
    index=1,  # Default to demo config so changes are immediately visible
)

actual_path = available_actual_configs[selected_option]
expected_path = st.sidebar.text_input(
    "Expected Configuration Path:",
    value=expected_path_default,
)

# Load configurations
try:
    expected_data = load_config(expected_path)
    actual_data = load_config(actual_path)
except Exception as e:
    st.error(f"Error loading configuration files: {e}")
    st.stop()

# Detect drift and evaluate findings
differences = detect_drift(expected_data, actual_data)
findings = evaluate_findings(differences)
report = generate_report(expected_path, actual_path, findings)
is_blocked = should_block(findings)

# Status Banner
if is_blocked:
    st.error(
        "🚨 **DEPLOYMENT STATUS: BLOCKED** — Critical configuration drift detected. Unsafe to deploy to production!"
    )
elif findings:
    st.warning(
        "⚠️ **DEPLOYMENT STATUS: WARNING** — Non-critical drift detected. Review changes before deployment."
    )
else:
    st.success(
        "✅ **DEPLOYMENT STATUS: PASSED** — Configuration matches expected baseline. Ready for deployment!"
    )

st.markdown("---")

# Summary Metrics Cards
col1, col2, col3, col4 = st.columns(4)

summary = report["summary"]
col1.metric("Total Differences", summary["total"])
col2.metric(
    "Critical",
    summary["critical"],
    delta="Blocker" if summary["critical"] > 0 else None,
    delta_color="inverse",
)
col3.metric("Medium", summary["medium"])
col4.metric("Low", summary["low"])

st.markdown("---")

# Tabs for Findings, Config Comparison, and Export
tab1, tab2, tab3 = st.tabs(["📋 Drift Findings", "🔍 Side-by-Side Comparison", "📥 Export Reports"])

with tab1:
    st.subheader("Detected Differences")
    if findings:
        severity_filter = st.multiselect(
            "Filter by Severity:",
            options=["CRITICAL", "MEDIUM", "LOW"],
            default=["CRITICAL", "MEDIUM", "LOW"],
        )

        filtered_findings = [f for f in findings if f["severity"] in severity_filter]

        if filtered_findings:
            df = pd.DataFrame(filtered_findings)
            # Reorder and format columns
            display_columns = ["setting", "severity", "change", "expected", "actual"]
            df = df[[col for col in display_columns if col in df.columns]]
            df.columns = [col.capitalize() for col in df.columns]

            def highlight_severity(row):
                severity = row.get("Severity", "")
                if severity == "CRITICAL":
                    return ["background-color: rgba(255, 75, 75, 0.2); font-weight: bold;"] * len(row)
                elif severity == "MEDIUM":
                    return ["background-color: rgba(255, 170, 0, 0.2);"] * len(row)
                elif severity == "LOW":
                    return ["background-color: rgba(0, 150, 255, 0.1);"] * len(row)
                return [""] * len(row)

            styled_df = df.style.apply(highlight_severity, axis=1)
            st.dataframe(styled_df, use_container_width=True, hide_index=True)
        else:
            st.info("No findings match the selected severity filter.")
    else:
        st.success("No configuration drift detected. Actual configuration matches expected baseline.")

with tab2:
    st.subheader("Configuration Comparison")
    comp_col1, comp_col2 = st.columns(2)

    with comp_col1:
        st.markdown(f"**Expected Configuration** (`{expected_path}`)")
        st.code(yaml.dump(expected_data, sort_keys=False), language="yaml")

    with comp_col2:
        st.markdown(f"**Actual Configuration** (`{actual_path}`)")
        st.code(yaml.dump(actual_data, sort_keys=False), language="yaml")

with tab3:
    st.subheader("Download & View Reports")

    report_json_str = json.dumps(report, indent=2)

    # Generate Markdown representation
    md_lines = [
        "# DriftGuard Configuration Drift Report",
        "",
        f"**Status:** {report['status']}",
        f"**Generated:** {report['generated_at']}",
        f"**Expected configuration:** `{report['expected_config']}`",
        f"**Actual configuration:** `{report['actual_config']}`",
        "",
        "## Summary",
        "",
        f"- Total differences: {summary['total']}",
        f"- Critical: {summary['critical']}",
        f"- Medium: {summary['medium']}",
        f"- Low: {summary['low']}",
        "",
        "## Findings",
        "",
    ]
    if findings:
        for f in findings:
            md_lines.extend([
                f"### {f['setting']}",
                f"- **Severity:** {f['severity']}",
                f"- **Change:** {f['change']}",
                f"- **Expected:** `{f['expected']}`",
                f"- **Actual:** `{f['actual']}`",
                "",
            ])
    else:
        md_lines.append("No configuration drift detected.")
    report_md_str = "\n".join(md_lines)

    down_col1, down_col2 = st.columns(2)
    with down_col1:
        st.download_button(
            label="💾 Download JSON Report",
            data=report_json_str,
            file_name="drift-report.json",
            mime="application/json",
            use_container_width=True,
        )

    with down_col2:
        st.download_button(
            label="📄 Download Markdown Report",
            data=report_md_str,
            file_name="drift-report.md",
            mime="text/markdown",
            use_container_width=True,
        )

    with st.expander("Preview Markdown Report"):
        st.markdown(report_md_str)

    with st.expander("Preview JSON Report"):
        st.json(report)
