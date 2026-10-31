# DriftGuard Configuration Drift Report

**Status:** BLOCKED
**Generated:** 2026-10-31T05:42:27.949Z
**Expected configuration:** `config/expected.yaml`
**Actual configuration:** `config/demo-actual.yaml`

## Summary

- Total differences: 2
- Critical: 1
- Medium: 1
- Low: 0

## Findings

### app.debug

- **Change:** changed
- **Expected:** `false`
- **Actual:** `true`
- **Severity:** CRITICAL

### app.port

- **Change:** changed
- **Expected:** `8000`
- **Actual:** `9000`
- **Severity:** MEDIUM
