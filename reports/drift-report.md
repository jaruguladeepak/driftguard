# DriftGuard Configuration Drift Report

**Status:** BLOCKED
**Generated:** 2026-10-31T11:13:47.360Z
**Expected configuration:** `config/sample-expected.toml`
**Actual configuration:** `config/sample-actual.toml`

## Summary

- Total differences: 1
- Critical: 1
- Medium: 0
- Low: 0

## Findings

### security.cors_origin

- **Change:** changed
- **Expected:** `https://app.example.com`
- **Actual:** `*`
- **Severity:** CRITICAL
- **Policy (CIS-CORS-1):** Access-Control-Allow-Origin: '*' allows unauthorized cross-origin requests to access user data.
