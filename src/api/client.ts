/**
 * DriftGuard Frontend API Client
 * Connects the React dashboard to the Fastify REST backend,
 * with graceful in-browser fallback if the backend is offline.
 */

import { DriftReport } from "../core/types";
import { parseConfig, detectFormat, ConfigFormat } from "../core/parser";
import { detectDrift } from "../core/detector";
import { evaluateFindings } from "../core/policies";
import { generateReport } from "../core/reporter";

const API_BASE = (import.meta as any).env?.VITE_API_URL || "http://localhost:3001";

export interface UserProfile {
  id: string;
  username: string;
  email: string;
  role: string;
}

export interface AnalysisRunMeta {
  id: string;
  project_id: string | null;
  expected_source: string;
  actual_source: string;
  format: string;
  status: "PASSED" | "BLOCKED";
  total_diffs: number;
  critical_count: number;
  medium_count: number;
  low_count: number;
  execution_duration_ms: number;
  created_at: string;
}

export interface AnalyzeResult {
  report: DriftReport;
  runId?: string;
  isBackendConnected: boolean;
}

export class DriftGuardApiClient {
  private isOnline = false;
  private token: string | null = null;
  private user: UserProfile | null = null;

  constructor() {
    if (typeof window !== "undefined") {
      this.token = localStorage.getItem("driftguard_token");
      const storedUser = localStorage.getItem("driftguard_user");
      if (storedUser) {
        try {
          this.user = JSON.parse(storedUser);
        } catch {
          this.user = null;
        }
      }
    }
  }

  public getToken(): string | null {
    return this.token;
  }

  public getUser(): UserProfile | null {
    return this.user;
  }

  public async checkHealth(): Promise<boolean> {
    try {
      const res = await fetch(`${API_BASE}/health`, { method: "GET", signal: AbortSignal.timeout(1500) });
      this.isOnline = res.ok;
      return res.ok;
    } catch {
      this.isOnline = false;
      return false;
    }
  }

  public getStatus(): boolean {
    return this.isOnline;
  }

  public async register(username: string, email: string, password: string): Promise<{ user: UserProfile; token: string }> {
    const res = await fetch(`${API_BASE}/api/v1/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username, email, password }),
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error?.message || "Registration failed");
    }

    this.token = data.token;
    this.user = data.user;
    if (typeof window !== "undefined") {
      localStorage.setItem("driftguard_token", data.token);
      localStorage.setItem("driftguard_user", JSON.stringify(data.user));
    }
    return data;
  }

  public async login(identifier: string, password: string): Promise<{ user: UserProfile; token: string }> {
    const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ identifier, password }),
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error?.message || "Login failed");
    }

    this.token = data.token;
    this.user = data.user;
    if (typeof window !== "undefined") {
      localStorage.setItem("driftguard_token", data.token);
      localStorage.setItem("driftguard_user", JSON.stringify(data.user));
    }
    return data;
  }

  public async logout(): Promise<void> {
    if (this.token) {
      try {
        await fetch(`${API_BASE}/api/v1/auth/logout`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${this.token}`,
          },
          credentials: "include",
        });
      } catch {
        // Ignore network errors on logout
      }
    }
    this.token = null;
    this.user = null;
    if (typeof window !== "undefined") {
      localStorage.removeItem("driftguard_token");
      localStorage.removeItem("driftguard_user");
    }
  }

  /**
   * Run drift analysis via Fastify backend API, falling back to local engine if server is unreachable.
   */
  public async analyze(
    expected: string,
    actual: string,
    format?: ConfigFormat,
    expectedSource = "Expected Baseline",
    actualSource = "Actual Configuration"
  ): Promise<AnalyzeResult> {
    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (this.token) {
        headers["Authorization"] = `Bearer ${this.token}`;
      }

      const res = await fetch(`${API_BASE}/api/v1/analyses`, {
        method: "POST",
        headers,
        credentials: "include",
        body: JSON.stringify({ expected, actual, format, expectedSource, actualSource }),
        signal: AbortSignal.timeout(3000),
      });

      if (res.ok) {
        const data = await res.json();
        this.isOnline = true;
        return {
          report: data.report,
          runId: data.run?.id,
          isBackendConnected: true,
        };
      }
    } catch {
      // Backend offline: gracefully fall back to local client-side engine
    }

    this.isOnline = false;
    const expFmt = format || detectFormat(expected, expectedSource);
    const actFmt = format || detectFormat(actual, actualSource);
    const expObj = parseConfig(expected, expectedSource, expFmt);
    const actObj = parseConfig(actual, actualSource, actFmt);
    const diffs = detectDrift(expObj, actObj);
    const findings = evaluateFindings(diffs);
    const report = generateReport(expectedSource, actualSource, findings);

    return {
      report,
      isBackendConnected: false,
    };
  }

  /**
   * Fetch recent persistent analysis runs from database.
   */
  public async getHistory(limit = 10): Promise<AnalysisRunMeta[]> {
    try {
      const headers: Record<string, string> = {};
      if (this.token) {
        headers["Authorization"] = `Bearer ${this.token}`;
      }

      const res = await fetch(`${API_BASE}/api/v1/analyses?limit=${limit}`, {
        method: "GET",
        headers,
        credentials: "include",
        signal: AbortSignal.timeout(2000),
      });
      if (res.ok) {
        const data = await res.json();
        return data.analyses || [];
      }
    } catch {
      // Offline or unauthenticated
    }
    return [];
  }

  /**
   * Download a persisted JSON or Markdown report from the server.
   */
  public getReportDownloadUrl(runId: string, format: "json" | "markdown"): string {
    return `${API_BASE}/api/v1/analyses/${runId}/reports/${format}`;
  }
}

export const apiClient = new DriftGuardApiClient();
