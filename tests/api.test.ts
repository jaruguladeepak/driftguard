import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { FastifyInstance } from "fastify";
import { buildApp } from "../src/server/app";
import { DatabaseManager } from "../src/server/db/index";

describe("DriftGuard REST API Endpoints & Security Controls", () => {
  let app: FastifyInstance;
  let db: DatabaseManager;

  beforeAll(async () => {
    db = new DatabaseManager(":memory:");
    app = buildApp({ db, disableRateLimit: true });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
    db.close();
  });

  describe("System Health", () => {
    it("responds with healthy status on GET /health", async () => {
      const res = await app.inject({ method: "GET", url: "/health" });
      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.status).toBe("ok");
      expect(json.engine).toContain("DriftGuard");
    });
  });

  describe("Authentication API", () => {
    it("registers a new user and returns token + cookie", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/auth/register",
        payload: {
          username: "devsecops_lead",
          email: "lead@driftguard.io",
          password: "SuperSecretPassword123!",
        },
      });

      expect(res.statusCode).toBe(201);
      const json = res.json();
      expect(json.user.username).toBe("devsecops_lead");
      expect(json.token).toBeDefined();
      expect(res.cookies.some((c) => c.name === "driftguard_session")).toBe(true);
    });

    it("rejects weak password on registration", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/auth/register",
        payload: {
          username: "weak_user",
          email: "weak@driftguard.io",
          password: "short",
        },
      });

      expect(res.statusCode).toBe(400);
      expect(res.json().error.code).toBe("REGISTRATION_FAILED");
    });

    it("authenticates valid login and rejects invalid password", async () => {
      const validRes = await app.inject({
        method: "POST",
        url: "/api/v1/auth/login",
        payload: {
          identifier: "devsecops_lead",
          password: "SuperSecretPassword123!",
        },
      });
      expect(validRes.statusCode).toBe(200);
      expect(validRes.json().token).toBeDefined();

      const invalidRes = await app.inject({
        method: "POST",
        url: "/api/v1/auth/login",
        payload: {
          identifier: "devsecops_lead",
          password: "WrongPassword123!",
        },
      });
      expect(invalidRes.statusCode).toBe(401);
    });

    it("protects /api/v1/auth/me against unauthenticated requests", async () => {
      const unauthRes = await app.inject({ method: "GET", url: "/api/v1/auth/me" });
      expect(unauthRes.statusCode).toBe(401);
    });
  });

  describe("Projects & Configurations API", () => {
    let userToken: string;
    let createdProjectId: string;

    beforeAll(async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/auth/login",
        payload: {
          identifier: "devsecops_lead",
          password: "SuperSecretPassword123!",
        },
      });
      userToken = res.json().token;
    });

    it("creates, lists, and retrieves projects for the authenticated user", async () => {
      const createRes = await app.inject({
        method: "POST",
        url: "/api/v1/projects",
        headers: { authorization: `Bearer ${userToken}` },
        payload: { name: "Cloud Gateway Service", description: "Edge ingress API gateway" },
      });
      expect(createRes.statusCode).toBe(201);
      createdProjectId = createRes.json().project.id;
      expect(createdProjectId).toBeDefined();

      const listRes = await app.inject({
        method: "GET",
        url: "/api/v1/projects",
        headers: { authorization: `Bearer ${userToken}` },
      });
      expect(listRes.statusCode).toBe(200);
      expect(listRes.json().projects.length).toBeGreaterThan(0);

      const getRes = await app.inject({
        method: "GET",
        url: `/api/v1/projects/${createdProjectId}`,
        headers: { authorization: `Bearer ${userToken}` },
      });
      expect(getRes.statusCode).toBe(200);
      expect(getRes.json().project.name).toBe("Cloud Gateway Service");
    });

    it("saves and lists project configurations", async () => {
      const configPayload = {
        name: "expected-baseline.yaml",
        format: "yaml",
        content: "security:\n  https_required: true\n  tls_version: '1.3'",
        isBaseline: true,
      };

      const createRes = await app.inject({
        method: "POST",
        url: `/api/v1/projects/${createdProjectId}/configurations`,
        headers: { authorization: `Bearer ${userToken}` },
        payload: configPayload,
      });

      expect(createRes.statusCode).toBe(201);
      const configId = createRes.json().configuration.id;
      expect(configId).toBeDefined();

      const listRes = await app.inject({
        method: "GET",
        url: `/api/v1/projects/${createdProjectId}/configurations`,
        headers: { authorization: `Bearer ${userToken}` },
      });

      expect(listRes.statusCode).toBe(200);
      expect(listRes.json().configurations.length).toBe(1);
      expect(listRes.json().configurations[0].name).toBe("expected-baseline.yaml");
    });
  });

  describe("Drift Analysis API", () => {
    let userToken: string;
    let analysisRunId: string;

    beforeAll(async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/auth/login",
        payload: {
          identifier: "devsecops_lead",
          password: "SuperSecretPassword123!",
        },
      });
      userToken = res.json().token;
    });

    it("runs in-memory drift analysis for unauthenticated users without database writes", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/analyses",
        payload: {
          expected: "app:\n  port: 8000\n  debug: false",
          actual: "app:\n  port: 9000\n  debug: true",
          format: "yaml",
        },
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.report.status).toBe("BLOCKED");
      expect(json.run).toBeUndefined(); // Zero database persistence for anonymous users
    });

    it("persists analysis run when authenticated", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/analyses",
        headers: { authorization: `Bearer ${userToken}` },
        payload: {
          expected: "app:\n  port: 8000\n  debug: false",
          actual: "app:\n  port: 9000\n  debug: true",
          format: "yaml",
          expectedSource: "prod-spec.yaml",
          actualSource: "deployed.yaml",
        },
      });

      expect(res.statusCode).toBe(201);
      const json = res.json();
      expect(json.report.status).toBe("BLOCKED");
      expect(json.report.summary.critical).toBe(1);
      expect(json.run.id).toBeDefined();
      analysisRunId = json.run.id;
    });

    it("runs drift analysis on JSON configurations", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/analyses",
        payload: {
          expected: JSON.stringify({ security: { tls_version: "1.3" } }),
          actual: JSON.stringify({ security: { tls_version: "1.0" } }),
          format: "json",
        },
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.report.status).toBe("BLOCKED");
      expect(json.report.findings[0].ruleId).toBe("CIS-TLS-1");
    });

    it("runs drift analysis on TOML configurations", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/analyses",
        payload: {
          expected: "[security]\ncors_origin = 'https://app.com'",
          actual: "[security]\ncors_origin = '*'",
          format: "toml",
        },
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.report.status).toBe("BLOCKED");
      expect(json.report.findings[0].ruleId).toBe("CIS-CORS-1");
    });

    it("rejects malformed syntax safely with code 400", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/analyses",
        payload: {
          expected: "valid: yaml",
          actual: "{ malformed json: [ broken",
          format: "json",
        },
      });

      expect(res.statusCode).toBe(400);
      expect(res.json().error.code).toBe("CONFIG_PARSE_ERROR");
    });

    it("exports JSON and Markdown reports by analysis identifier for authorized owner", async () => {
      const jsonRes = await app.inject({
        method: "GET",
        url: `/api/v1/analyses/${analysisRunId}/reports/json`,
        headers: { authorization: `Bearer ${userToken}` },
      });
      expect(jsonRes.statusCode).toBe(200);
      expect(jsonRes.headers["content-type"]).toContain("application/json");
      const reportObj = JSON.parse(jsonRes.body);
      expect(reportObj.status).toBe("BLOCKED");

      const mdRes = await app.inject({
        method: "GET",
        url: `/api/v1/analyses/${analysisRunId}/reports/markdown`,
        headers: { authorization: `Bearer ${userToken}` },
      });
      expect(mdRes.statusCode).toBe(200);
      expect(mdRes.headers["content-type"]).toContain("text/markdown");
      expect(mdRes.body).toContain("# DriftGuard Configuration Drift Report");
    });

    it("updates finding review status for authorized owner", async () => {
      const findingsRes = await app.inject({
        method: "GET",
        url: `/api/v1/analyses/${analysisRunId}/findings`,
        headers: { authorization: `Bearer ${userToken}` },
      });
      const findingId = findingsRes.json().findings[0].id;

      const patchRes = await app.inject({
        method: "PATCH",
        url: `/api/v1/analyses/findings/${findingId}`,
        headers: { authorization: `Bearer ${userToken}` },
        payload: { status: "ACKNOWLEDGED" },
      });

      expect(patchRes.statusCode).toBe(200);
      expect(patchRes.json().reviewStatus).toBe("ACKNOWLEDGED");
    });
  });

  describe("Security & Multi-Tenant Authorization Enforcement", () => {
    let userAToken: string;
    let userBToken: string;
    let userAAnalysisId: string;
    let userAFindingId: string;
    let userAConfigId: string;

    beforeAll(async () => {
      // Create User A
      const regA = await app.inject({
        method: "POST",
        url: "/api/v1/auth/register",
        payload: { username: "user_a", email: "user_a@test.com", password: "Password123!" },
      });
      userAToken = regA.json().token;

      // Create User B
      const regB = await app.inject({
        method: "POST",
        url: "/api/v1/auth/register",
        payload: { username: "user_b", email: "user_b@test.com", password: "Password123!" },
      });
      userBToken = regB.json().token;

      // User A creates project & config
      const projRes = await app.inject({
        method: "POST",
        url: "/api/v1/projects",
        headers: { authorization: `Bearer ${userAToken}` },
        payload: { name: "User A Secret Project" },
      });
      const projAId = projRes.json().project.id;

      const confRes = await app.inject({
        method: "POST",
        url: `/api/v1/projects/${projAId}/configurations`,
        headers: { authorization: `Bearer ${userAToken}` },
        payload: { name: "a-config.yaml", format: "yaml", content: "secret_token: mysecret123" },
      });
      userAConfigId = confRes.json().configuration.id;

      // User A runs analysis
      const anaRes = await app.inject({
        method: "POST",
        url: "/api/v1/analyses",
        headers: { authorization: `Bearer ${userAToken}` },
        payload: {
          expected: "app:\n  debug: false",
          actual: "app:\n  debug: true",
          format: "yaml",
          projectId: projAId,
        },
      });
      userAAnalysisId = anaRes.json().run.id;

      const findingsRes = await app.inject({
        method: "GET",
        url: `/api/v1/analyses/${userAAnalysisId}/findings`,
        headers: { authorization: `Bearer ${userAToken}` },
      });
      userAFindingId = findingsRes.json().findings[0].id;
    });

    it("1. blocks unauthenticated client from accessing private analysis history", async () => {
      const res = await app.inject({ method: "GET", url: "/api/v1/analyses" });
      expect(res.statusCode).toBe(401);
      expect(res.json().error.code).toBe("UNAUTHORIZED");
    });

    it("2. blocks unauthenticated client from retrieving private analysis", async () => {
      const res = await app.inject({ method: "GET", url: `/api/v1/analyses/${userAAnalysisId}` });
      expect(res.statusCode).toBe(401);
    });

    it("3. blocks unauthenticated client from downloading private reports", async () => {
      const res = await app.inject({ method: "GET", url: `/api/v1/analyses/${userAAnalysisId}/reports/json` });
      expect(res.statusCode).toBe(401);

      const resMd = await app.inject({ method: "GET", url: `/api/v1/analyses/${userAAnalysisId}/reports/markdown` });
      expect(resMd.statusCode).toBe(401);
    });

    it("4. blocks unauthenticated client from changing finding review status", async () => {
      const res = await app.inject({
        method: "PATCH",
        url: `/api/v1/analyses/findings/${userAFindingId}`,
        payload: { status: "RESOLVED" },
      });
      expect(res.statusCode).toBe(401);
    });

    it("5. prevents User B from accessing User A's private analysis", async () => {
      const res = await app.inject({
        method: "GET",
        url: `/api/v1/analyses/${userAAnalysisId}`,
        headers: { authorization: `Bearer ${userBToken}` },
      });
      expect(res.statusCode).toBe(404);
      expect(res.json().error.code).toBe("NOT_FOUND");
    });

    it("6. prevents User B from accessing User A's saved configuration", async () => {
      const res = await app.inject({
        method: "GET",
        url: `/api/v1/configurations/${userAConfigId}`,
        headers: { authorization: `Bearer ${userBToken}` },
      });
      expect(res.statusCode).toBe(404);
      expect(res.json().error.code).toBe("NOT_FOUND");
    });

    it("7. prevents User B from downloading User A's private reports", async () => {
      const res = await app.inject({
        method: "GET",
        url: `/api/v1/analyses/${userAAnalysisId}/reports/json`,
        headers: { authorization: `Bearer ${userBToken}` },
      });
      expect(res.statusCode).toBe(404);
    });

    it("8. prevents User B from comparing User A's private analysis", async () => {
      const res = await app.inject({
        method: "GET",
        url: `/api/v1/analyses/${userAAnalysisId}/compare/${userAAnalysisId}`,
        headers: { authorization: `Bearer ${userBToken}` },
      });
      expect(res.statusCode).toBe(404);
      expect(res.json().error.code).toBe("COMPARISON_FAILED");
    });

    it("9. prevents User B from modifying User A's findings", async () => {
      const res = await app.inject({
        method: "PATCH",
        url: `/api/v1/analyses/findings/${userAFindingId}`,
        headers: { authorization: `Bearer ${userBToken}` },
        payload: { status: "RESOLVED" },
      });
      expect(res.statusCode).toBe(404);
    });

    it("10. invalidates session on logout", async () => {
      // Create session to logout
      const loginRes = await app.inject({
        method: "POST",
        url: "/api/v1/auth/login",
        payload: { identifier: "user_a", password: "Password123!" },
      });
      const tempToken = loginRes.json().token;

      // Verify active
      const activeRes = await app.inject({
        method: "GET",
        url: "/api/v1/auth/me",
        headers: { authorization: `Bearer ${tempToken}` },
      });
      expect(activeRes.statusCode).toBe(200);

      // Logout
      const logoutRes = await app.inject({
        method: "POST",
        url: "/api/v1/auth/logout",
        headers: { authorization: `Bearer ${tempToken}` },
      });
      expect(logoutRes.statusCode).toBe(200);

      // Verify invalidated
      const revokedRes = await app.inject({
        method: "GET",
        url: "/api/v1/auth/me",
        headers: { authorization: `Bearer ${tempToken}` },
      });
      expect(revokedRes.statusCode).toBe(401);
    });

    it("11. rejects expired sessions", async () => {
      // Query raw db and create an already expired session
      const userA = db.queryOne("SELECT id FROM users WHERE username = 'user_a'");
      const expiredToken = "expired_session_test_token_123456789";
      const tokenHash = require("node:crypto").createHash("sha256").update(expiredToken).digest("hex");
      const pastTime = new Date(Date.now() - 3600 * 1000).toISOString();

      db.run("INSERT INTO sessions (id, token_hash, user_id, expires_at) VALUES (?, ?, ?, ?)", [
        "expired-id-123",
        tokenHash,
        userA.id,
        pastTime,
      ]);

      const res = await app.inject({
        method: "GET",
        url: "/api/v1/auth/me",
        headers: { authorization: `Bearer ${expiredToken}` },
      });
      expect(res.statusCode).toBe(401);
    });

    it("12. sanitizes errors without leaking stack traces or internal SQL details", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/analyses",
        payload: {
          expected: "valid: true",
          actual: "{ malformed: [ syntax error",
          format: "json",
        },
      });

      expect(res.statusCode).toBe(400);
      const json = res.json();
      expect(json.error).toBeDefined();
      expect(json.error.message).toBeDefined();
      expect(json.stack).toBeUndefined(); // Stack trace never exposed
      expect(JSON.stringify(json)).not.toContain("SELECT "); // SQL internals never exposed
    });
  });
});
