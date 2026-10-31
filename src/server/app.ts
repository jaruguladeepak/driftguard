import Fastify, { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import cors from "@fastify/cors";
import cookie from "@fastify/cookie";
import rateLimit from "@fastify/rate-limit";
import { DatabaseManager, getDatabase } from "./db/index";
import { Repositories, UserRecord } from "./db/repositories";
import { AuthService } from "./services/auth";
import { AnalysisService } from "./services/analysis";
import { ConfigParseError } from "../core/parser";

declare module "fastify" {
  interface FastifyRequest {
    user?: Omit<UserRecord, "password_hash">;
    sessionToken?: string;
  }
}

export interface AppOptions {
  dbPath?: string;
  db?: DatabaseManager;
  disableRateLimit?: boolean;
}

export function buildApp(options: AppOptions = {}): FastifyInstance {
  const app = Fastify({
    logger: false,
    bodyLimit: 5 * 1024 * 1024, // 5 MB max body size
  });

  const db: DatabaseManager = options.db || getDatabase(options.dbPath);
  const repos = new Repositories(db);
  const authService = new AuthService(repos);
  const analysisService = new AnalysisService(repos);

  // Security: CORS
  app.register(cors, {
    origin: (origin, cb) => {
      if (!origin || /^http:\/\/(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+)(:\d+)?$/.test(origin)) {
        cb(null, true);
        return;
      }
      cb(new Error("CORS: Not allowed origin"), false);
    },
    credentials: true,
  });

  // Security: Cookie parsing
  app.register(cookie, {
    secret: process.env.COOKIE_SECRET || "driftguard-insecure-cookie-secret-change-in-prod-1234567890",
  });

  // Security: Rate limiting
  if (!options.disableRateLimit) {
    app.register(rateLimit, {
      max: 100,
      timeWindow: "1 minute",
    });
  }

  // Security: Global Security Headers
  app.addHook("onSend", async (_request, reply) => {
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("X-Frame-Options", "DENY");
    reply.header("X-XSS-Protection", "1; mode=block");
    reply.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  });

  // Centralized Error Handling
  app.setErrorHandler((error: any, request, reply) => {
    const statusCode = error.statusCode || (error instanceof ConfigParseError ? 400 : 500);

    let safeMessage = error.message || "Internal server error";
    if (statusCode === 500 && process.env.NODE_ENV === "production") {
      safeMessage = "An internal server error occurred.";
    }

    reply.status(statusCode).send({
      error: {
        code: error.code || "REQUEST_ERROR",
        message: safeMessage,
        statusCode,
        requestId: request.id,
      },
    });
  });

  // Strict Authentication Decorator
  app.decorate("authenticate", async (request: FastifyRequest, reply: FastifyReply) => {
    const cookieToken = request.cookies.driftguard_session;
    const authHeader = request.headers.authorization;
    const bearerToken = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : undefined;
    const token = cookieToken || bearerToken;

    if (!token) {
      reply.status(401).send({
        error: {
          code: "UNAUTHORIZED",
          message: "Authentication required to access this resource.",
          statusCode: 401,
        },
      });
      return;
    }

    const session = authService.validateSession(token);
    if (!session) {
      reply.status(401).send({
        error: {
          code: "SESSION_EXPIRED",
          message: "Session is invalid or has expired.",
          statusCode: 401,
        },
      });
      return;
    }

    const user = repos.getUserById(session.user_id);
    if (!user) {
      reply.status(401).send({
        error: {
          code: "USER_NOT_FOUND",
          message: "User associated with this session no longer exists.",
          statusCode: 401,
        },
      });
      return;
    }

    const { password_hash: _, ...safeUser } = user;
    request.user = safeUser;
    request.sessionToken = token;
  });

  // Optional Session Context Hook
  app.addHook("preHandler", async (request) => {
    const cookieToken = request.cookies.driftguard_session;
    const authHeader = request.headers.authorization;
    const bearerToken = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : undefined;
    const token = cookieToken || bearerToken;

    if (token) {
      const session = authService.validateSession(token);
      if (session) {
        const user = repos.getUserById(session.user_id);
        if (user) {
          const { password_hash: _, ...safeUser } = user;
          request.user = safeUser;
          request.sessionToken = token;
        }
      }
    }
  });

  // ================= HEALTH =================
  app.get("/health", async () => {
    return {
      status: "ok",
      version: "1.0.0",
      timestamp: new Date().toISOString(),
      engine: "DriftGuard Core 2.0",
    };
  });

  // ================= AUTH ROUTES =================
  app.post("/api/v1/auth/register", async (request, reply) => {
    const body = request.body as any;
    if (!body || !body.username || !body.email || !body.password) {
      return reply.status(400).send({
        error: { code: "VALIDATION_ERROR", message: "Username, email, and password are required.", statusCode: 400 },
      });
    }

    try {
      const user = authService.register(body);
      repos.logAudit({
        userId: user.id,
        action: "USER_REGISTERED",
        resourceType: "user",
        resourceId: user.id,
        ipAddress: request.ip,
      });

      const { user: safeUser, token } = authService.login(user.username, body.password);
      reply.setCookie("driftguard_session", token, {
        path: "/",
        httpOnly: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 3600,
      });

      return reply.status(201).send({ user: safeUser, token });
    } catch (err: any) {
      return reply.status(400).send({
        error: { code: "REGISTRATION_FAILED", message: err.message, statusCode: 400 },
      });
    }
  });

  app.post("/api/v1/auth/login", async (request, reply) => {
    const body = request.body as any;
    const identifier = body?.identifier || body?.username || body?.email;
    const password = body?.password;

    if (!identifier || !password) {
      return reply.status(400).send({
        error: { code: "VALIDATION_ERROR", message: "Identifier (username/email) and password are required.", statusCode: 400 },
      });
    }

    try {
      const { user, token } = authService.login(identifier, password);
      repos.logAudit({
        userId: user.id,
        action: "USER_LOGIN",
        resourceType: "user",
        resourceId: user.id,
        ipAddress: request.ip,
      });

      reply.setCookie("driftguard_session", token, {
        path: "/",
        httpOnly: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 3600,
      });

      return { user, token };
    } catch (err: any) {
      return reply.status(401).send({
        error: { code: "INVALID_CREDENTIALS", message: err.message, statusCode: 401 },
      });
    }
  });

  app.post("/api/v1/auth/logout", { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    if (request.sessionToken) {
      authService.logout(request.sessionToken);
      repos.logAudit({
        userId: request.user!.id,
        action: "USER_LOGOUT",
        resourceType: "session",
        ipAddress: request.ip,
      });
    }
    reply.clearCookie("driftguard_session", { path: "/" });
    return { success: true, message: "Logged out successfully." };
  });

  app.get("/api/v1/auth/me", { preHandler: [(app as any).authenticate] }, async (request) => {
    return { user: request.user };
  });

  // ================= PROJECTS =================
  app.get("/api/v1/projects", { preHandler: [(app as any).authenticate] }, async (request) => {
    const projects = repos.listProjectsByUser(request.user!.id);
    return { projects };
  });

  app.post("/api/v1/projects", { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const body = request.body as any;
    if (!body?.name || typeof body.name !== "string" || body.name.trim().length === 0) {
      return reply.status(400).send({
        error: { code: "VALIDATION_ERROR", message: "Project name is required.", statusCode: 400 },
      });
    }

    const project = repos.createProject(request.user!.id, body.name.trim(), body.description?.trim());
    repos.logAudit({
      userId: request.user!.id,
      action: "PROJECT_CREATED",
      resourceType: "project",
      resourceId: project.id,
      details: { name: project.name },
      ipAddress: request.ip,
    });

    return reply.status(201).send({ project });
  });

  app.get("/api/v1/projects/:id", { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const { id } = request.params as any;
    const project = repos.getProjectById(id, request.user!.id);
    if (!project) {
      return reply.status(404).send({
        error: { code: "NOT_FOUND", message: "Project not found.", statusCode: 404 },
      });
    }
    const configs = repos.listConfigurationsByProject(id);
    const analyses = repos.listAnalysisRuns({ projectId: id, userId: request.user!.id, limit: 10 });
    return { project, configurations: configs, recentAnalyses: analyses };
  });

  app.patch("/api/v1/projects/:id", { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const { id } = request.params as any;
    const body = request.body as any;
    const updated = repos.updateProject(id, request.user!.id, {
      name: body?.name,
      description: body?.description,
    });
    if (!updated) {
      return reply.status(404).send({
        error: { code: "NOT_FOUND", message: "Project not found.", statusCode: 404 },
      });
    }
    return { project: updated };
  });

  app.delete("/api/v1/projects/:id", { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const { id } = request.params as any;
    const deleted = repos.deleteProject(id, request.user!.id);
    if (!deleted) {
      return reply.status(404).send({
        error: { code: "NOT_FOUND", message: "Project not found.", statusCode: 404 },
      });
    }
    repos.logAudit({
      userId: request.user!.id,
      action: "PROJECT_DELETED",
      resourceType: "project",
      resourceId: id,
      ipAddress: request.ip,
    });
    return reply.status(204).send();
  });

  // ================= CONFIGURATIONS =================
  app.get("/api/v1/projects/:projectId/configurations", { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const { projectId } = request.params as any;
    const project = repos.getProjectById(projectId, request.user!.id);
    if (!project) {
      return reply.status(404).send({ error: { code: "NOT_FOUND", message: "Project not found.", statusCode: 404 } });
    }
    const configurations = repos.listConfigurationsByProject(projectId);
    return { configurations };
  });

  app.post("/api/v1/projects/:projectId/configurations", { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const { projectId } = request.params as any;
    const project = repos.getProjectById(projectId, request.user!.id);
    if (!project) {
      return reply.status(404).send({ error: { code: "NOT_FOUND", message: "Project not found.", statusCode: 404 } });
    }

    const body = request.body as any;
    if (!body?.name || !body?.content || !body?.format) {
      return reply.status(400).send({
        error: { code: "VALIDATION_ERROR", message: "Configuration name, format (yaml/json/toml), and content are required.", statusCode: 400 },
      });
    }

    const config = repos.createConfiguration({
      projectId,
      name: body.name.trim(),
      format: body.format,
      content: body.content,
      isBaseline: Boolean(body.isBaseline),
    });

    repos.logAudit({
      userId: request.user!.id,
      action: "CONFIGURATION_CREATED",
      resourceType: "configuration",
      resourceId: config.id,
      details: { name: config.name, format: config.format },
      ipAddress: request.ip,
    });

    return reply.status(201).send({ configuration: config });
  });

  app.get("/api/v1/configurations/:id", { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const { id } = request.params as any;
    const config = repos.getConfigurationById(id, request.user!.id);
    if (!config) {
      return reply.status(404).send({ error: { code: "NOT_FOUND", message: "Configuration not found.", statusCode: 404 } });
    }
    return { configuration: config };
  });

  app.patch("/api/v1/configurations/:id", { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const { id } = request.params as any;
    const body = request.body as any;
    const updated = repos.updateConfiguration(
      id,
      {
        name: body?.name,
        content: body?.content,
        isBaseline: body?.isBaseline,
      },
      request.user!.id
    );
    if (!updated) {
      return reply.status(404).send({ error: { code: "NOT_FOUND", message: "Configuration not found.", statusCode: 404 } });
    }
    return { configuration: updated };
  });

  app.delete("/api/v1/configurations/:id", { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const { id } = request.params as any;
    const deleted = repos.deleteConfiguration(id, request.user!.id);
    if (!deleted) {
      return reply.status(404).send({ error: { code: "NOT_FOUND", message: "Configuration not found.", statusCode: 404 } });
    }
    return reply.status(204).send();
  });

  // ================= ANALYSES =================
  /**
   * Submit configuration for analysis:
   * - Authenticated users: executes analysis, saves to SQLite database, logs audit event, and returns { report, run }.
   * - Unauthenticated users: executes in-memory only and returns { report } without database writes.
   * - If an unauthenticated user specifies a projectId: rejected with 401 Unauthorized.
   */
  app.post("/api/v1/analyses", async (request, reply) => {
    const body = request.body as any;
    if (!body || typeof body.expected !== "string" || typeof body.actual !== "string") {
      return reply.status(400).send({
        error: { code: "VALIDATION_ERROR", message: "Expected and actual configuration strings are required.", statusCode: 400 },
      });
    }

    if (body.projectId && !request.user) {
      return reply.status(401).send({
        error: { code: "UNAUTHORIZED", message: "Authentication required to associate analysis with a project.", statusCode: 401 },
      });
    }

    if (body.projectId && request.user) {
      const project = repos.getProjectById(body.projectId, request.user.id);
      if (!project) {
        return reply.status(404).send({
          error: { code: "NOT_FOUND", message: "Project not found.", statusCode: 404 },
        });
      }
    }

    try {
      if (request.user) {
        // Authenticated: Persist to database
        const { report, run } = analysisService.executeAndPersistAnalysis({
          expected: body.expected,
          actual: body.actual,
          format: body.format,
          expectedSource: body.expectedSource || "Expected Baseline",
          actualSource: body.actualSource || "Actual Configuration",
          projectId: body.projectId || null,
          userId: request.user.id,
        });

        repos.logAudit({
          userId: request.user.id,
          action: "ANALYSIS_EXECUTED",
          resourceType: "analysis",
          resourceId: run.id,
          details: { status: run.status, totalDiffs: run.total_diffs },
          ipAddress: request.ip,
        });

        return reply.status(201).send({ report, run });
      }

      // Unauthenticated: In-memory one-time analysis (zero database persistence)
      const { report } = analysisService.executeAnalysisOnly({
        expected: body.expected,
        actual: body.actual,
        format: body.format,
        expectedSource: body.expectedSource || "Expected Baseline",
        actualSource: body.actualSource || "Actual Configuration",
      });

      return reply.status(200).send({ report });
    } catch (err: any) {
      if (err instanceof ConfigParseError) {
        return reply.status(400).send({
          error: { code: "CONFIG_PARSE_ERROR", message: err.message, statusCode: 400 },
        });
      }
      return reply.status(400).send({
        error: { code: "ANALYSIS_FAILED", message: err.message, statusCode: 400 },
      });
    }
  });

  // Protected: List authenticated user's analysis history
  app.get("/api/v1/analyses", { preHandler: [(app as any).authenticate] }, async (request) => {
    const query = request.query as any;
    const runs = repos.listAnalysisRuns({
      userId: request.user!.id,
      projectId: query.projectId,
      limit: query.limit ? Number(query.limit) : 50,
      offset: query.offset ? Number(query.offset) : 0,
    });
    return { analyses: runs };
  });

  // Protected: Retrieve single analysis run with ownership check
  app.get("/api/v1/analyses/:id", { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const { id } = request.params as any;
    const run = repos.getAnalysisRunById(id, request.user!.id);
    if (!run) {
      return reply.status(404).send({ error: { code: "NOT_FOUND", message: "Analysis run not found.", statusCode: 404 } });
    }
    const findings = repos.getFindingsByRun(id, undefined, request.user!.id);
    return { run, findings };
  });

  // Protected: Retrieve findings for an analysis run with ownership check
  app.get("/api/v1/analyses/:id/findings", { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const { id } = request.params as any;
    const query = request.query as any;
    const run = repos.getAnalysisRunById(id, request.user!.id);
    if (!run) {
      return reply.status(404).send({ error: { code: "NOT_FOUND", message: "Analysis run not found.", statusCode: 404 } });
    }
    const findings = repos.getFindingsByRun(id, {
      severity: query.severity,
      ruleId: query.ruleId,
    }, request.user!.id);
    return { findings };
  });

  // Protected: Update finding review status with ownership check
  app.patch("/api/v1/analyses/findings/:findingId", { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const { findingId } = request.params as any;
    const body = request.body as any;
    if (!body?.status || !["PENDING", "ACKNOWLEDGED", "RESOLVED"].includes(body.status)) {
      return reply.status(400).send({
        error: { code: "VALIDATION_ERROR", message: "Valid status (PENDING, ACKNOWLEDGED, RESOLVED) is required.", statusCode: 400 },
      });
    }

    const updated = repos.updateFindingReviewStatus(findingId, body.status, request.user!.id);
    if (!updated) {
      return reply.status(404).send({ error: { code: "NOT_FOUND", message: "Finding not found.", statusCode: 404 } });
    }
    return { success: true, findingId, reviewStatus: body.status };
  });

  // Protected: Download JSON report with ownership check
  app.get("/api/v1/analyses/:id/reports/json", { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const { id } = request.params as any;
    const report = repos.getReportByRunAndFormat(id, "json", request.user!.id);
    if (!report) {
      return reply.status(404).send({ error: { code: "NOT_FOUND", message: "JSON report not found.", statusCode: 404 } });
    }
    reply.header("Content-Type", "application/json");
    reply.header("Content-Disposition", `attachment; filename="drift-report-${id}.json"`);
    return reply.send(report.content);
  });

  // Protected: Download Markdown report with ownership check
  app.get("/api/v1/analyses/:id/reports/markdown", { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const { id } = request.params as any;
    const report = repos.getReportByRunAndFormat(id, "markdown", request.user!.id);
    if (!report) {
      return reply.status(404).send({ error: { code: "NOT_FOUND", message: "Markdown report not found.", statusCode: 404 } });
    }
    reply.header("Content-Type", "text/markdown; charset=utf-8");
    reply.header("Content-Disposition", `attachment; filename="drift-report-${id}.md"`);
    return reply.send(report.content);
  });

  // Protected: Compare historical runs with mutual ownership check
  app.get("/api/v1/analyses/:id/compare/:otherId", { preHandler: [(app as any).authenticate] }, async (request, reply) => {
    const { id, otherId } = request.params as any;
    try {
      const comparison = analysisService.compareHistoricalRuns(id, otherId, request.user!.id);
      return { comparison };
    } catch (err: any) {
      return reply.status(404).send({
        error: { code: "COMPARISON_FAILED", message: err.message, statusCode: 404 },
      });
    }
  });

  // ================= AUDIT =================
  // Protected: Retrieve user's own audit events
  app.get("/api/v1/audit-events", { preHandler: [(app as any).authenticate] }, async (request) => {
    const events = repos.listAuditEvents(request.user!.id, 100);
    return { auditEvents: events };
  });

  return app;
}
