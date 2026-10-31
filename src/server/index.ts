import { buildApp } from "./app";
import { getDatabase } from "./db/index";

const PORT = Number(process.env.PORT) || 3001;
const HOST = process.env.HOST || "0.0.0.0";

async function startServer() {
  const app = buildApp();

  try {
    const address = await app.listen({ port: PORT, host: HOST });
    console.log(`[DriftGuard Backend] Server listening at ${address}`);
    console.log(`[DriftGuard Backend] Health check: ${address}/health`);
    console.log(`[DriftGuard Backend] REST API base: ${address}/api/v1`);

    const shutdown = async (signal: string) => {
      console.log(`[DriftGuard Backend] Received ${signal}. Shutting down gracefully...`);
      try {
        await app.close();
        getDatabase().close();
        console.log("[DriftGuard Backend] Server and database closed cleanly.");
        process.exit(0);
      } catch (err) {
        console.error("[DriftGuard Backend] Error during graceful shutdown:", err);
        process.exit(1);
      }
    };

    process.on("SIGINT", () => shutdown("SIGINT"));
    process.on("SIGTERM", () => shutdown("SIGTERM"));
  } catch (err) {
    console.error("[DriftGuard Backend] Failed to start server:", err);
    process.exit(1);
  }
}

startServer();
