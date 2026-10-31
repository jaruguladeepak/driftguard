import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import { SCHEMA_V1 } from "./schema";

export class DatabaseManager {
  private db: DatabaseSync;
  private isClosed = false;

  constructor(dbPath?: string) {
    const finalPath = dbPath || process.env.DATABASE_PATH || path.join(process.cwd(), "data", "driftguard.db");

    if (finalPath !== ":memory:") {
      const dir = path.dirname(finalPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    }

    this.db = new DatabaseSync(finalPath);
    this.init();
  }

  private init() {
    // Enable WAL mode and foreign key constraints
    this.db.exec("PRAGMA foreign_keys = ON;");
    this.db.exec("PRAGMA journal_mode = WAL;");

    // Run initial migration
    this.applyMigrations();
  }

  private applyMigrations() {
    this.db.exec(SCHEMA_V1);

    // Record v1 migration if not present
    const stmt = this.db.prepare("SELECT id FROM _migrations WHERE name = ?");
    const existing = stmt.get("001_initial_schema");
    if (!existing) {
      this.db.prepare("INSERT INTO _migrations (name) VALUES (?)").run("001_initial_schema");
    }
  }

  public getRawDb(): DatabaseSync {
    return this.db;
  }

  public exec(sql: string): void {
    this.db.exec(sql);
  }

  public query<T = any>(sql: string, params: any[] = []): T[] {
    const stmt = this.db.prepare(sql);
    return stmt.all(...params) as T[];
  }

  public queryOne<T = any>(sql: string, params: any[] = []): T | undefined {
    const stmt = this.db.prepare(sql);
    const result = stmt.get(...params);
    return result as T | undefined;
  }

  public run(sql: string, params: any[] = []): { changes: number | bigint; lastInsertRowid: number | bigint } {
    const stmt = this.db.prepare(sql);
    return stmt.run(...params);
  }

  public transaction<T>(fn: () => T): T {
    this.db.exec("BEGIN TRANSACTION;");
    try {
      const result = fn();
      this.db.exec("COMMIT;");
      return result;
    } catch (err) {
      this.db.exec("ROLLBACK;");
      throw err;
    }
  }

  public close(): void {
    if (!this.isClosed) {
      this.db.close();
      this.isClosed = true;
    }
  }
}

let defaultDb: DatabaseManager | null = null;

export function getDatabase(dbPath?: string): DatabaseManager {
  if (dbPath) {
    return new DatabaseManager(dbPath);
  }
  if (!defaultDb) {
    defaultDb = new DatabaseManager();
  }
  return defaultDb;
}
