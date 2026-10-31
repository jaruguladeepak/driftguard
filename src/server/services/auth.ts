import crypto from "node:crypto";
import { Repositories, UserRecord, SessionRecord } from "../db/repositories";

const SCRYPT_KEYLEN = 64;
const SESSION_TTL_HOURS = 24 * 7; // 7 days

export class AuthService {
  constructor(private repos: Repositories) {}

  /**
   * Hash a password using scrypt with a cryptographic salt.
   */
  public hashPassword(password: string): string {
    const salt = crypto.randomBytes(16).toString("hex");
    const derivedKey = crypto.scryptSync(password, salt, SCRYPT_KEYLEN);
    return `${salt}:${derivedKey.toString("hex")}`;
  }

  /**
   * Constant-time comparison to verify password hash.
   */
  public verifyPassword(password: string, storedHash: string): boolean {
    const [salt, key] = storedHash.split(":");
    if (!salt || !key) return false;

    const keyBuffer = Buffer.from(key, "hex");
    const derivedKey = crypto.scryptSync(password, salt, SCRYPT_KEYLEN);

    if (keyBuffer.length !== derivedKey.length) return false;
    return crypto.timingSafeEqual(keyBuffer, derivedKey);
  }

  /**
   * Hash a token using SHA-256 for secure database lookup.
   */
  public hashToken(token: string): string {
    return crypto.createHash("sha256").update(token).digest("hex");
  }

  /**
   * Register a new user with secure password hash.
   */
  public register(data: { username: string; email: string; password: string }): UserRecord {
    if (!data.username || data.username.length < 3) {
      throw new Error("Username must be at least 3 characters long.");
    }
    if (!data.email || !data.email.includes("@")) {
      throw new Error("Valid email address is required.");
    }
    if (!data.password || data.password.length < 8) {
      throw new Error("Password must be at least 8 characters long.");
    }

    const existingUser = this.repos.getUserByUsername(data.username);
    if (existingUser) {
      throw new Error("Username is already registered.");
    }

    const existingEmail = this.repos.getUserByEmail(data.email);
    if (existingEmail) {
      throw new Error("Email is already registered.");
    }

    const password_hash = this.hashPassword(data.password);
    return this.repos.createUser({
      username: data.username,
      email: data.email,
      password_hash,
      role: "user",
    });
  }

  /**
   * Authenticate user credentials and create a session.
   */
  public login(identifier: string, password: string): { user: Omit<UserRecord, "password_hash">; token: string; session: SessionRecord } {
    const user = identifier.includes("@")
      ? this.repos.getUserByEmail(identifier)
      : this.repos.getUserByUsername(identifier);

    if (!user || !this.verifyPassword(password, user.password_hash)) {
      throw new Error("Invalid username or password.");
    }

    // Generate cryptographically secure token
    const token = crypto.randomBytes(32).toString("hex");
    const tokenHash = this.hashToken(token);

    const expiresAt = new Date(Date.now() + SESSION_TTL_HOURS * 3600 * 1000).toISOString();
    const session = this.repos.createSession(user.id, tokenHash, expiresAt);

    const { password_hash: _, ...safeUser } = user;
    return { user: safeUser, token, session };
  }

  /**
   * Validate a session token.
   */
  public validateSession(token: string): (SessionRecord & { username: string; email: string; role: string }) | undefined {
    const tokenHash = this.hashToken(token);
    return this.repos.getSessionByTokenHash(tokenHash);
  }

  /**
   * Invalidate a session on logout.
   */
  public logout(token: string): void {
    const tokenHash = this.hashToken(token);
    this.repos.deleteSession(tokenHash);
  }
}
