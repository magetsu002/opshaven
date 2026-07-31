import { randomBytes } from "node:crypto";
import type { McpPrincipal } from "../mcp.js";
import type { EnabledRemoteMcpConfig } from "./config.js";

export class RemoteSessionError extends Error {
  constructor(readonly status: 400 | 409 | 429, message = "Remote MCP session is invalid or unavailable.") { super(message); }
}

interface SessionRecord {
  readonly id: string;
  readonly principalId: string;
  readonly profileId: string;
  readonly protocol: string;
  readonly createdAt: number;
  lastActiveAt: number;
  pending: number;
  readonly maximumPending: number;
  readonly seenRequests: Set<string>;
}
export interface SessionLease {
  readonly principal: McpPrincipal;
  release(): void;
}

const SESSION_ID = /^[A-Za-z0-9_-]{43}$/;
function requestKey(value: string | number | null): string | undefined {
  if (typeof value === "string") return `s:${value}`;
  if (typeof value === "number" && Number.isFinite(value)) return `n:${value}`;
  return undefined;
}

export class RemoteSessionManager {
  private readonly sessions = new Map<string, SessionRecord>();
  private closed = false;
  constructor(private readonly config: EnabledRemoteMcpConfig, private readonly clock: () => number = Date.now) {}

  private profile(principal: McpPrincipal) {
    const profile = this.config.profiles.find((candidate) => candidate.id === principal.profileId);
    if (!profile) throw new RemoteSessionError(400);
    return profile;
  }
  private prune(now = this.clock()): void {
    for (const [id, session] of this.sessions) {
      const profile = this.config.profiles.find((candidate) => candidate.id === session.profileId);
      const lifetime = Math.min(this.config.sessions.lifetimeSeconds, profile?.sessionLimits.lifetimeSeconds ?? this.config.sessions.lifetimeSeconds) * 1000;
      const inactivity = Math.min(this.config.sessions.inactivitySeconds, profile?.sessionLimits.inactivitySeconds ?? this.config.sessions.inactivitySeconds) * 1000;
      if (now - session.createdAt >= lifetime || now - session.lastActiveAt >= inactivity) this.sessions.delete(id);
    }
  }
  create(principal: McpPrincipal, protocol: string): string {
    if (this.closed) throw new RemoteSessionError(409);
    this.prune();
    const profile = this.profile(principal);
    if (this.sessions.size >= this.config.sessions.maximumGlobal) throw new RemoteSessionError(429);
    const principalCount = [...this.sessions.values()].filter((session) => session.principalId === principal.id).length;
    const maximum = Math.min(this.config.sessions.maximumPerPrincipal, profile.sessionLimits.maximumSessions);
    if (principalCount >= maximum) throw new RemoteSessionError(429);
    let id: string;
    do { id = randomBytes(32).toString("base64url"); } while (this.sessions.has(id));
    const now = this.clock();
    this.sessions.set(id, {
      id,
      principalId: principal.id,
      profileId: profile.id,
      protocol,
      createdAt: now,
      lastActiveAt: now,
      pending: 0,
      maximumPending: Math.min(this.config.sessions.maximumPendingPerSession, profile.sessionLimits.maximumPendingRequests),
      seenRequests: new Set(),
    });
    return id;
  }
  acquire(sessionId: string, principal: McpPrincipal, protocol: string, id: string | number | null): SessionLease {
    if (this.closed || !SESSION_ID.test(sessionId)) throw new RemoteSessionError(400);
    this.prune();
    const session = this.sessions.get(sessionId);
    if (!session || session.principalId !== principal.id || session.profileId !== principal.profileId || session.protocol !== protocol) throw new RemoteSessionError(400);
    if (session.pending >= session.maximumPending) throw new RemoteSessionError(429);
    const key = requestKey(id);
    if (key && session.seenRequests.has(key)) throw new RemoteSessionError(409, "Remote MCP request was replayed.");
    if (key) {
      if (session.seenRequests.size >= 512) throw new RemoteSessionError(429);
      session.seenRequests.add(key);
    }
    session.pending += 1;
    session.lastActiveAt = this.clock();
    let released = false;
    return {
      principal: Object.freeze({ ...principal, sessionId }),
      release: () => {
        if (released) return;
        released = true;
        session.pending = Math.max(0, session.pending - 1);
        session.lastActiveAt = this.clock();
      },
    };
  }
  delete(sessionId: string, principal: McpPrincipal): void {
    const session = this.sessions.get(sessionId);
    if (!session || session.principalId !== principal.id || session.profileId !== principal.profileId) throw new RemoteSessionError(400);
    this.sessions.delete(sessionId);
  }
  close(): void { this.closed = true; this.sessions.clear(); }
  size(): number { this.prune(); return this.sessions.size; }
}
