import type { McpPrincipal } from "../mcp.js";
import type { EnabledRemoteMcpConfig } from "./config.js";

export class RemoteLimitError extends Error {
  constructor(readonly status: 400 | 403 | 408 | 413 | 429 | 503, message = "Remote MCP resource limit was exceeded.") { super(message); }
}

export function validateHeaderLimits(headers: Readonly<Record<string, string | string[] | undefined>>, maximumHeaders: number, maximumBytes: number): void {
  const entries = Object.entries(headers);
  if (entries.length > maximumHeaders) throw new RemoteLimitError(413, "Remote MCP header count exceeds the configured limit.");
  let bytes = 0;
  for (const [name, value] of entries) {
    bytes += Buffer.byteLength(name, "utf8") + 2;
    const values = Array.isArray(value) ? value : value === undefined ? [] : [value];
    if (values.length > 8) throw new RemoteLimitError(413, "Remote MCP header values exceed the configured limit.");
    for (const item of values) {
      if (typeof item !== "string" || /[\u0000\r\n]/.test(item)) throw new RemoteLimitError(400, "Remote MCP headers are malformed.");
      bytes += Buffer.byteLength(item, "utf8") + 2;
      if (bytes > maximumBytes) throw new RemoteLimitError(413, "Remote MCP headers exceed the configured byte limit.");
    }
  }
}

export function validateJsonComplexity(value: unknown, maximumDepth: number, maximumNodes: number): void {
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 1 }];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) break;
    nodes += 1;
    if (nodes > maximumNodes) throw new RemoteLimitError(413, "Remote MCP JSON structure exceeds the configured node limit.");
    if (current.depth > maximumDepth) throw new RemoteLimitError(413, "Remote MCP JSON structure exceeds the configured depth limit.");
    if (Array.isArray(current.value)) {
      if (current.value.length > maximumNodes) throw new RemoteLimitError(413);
      for (const item of current.value) stack.push({ value: item, depth: current.depth + 1 });
    } else if (current.value && typeof current.value === "object") {
      const entries = Object.entries(current.value as Record<string, unknown>);
      if (entries.length > maximumNodes) throw new RemoteLimitError(413);
      for (const [key, item] of entries) {
        if (key.length > 256) throw new RemoteLimitError(413, "Remote MCP JSON keys exceed the configured limit.");
        stack.push({ value: item, depth: current.depth + 1 });
      }
    } else if (typeof current.value === "string" && current.value.length > 262144) throw new RemoteLimitError(413, "Remote MCP JSON strings exceed the configured limit.");
  }
}

interface RateWindow { startedAt: number; count: number }
interface Waiter { readonly principal: McpPrincipal; readonly resolve: (lease: AdmissionLease) => void; readonly reject: (error: Error) => void; readonly timer: unknown }
export interface AdmissionLease { release(): void }

export class RemoteAdmissionController {
  private globalActive = 0;
  private readonly principalActive = new Map<string, number>();
  private readonly globalRate: RateWindow = { startedAt: 0, count: 0 };
  private readonly principalRates = new Map<string, RateWindow>();
  private readonly queue: Waiter[] = [];
  private closed = false;
  constructor(private readonly config: EnabledRemoteMcpConfig, private readonly clock: () => number = Date.now) {}

  private profile(principal: McpPrincipal) { return this.config.profiles.find((profile) => profile.id === principal.profileId); }
  private consumeRate(window: RateWindow, seconds: number, maximum: number): void {
    const now = this.clock();
    if (now - window.startedAt >= seconds * 1000) { window.startedAt = now; window.count = 0; }
    if (window.count >= maximum) throw new RemoteLimitError(429, "Remote MCP rate limit was exceeded.");
    window.count += 1;
  }
  private checkRate(principal: McpPrincipal): void {
    const profile = this.profile(principal);
    if (!profile) throw new RemoteLimitError(403, "Remote MCP profile is unavailable.");
    this.consumeRate(this.globalRate, this.config.rateLimits.windowSeconds, this.config.rateLimits.maximumRequests);
    const window = this.principalRates.get(principal.id) ?? { startedAt: 0, count: 0 };
    this.principalRates.set(principal.id, window);
    this.consumeRate(window, profile.rateLimits.windowSeconds, profile.rateLimits.maximumRequests);
  }
  private capacity(principal: McpPrincipal): boolean {
    const profile = this.profile(principal);
    const principalMaximum = Math.min(this.config.requests.perPrincipalConcurrency, profile?.rateLimits.concurrency ?? 1);
    return this.globalActive < this.config.requests.globalConcurrency && (this.principalActive.get(principal.id) ?? 0) < principalMaximum;
  }
  private grant(principal: McpPrincipal): AdmissionLease {
    this.globalActive += 1;
    this.principalActive.set(principal.id, (this.principalActive.get(principal.id) ?? 0) + 1);
    let released = false;
    return { release: () => {
      if (released) return;
      released = true;
      this.globalActive = Math.max(0, this.globalActive - 1);
      const active = Math.max(0, (this.principalActive.get(principal.id) ?? 1) - 1);
      if (active === 0) this.principalActive.delete(principal.id); else this.principalActive.set(principal.id, active);
      this.drain();
    } };
  }
  private drain(): void {
    if (this.closed) return;
    for (let index = 0; index < this.queue.length;) {
      const waiter = this.queue[index];
      if (!waiter) break;
      if (!this.capacity(waiter.principal)) { index += 1; continue; }
      this.queue.splice(index, 1);
      clearTimeout(waiter.timer as any);
      waiter.resolve(this.grant(waiter.principal));
    }
  }
  async acquire(principal: McpPrincipal): Promise<AdmissionLease> {
    if (this.closed) throw new RemoteLimitError(503);
    this.checkRate(principal);
    if (this.capacity(principal)) return this.grant(principal);
    if (this.queue.length >= this.config.requests.maximumQueue) throw new RemoteLimitError(429, "Remote MCP concurrency limit was exceeded.");
    return await new Promise<AdmissionLease>((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = this.queue.findIndex((item) => item.resolve === resolve);
        if (index >= 0) this.queue.splice(index, 1);
        reject(new RemoteLimitError(408, "Remote MCP queue wait timed out."));
      }, this.config.requests.timeoutMs);
      this.queue.push({ principal, resolve, reject, timer });
    });
  }
  close(): void {
    this.closed = true;
    for (const waiter of this.queue.splice(0)) {
      clearTimeout(waiter.timer as any);
      waiter.reject(new RemoteLimitError(503));
    }
  }
  active(): number { return this.globalActive; }
  queued(): number { return this.queue.length; }
}

export async function withRemoteTimeout<T>(work: (signal: AbortSignal) => Promise<T>, timeoutMs: number, disconnected?: AbortSignal): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const disconnect = (): void => controller.abort();
  disconnected?.addEventListener("abort", disconnect, { once: true });
  try { return await work(controller.signal); }
  catch (error) {
    if (controller.signal.aborted) throw new RemoteLimitError(408, "Remote MCP request timed out or was cancelled.");
    throw error;
  } finally {
    clearTimeout(timer);
    disconnected?.removeEventListener("abort", disconnect);
  }
}
