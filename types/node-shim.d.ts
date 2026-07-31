declare const process: {
  argv: string[];
  env: Record<string, string | undefined>;
  stdin: NodeJS.ReadableStream;
  stdout: NodeJS.WritableStream & { write(chunk: string | Uint8Array): boolean };
  stderr: NodeJS.WritableStream & { write(chunk: string | Uint8Array): boolean };
  exitCode?: number;
  pid: number;
  execPath: string;
  versions?: { node?: string };
  cwd(): string;
  getuid?(): number;
  umask(mask?: number): number;
  on(event: string, listener: (...args: unknown[]) => void): void;
};
declare const Buffer: {
  from(input: string | Uint8Array, encoding?: string): Uint8Array & { toString(encoding?: string): string; length: number };
  byteLength(input: string, encoding?: string): number;
  concat(chunks: readonly Uint8Array[]): Uint8Array & { toString(encoding?: string): string; length: number };
  isBuffer(value: unknown): value is Uint8Array;
};
declare const URL: { new(input: string, base?: string): { protocol: string; username: string; password: string; hostname: string; port: string; pathname: string; search: string; searchParams: { has(name: string): boolean }; hash: string; origin: string; toString(): string } };
declare namespace NodeJS {
  interface ReadableStream { on(event: string, listener: (...args: any[]) => void): this; resume(): void; }
  interface WritableStream { write(chunk: string | Uint8Array): boolean; }
  interface Timeout {}
  interface Signals {}
}
declare module "node:assert/strict" { const assert: any; export default assert; }
declare module "node:test" { const test: any; export default test; }
declare module "node:crypto" {
  export const constants: { RSA_PKCS1_PSS_PADDING: number };
  export function createHash(algorithm: string): { update(data: string | Uint8Array): any; digest(encoding: "hex"): string };
  export function createHmac(algorithm: string, key: string | Uint8Array): { update(data: string | Uint8Array): any; digest(encoding?: "hex" | "base64url"): any };
  export function randomBytes(size: number): Uint8Array & { toString(encoding: "hex" | "base64url"): string };
  export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean;
  export function sign(algorithm: null, data: Uint8Array, key: any): Uint8Array & { toString(encoding: "base64url"): string };
  export function verify(algorithm: null | string, data: Uint8Array, key: any, signature: Uint8Array): boolean;
  export function generateKeyPairSync(type: "ed25519"): { publicKey: { export(options: any): any }; privateKey: { export(options: any): any } };
  export function createPublicKey(options: any): any;
}
declare module "node:fs" {
  export const constants: any;
  export const promises: any;
  export function createReadStream(path: string, options?: any): any;
  export function createWriteStream(path: string, options?: any): any;
}
declare module "node:path" { const path: any; export default path; }
declare module "node:os" { export function homedir(): string; export function tmpdir(): string; }
declare module "node:child_process" { export function spawn(command: string, args?: readonly string[], options?: any): any; }
declare module "node:http" {
  export function request(options: any, callback: (response: any) => void): any;
  export function createServer(listener: (request: any, response: any) => void | Promise<void>): any;
}
declare module "node:https" { export function request(options: any, callback: (response: any) => void): any; }
declare module "node:readline" { export function createInterface(options: any): any; }
declare module "node:url" { export function fileURLToPath(url: string): string; }
