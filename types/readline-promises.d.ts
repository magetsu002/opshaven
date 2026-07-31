declare module "node:readline/promises" {
  export interface Interface {
    question(prompt: string): Promise<string>;
    close(): void;
  }
  export function createInterface(options: { input: unknown; output: unknown; terminal?: boolean }): Interface;
}
