import { OpsHavenError } from "../core/errors.js";

export async function readSingleJsonLine(stream: NodeJS.ReadableStream, maxBytes = 65_536): Promise<unknown> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of stream) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    bytes += buffer.byteLength;
    if (bytes > maxBytes) throw new OpsHavenError("OUTPUT_LIMIT_EXCEEDED", "Dispatcher request exceeds hard limit");
    chunks.push(buffer);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (text.includes("\0")) throw new OpsHavenError("BINARY_OUTPUT_REJECTED", "Dispatcher request contains NUL");
  const lines = text.trimEnd().split("\n");
  const line = lines[0];
  if (lines.length !== 1 || line === undefined || line.length === 0) {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Dispatcher accepts exactly one JSON line");
  }
  try {
    return JSON.parse(line) as unknown;
  } catch {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Dispatcher request is not valid JSON");
  }
}
