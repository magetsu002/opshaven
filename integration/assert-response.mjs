import { readFileSync } from "node:fs";

const [path, expectedOperation, expectedOk, forbidden = ""] = process.argv.slice(2);
if (!path || !expectedOperation || !expectedOk) throw new Error("assert-response arguments are required");
const text = readFileSync(path, "utf8").trim();
const message = JSON.parse(text);
const envelope = message?.result?.structuredContent;
if (envelope?.operation !== expectedOperation) throw new Error(`Unexpected operation: ${envelope?.operation}`);
if (envelope?.ok !== (expectedOk === "true")) throw new Error(`Unexpected result: ${JSON.stringify(envelope)}`);
if (forbidden && text.includes(forbidden)) throw new Error("Forbidden planted value crossed the boundary");
process.stdout.write(`${JSON.stringify(envelope)}\n`);
