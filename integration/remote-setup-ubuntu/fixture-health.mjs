import { createServer } from "node:http";

const port = Number(process.argv[2]);
const application = process.argv[3] ?? "sample";
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("invalid fixture port");
createServer((request, response) => {
  if (request.url === "/health") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(`${JSON.stringify({ healthy: true, application })}\n`);
    return;
  }
  response.writeHead(404);
  response.end();
}).listen(port, "127.0.0.1");
