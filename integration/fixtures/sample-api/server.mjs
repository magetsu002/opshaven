import { createServer } from "node:http";
import { promises as fs } from "node:fs";

const { revision } = JSON.parse(await fs.readFile(new URL("./dist/revision.json", import.meta.url), "utf8"));
const unhealthy = process.env.SAMPLE_API_UNHEALTHY === "1";
createServer((request, response) => {
  if (request.url === "/health") {
    response.writeHead(unhealthy ? 503 : 200, { "content-type": "application/json" });
    response.end(`${JSON.stringify({ healthy: !unhealthy, revision })}\n`);
    return;
  }
  if (request.url === "/version") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(`${JSON.stringify({ revision })}\n`);
    return;
  }
  response.writeHead(404);
  response.end();
}).listen(Number(process.env.PORT ?? 3000), "127.0.0.1");
