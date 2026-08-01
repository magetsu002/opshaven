import { promises as fs } from "node:fs";

const revision = (await fs.readFile(new URL("./revision.txt", import.meta.url), "utf8")).trim();
if (!/^[a-f0-9]{40}$/.test(revision)) throw new Error("Synthetic fixture revision is invalid.");
await fs.mkdir(new URL("./dist/", import.meta.url), { recursive: true });
await fs.writeFile(new URL("./dist/revision.json", import.meta.url), `${JSON.stringify({ revision })}\n`);
