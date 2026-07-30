import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";

const artifacts = process.argv.slice(2);
if (artifacts.length === 0) throw new Error("At least one artifact is required for provenance.");
async function digest(file) { return createHash("sha256").update(await fs.readFile(file)).digest("hex"); }
const subjects = [];
for (const file of artifacts.sort()) subjects.push({ name: path.basename(file), digest: { sha256: await digest(file) } });
const provenance = {
  _type: "https://in-toto.io/Statement/v1",
  subject: subjects,
  predicateType: "https://slsa.dev/provenance/v1",
  predicate: {
    buildDefinition: {
      buildType: "https://github.com/magetsu002/opshaven/reproducible-build/v1",
      externalParameters: { sourceDateEpoch: process.env.SOURCE_DATE_EPOCH ?? null },
      internalParameters: { node: process.version, npm: execFileSync("npm", ["--version"], { encoding: "utf8" }).trim() },
      resolvedDependencies: [
        { uri: "git+https://github.com/magetsu002/opshaven", digest: { gitCommit: execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(), gitTree: execFileSync("git", ["rev-parse", "HEAD^{tree}"], { encoding: "utf8" }).trim() } },
        { uri: "file:package-lock.json", digest: { sha256: await digest("package-lock.json") } },
        { uri: "file:security/capability-declaration.json", digest: { sha256: await digest("security/capability-declaration.json") } },
      ],
    },
    runDetails: { builder: { id: "https://github.com/magetsu002/opshaven/.github/workflows/release-verification.yml" }, metadata: { invocationId: process.env.GITHUB_RUN_ID ?? "local", startedOn: null, finishedOn: null } },
  },
};
const output = process.env.PROVENANCE_OUTPUT ?? "artifacts/opshaven.provenance.intoto.json";
await fs.mkdir(path.dirname(output), { recursive: true });
await fs.writeFile(output, `${JSON.stringify(provenance, null, 2)}\n`);
console.log(`provenance: ${subjects.length} subjects written to ${output}`);
