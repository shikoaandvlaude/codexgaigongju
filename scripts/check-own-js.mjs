import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";

const rootDir = path.resolve(import.meta.dirname, "..");
const excludedSegments = new Set(["node_modules", "integrations", "workspace", ".git"]);
const jsFiles = [];

await collectJsFiles(rootDir);

const failures = [];
for (const file of jsFiles) {
  const result = spawnSync(process.execPath, ["--check", file], { encoding: "utf8" });
  if (result.status !== 0) {
    failures.push({ file, output: `${result.stdout || ""}${result.stderr || ""}`.trim() });
  }
}

if (failures.length) {
  for (const failure of failures) {
    console.error(`\n[check failed] ${path.relative(rootDir, failure.file)}`);
    console.error(failure.output);
  }
  process.exit(1);
}

console.log(`Checked ${jsFiles.length} own JS files.`);

async function collectJsFiles(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (excludedSegments.has(entry.name)) {
      continue;
    }
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await collectJsFiles(fullPath);
    } else if (entry.isFile() && entry.name.endsWith(".js")) {
      jsFiles.push(fullPath);
    }
  }
}
