import { promises as fs } from "node:fs";
import path from "node:path";
import { BOUNTY_INTEGRATIONS } from "../config/bountyIntegrations.js";

export async function buildBountyIntegrationReport({ rootDir }) {
  const integrations = await Promise.all(
    BOUNTY_INTEGRATIONS.map(async (integration) => {
      const absolutePath = path.join(rootDir, integration.localPath);
      const installed = await isDirectory(absolutePath);
      const stats = installed ? await collectIntegrationStats(absolutePath) : emptyStats();

      return {
        ...integration,
        absolutePath,
        installed,
        stats,
        updateHint: `powershell -ExecutionPolicy Bypass -File "${path.join(rootDir, "scripts", "update-bounty-integrations.ps1")}"`
      };
    })
  );

  return {
    generatedAt: new Date().toISOString(),
    integrations,
    installedCount: integrations.filter((item) => item.installed).length,
    safeUseNote: "Only run black-box templates against assets explicitly allowed by the program scope. Use findings as leads, then verify impact and reproducibility before submitting."
  };
}

async function collectIntegrationStats(root) {
  const stats = emptyStats();
  await walk(root, stats);
  return stats;
}

async function walk(current, stats) {
  let entries = [];
  try {
    entries = await fs.readdir(current, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (entry.name === ".git" || entry.name === "node_modules") continue;
    const fullPath = path.join(current, entry.name);
    if (entry.isDirectory()) {
      stats.directories += 1;
      await walk(fullPath, stats);
    } else if (entry.isFile()) {
      stats.files += 1;
      if (/\.ya?ml$/i.test(entry.name)) stats.yamlRules += 1;
      if (/\.md$/i.test(entry.name)) stats.docs += 1;
    }
  }
}

async function isDirectory(value) {
  try {
    return (await fs.stat(value)).isDirectory();
  } catch {
    return false;
  }
}

function emptyStats() {
  return {
    files: 0,
    directories: 0,
    yamlRules: 0,
    docs: 0
  };
}
