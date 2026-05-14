#!/usr/bin/env bun
/**
 * secharden — Security hardening audit tool for Windows / WSL2
 * Usage: bun src/index.ts [--module <name>] [--severity <level>] [--format <fmt>]
 */

import type { Finding, AuditResult, Severity } from "./types.ts"
import { runNetwork }     from "./modules/network.ts"
import { runCredentials } from "./modules/credentials.ts"
import { runFilesystem }  from "./modules/filesystem.ts"
import { runSSH }         from "./modules/ssh.ts"
import { runWSL }         from "./modules/wsl.ts"
import { renderMarkdown, renderTable, renderJson } from "./report.ts"
import { mkdir, writeFile } from "fs/promises"
import { join } from "path"
import { execSync } from "child_process"

const args = process.argv.slice(2)
const getArg = (flag: string) => { const i = args.indexOf(flag); return i !== -1 ? args[i + 1] : null }

const moduleFilter   = getArg("--module")
const severityFilter = getArg("--severity") as Severity | null
const format         = getArg("--format") ?? "markdown"

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"]

const modules: Record<string, () => Promise<Finding[]>> = {
  network:     runNetwork,
  credentials: runCredentials,
  filesystem:  runFilesystem,
  ssh:         runSSH,
  wsl:         runWSL,
}

const host = (() => {
  try { return execSync("hostname", { encoding: "utf8" }).trim() } catch { return "unknown" }
})()

console.log("secharden v0.1.0 — auditing " + host)
console.log("Modules: " + (moduleFilter ?? "all") + " | Severity: " + (severityFilter ?? "all") + " | Format: " + format + "\n")

const start = Date.now()
const allFindings: Finding[] = []

for (const [name, runner] of Object.entries(modules)) {
  if (moduleFilter && name !== moduleFilter) continue
  process.stdout.write("  Running " + name + "...")
  try {
    const found = await runner()
    allFindings.push(...found.map(f => ({ ...f, module: name })))
    console.log(" " + found.length + " finding(s)")
  } catch (err) {
    console.log(" ERROR: " + err)
  }
}

const filtered = severityFilter
  ? allFindings.filter(f => SEVERITY_ORDER.indexOf(f.severity) <= SEVERITY_ORDER.indexOf(severityFilter))
  : allFindings

filtered.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))

const result: AuditResult = {
  host,
  date: new Date().toISOString(),
  findings: filtered,
  duration_ms: Date.now() - start,
}

let output: string
if (format === "json")       output = renderJson(result)
else if (format === "table") output = renderTable(result)
else                         output = renderMarkdown(result)

if (format === "markdown") {
  const dateStr    = new Date().toISOString().slice(0, 10)
  const reportPath = join(process.cwd(), "reports", dateStr + "-audit.md")
  await mkdir(join(process.cwd(), "reports"), { recursive: true })
  await writeFile(reportPath, output)
  console.log("\nReport saved to: " + reportPath)
}

console.log("\n" + output)
console.log("\nAudit complete in " + result.duration_ms + "ms — " + filtered.length + " finding(s)")
