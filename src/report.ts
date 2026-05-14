import type { AuditResult, Finding, Severity } from "./types.ts"

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: "🔴",
  high:     "🟠",
  medium:   "🟡",
  low:      "🔵",
  info:     "⚪",
}

export function renderMarkdown(result: AuditResult): string {
  const lines: string[] = [
    `# secharden Audit Report`,
    `**Date:** ${result.date.slice(0, 10)} | **Host:** ${result.host} | **Duration:** ${result.duration_ms}ms`,
    "",
  ]

  if (result.findings.length === 0) {
    lines.push("✅ No findings. Environment looks clean.")
    return lines.join("\n")
  }

  const bySeverity = (sev: Severity) => result.findings.filter(f => f.severity === sev)

  for (const sev of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    const group = bySeverity(sev)
    if (group.length === 0) continue
    lines.push(`## ${SEVERITY_EMOJI[sev]} ${sev.toUpperCase()} (${group.length})`, "")
    for (const f of group) {
      lines.push(
        `### [${f.id}] ${f.title}`,
        `**Module:** ${f.module ?? "—"}`,
        f.detail,
        `> **Fix:** ${f.remediation}`,
        ""
      )
    }
  }

  return lines.join("\n")
}

export function renderTable(result: AuditResult): string {
  const header = "ID           | SEV      | Title"
  const sep    = "-------------|----------|----------------------------------------------"
  const rows = result.findings.map(f =>
    `${f.id.padEnd(12)} | ${f.severity.padEnd(8)} | ${f.title}`
  )
  return [header, sep, ...rows].join("\n")
}

export function renderJson(result: AuditResult): string {
  return JSON.stringify(result, null, 2)
}
