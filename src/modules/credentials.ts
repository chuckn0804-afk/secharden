import type { Finding } from "../types.ts"
import { statSync } from "fs"
import { join } from "path"

const HOME = process.env.HOME ?? ""

const DANGEROUS_ENV_PATTERNS = [
  /^ANTHROPIC_API_KEY$/,
  /^OPENAI_API_KEY$/,
  /^AWS_SECRET/,
  /^STRIPE_SECRET/,
  /.*_SECRET_KEY$/,
  /.*_PRIVATE_KEY$/,
]

const SENSITIVE_FILES = [
  { path: ".netrc",           severity: "high"   as const },
  { path: ".aws/credentials", severity: "high"   as const },
  { path: ".claude/.env",     severity: "medium" as const },
]

export async function runCredentials(): Promise<Finding[]> {
  const findings: Finding[] = []

  for (const [key, val] of Object.entries(process.env)) {
    if (!val || val.length < 8) continue
    if (DANGEROUS_ENV_PATTERNS.some(p => p.test(key))) {
      findings.push({
        id: "CRED-ENV", severity: "high",
        title: `Sensitive key in environment: ${key}`,
        detail: `${key} is set in the process environment and inherited by child processes.`,
        remediation: "Store in ~/.claude/.env (chmod 600) instead of the shell environment.",
      })
    }
  }

  for (const { path, severity } of SENSITIVE_FILES) {
    try {
      const stat = statSync(join(HOME, path))
      const mode = stat.mode & 0o777
      if (mode & 0o044) {
        findings.push({
          id: "CRED-FILE", severity,
          title: `${path} readable by group/world (${mode.toString(8)})`,
          detail: `${join(HOME, path)} contains secrets with overly permissive file mode.`,
          remediation: `chmod 600 ~/${path}`,
        })
      }
    } catch { /* file absent — ok */ }
  }

  if (findings.length === 0) {
    findings.push({
      id: "CRED-OK", severity: "info",
      title: "No obvious credential exposures found",
      detail: "Checked environment variables and common secret file locations.",
      remediation: "No action required.",
    })
  }

  return findings
}
