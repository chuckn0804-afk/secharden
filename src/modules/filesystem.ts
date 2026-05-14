import type { Finding } from "../types.ts"
import { statSync } from "fs"
import { join } from "path"

const HOME = process.env.HOME ?? ""

const CHECKS = [
  { path: ".ssh",             expected: 0o700, label: "~/.ssh directory" },
  { path: ".ssh/id_rsa",     expected: 0o600, label: "SSH private key (RSA)" },
  { path: ".ssh/id_ed25519", expected: 0o600, label: "SSH private key (ed25519)" },
  { path: ".claude/.env",    expected: 0o600, label: "PAI env file" },
  { path: ".claude",         expected: 0o700, label: "~/.claude directory" },
]

export async function runFilesystem(): Promise<Finding[]> {
  const findings: Finding[] = []

  for (const { path, expected, label } of CHECKS) {
    try {
      const actual = statSync(join(HOME, path)).mode & 0o777
      if (actual > expected) {
        findings.push({
          id: "FILE-PERM", severity: "medium",
          title: `${label} has loose permissions (${actual.toString(8)} vs ${expected.toString(8)})`,
          detail: `${join(HOME, path)} is more permissive than recommended.`,
          remediation: `chmod ${expected.toString(8)} ~/${path}`,
        })
      }
    } catch { /* path absent */ }
  }

  if (findings.length === 0) {
    findings.push({
      id: "FILE-OK", severity: "info",
      title: "Sensitive file permissions look correct",
      detail: "SSH keys, PAI config, and other sensitive paths checked.",
      remediation: "No action required.",
    })
  }

  return findings
}
