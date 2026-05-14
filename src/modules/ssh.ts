import type { Finding } from "../types.ts"
import { readFileSync } from "fs"
import { join } from "path"

const HOME = process.env.HOME ?? ""

export async function runSSH(): Promise<Finding[]> {
  const findings: Finding[] = []

  // Authorized keys audit
  try {
    const content = readFileSync(join(HOME, ".ssh/authorized_keys"), "utf8")
    const keys = content.split("\n").filter(l => l.trim() && !l.startsWith("#"))
    if (keys.length > 0) {
      findings.push({
        id: "SSH-AUTHKEYS", severity: "medium",
        title: `authorized_keys contains ${keys.length} key(s) — review recommended`,
        detail: keys.map(k => "  - " + k.slice(0, 72) + "...").join("\n"),
        remediation: "Remove any keys you don't recognize. Document when each was added.",
      })
    }
  } catch { /* no authorized_keys — good */ }

  // PermitRootLogin check
  try {
    const config = readFileSync("/etc/ssh/sshd_config", "utf8")
    if (/^PermitRootLogin\s+yes/im.test(config)) {
      findings.push({
        id: "SSH-ROOTLOGIN", severity: "high",
        title: "SSH PermitRootLogin is enabled",
        detail: "Root login over SSH is permitted in /etc/ssh/sshd_config.",
        remediation: "Set PermitRootLogin no, then: sudo systemctl restart sshd",
      })
    }
  } catch { /* sshd_config not readable */ }

  if (findings.length === 0) {
    findings.push({
      id: "SSH-OK", severity: "info",
      title: "SSH configuration looks clean",
      detail: "No authorized_keys entries, root login not permitted.",
      remediation: "No action required.",
    })
  }

  return findings
}
