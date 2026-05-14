import type { Finding } from "../types.ts"
import { execSync } from "child_process"

const DANGEROUS_PORTS: Record<number, string> = {
  21: "FTP", 23: "Telnet", 3306: "MySQL", 5432: "PostgreSQL",
  6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
}

export async function runNetwork(): Promise<Finding[]> {
  const findings: Finding[] = []

  let ssOutput = ""
  try {
    ssOutput = execSync("ss -tlnp 2>/dev/null", { encoding: "utf8" })
  } catch {
    return [{
      id: "NET-000", severity: "info",
      title: "ss command unavailable",
      detail: "Could not run network scan.",
      remediation: "Install iproute2: sudo apt install iproute2",
    }]
  }

  for (const line of ssOutput.split("\n").slice(1)) {
    const cols = line.trim().split(/\s+/)
    if (cols.length < 5) continue
    const local = cols[3] ?? ""
    if (!local.includes("0.0.0.0") && !local.includes("*:")) continue
    const port = parseInt(local.split(":").pop() ?? "0")
    if (!port || !DANGEROUS_PORTS[port]) continue

    findings.push({
      id: `NET-${String(port).padStart(3, "0")}`,
      severity: "high",
      title: `${DANGEROUS_PORTS[port]} (port ${port}) exposed on all interfaces`,
      detail: `Port ${port} is listening on 0.0.0.0 and may be reachable from the LAN.`,
      remediation: `Bind to 127.0.0.1 or add a firewall rule: ufw deny ${port}`,
    })
  }

  if (findings.length === 0) {
    findings.push({
      id: "NET-OK", severity: "info",
      title: "No high-risk ports exposed on all interfaces",
      detail: "No database or legacy-protocol ports found listening on 0.0.0.0.",
      remediation: "No action required.",
    })
  }

  return findings
}
