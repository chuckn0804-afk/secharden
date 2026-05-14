import type { Finding } from "../types.ts"
import { readFileSync } from "fs"
import { execSync } from "child_process"

function isWSL(): boolean {
  try { return readFileSync("/proc/version", "utf8").toLowerCase().includes("microsoft") }
  catch { return false }
}

export async function runWSL(): Promise<Finding[]> {
  if (!isWSL()) {
    return [{ id: "WSL-NA", severity: "info", title: "Not running in WSL", detail: "WSL checks skipped.", remediation: "N/A" }]
  }

  const findings: Finding[] = []

  // systemd check
  try {
    const wslConf = readFileSync("/etc/wsl.conf", "utf8")
    if (/\[boot\][\s\S]*systemd\s*=\s*true/i.test(wslConf)) {
      findings.push({
        id: "WSL-SYSTEMD", severity: "info",
        title: "systemd enabled in WSL",
        detail: "Expands the init system and enables more services. Expected for PAI workloads.",
        remediation: "No action required if you intentionally use systemd services.",
      })
    }
  } catch { /* wsl.conf absent */ }

  // Windows Firewall check
  try {
    const fw = execSync(
      'powershell.exe -Command "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled" 2>/dev/null',
      { encoding: "utf8", timeout: 5000 }
    ).trim()
    if (fw.includes("False")) {
      findings.push({
        id: "WSL-FW", severity: "high",
        title: "Windows Firewall disabled on one or more profiles",
        detail: `Profile state: ${fw.replace(/\n/g, ", ")}`,
        remediation: "Re-enable in Windows Security > Firewall & network protection.",
      })
    } else {
      findings.push({
        id: "WSL-FW-OK", severity: "info",
        title: "Windows Firewall enabled on all profiles",
        detail: "Inbound rules apply to WSL-exposed ports.",
        remediation: "No action required.",
      })
    }
  } catch { /* powershell unavailable */ }

  return findings
}
