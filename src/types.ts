export type Severity = "critical" | "high" | "medium" | "low" | "info"

export interface Finding {
  id: string
  severity: Severity
  title: string
  detail: string
  remediation: string
  module?: string
}

export interface AuditResult {
  host: string
  date: string
  findings: Finding[]
  duration_ms: number
}
