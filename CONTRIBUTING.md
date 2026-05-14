# Contributing to secharden

Thanks for helping make secharden better. Contributions of all kinds are welcome — new checks, bug fixes, documentation, and platform support.

## Adding a new check

Each security domain lives in `src/modules/<name>.ts`. A module exports a single async function:

```typescript
export async function run<Name>(): Promise<Finding[]>
```

A `Finding` has five required fields:

```typescript
{
  id: "PREFIX-SHORT_ID",          // e.g. "NET-REDIS", "CRED-AWSKEY"
  severity: "critical" | "high" | "medium" | "low" | "info",
  title: "Short human-readable title",
  detail: "Full explanation of what was found",
  remediation: "Exact steps to fix it",
}
```

Severity guidelines:

| Level | Meaning |
|-------|---------|
| critical | Immediate compromise risk (e.g. unauthenticated service on 0.0.0.0) |
| high | Significant exposure, exploitable under common conditions |
| medium | Weakens defense-in-depth; should be fixed but not urgent |
  | low | Best-practice deviation with minimal direct risk |
| info | Informational; no remediation needed |

After writing the module, import and register it in `src/index.ts` under the `modules` map.

## Code style

- TypeScript strict mode
- Bun runtime — use `Bun.*` APIs where they simplify things
- No external dependencies beyond what's in `package.json`
- `try/catch` around every OS call — a missing file is never a crash

## Pull request checklist

- [ ] Module file added under `src/modules/`
- [ ] Module registered in `src/index.ts`
- [ ] Each finding has a unique `id`, correct `severity`, and a concrete `remediation`
- [ ] `bun run audit -- --module <name>` runs cleanly on WSL2 Ubuntu

## Reporting issues

Open a GitHub issue. Include your OS version (`uname -a`), Bun version (`bun --version`), and the full console output.
