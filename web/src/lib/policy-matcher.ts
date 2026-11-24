import type { PolicyRule } from "@/lib/api"

/**
 * Mirrors `cx_protocol::host_matches_pattern`:
 * Exact hostname or single-level leftmost wildcard (`*.example.com`).
 */
export function hostMatchesPattern(host: string, pattern: string): boolean {
  const hostLc = host.trim().replace(/\.+$/, "").toLowerCase()
  const pat = pattern.trim().replace(/\.+$/, "").toLowerCase()
  if (pat === "*") return true
  if (pat.startsWith("*.")) {
    const suffix = pat.slice(2)
    if (!suffix) return false
    if (hostLc.endsWith(suffix)) {
      const prefix = hostLc.slice(0, hostLc.length - suffix.length)
      return prefix.endsWith(".") && prefix.length > 1
    }
    return false
  }
  return hostLc === pat
}

export function pathMatchesGlob(pathAndQuery: string, pattern: string): boolean {
  const pathOnly = pathAndQuery.split("?")[0] || "/"
  let regex = "^"
  let i = 0
  while (i < pattern.length) {
    const ch = pattern[i]
    if (ch === "*") {
      if (pattern[i + 1] === "*") {
        regex += ".*"
        i += 2
      } else {
        regex += "[^/]*"
        i += 1
      }
    } else if (ch === "?") {
      regex += "[^/]"
      i += 1
    } else if (ch === "{") {
      const end = pattern.indexOf("}", i)
      if (end !== -1) {
        const alts = pattern
          .slice(i + 1, end)
          .split(",")
          .map((p) => p.replace(/[.+^$|()[\]\\]/g, "\\$&"))
        regex += `(?:${alts.join("|")})`
        i = end + 1
      } else {
        regex += "\\{"
        i += 1
      }
    } else if (".+^$|()[]\\".includes(ch)) {
      regex += `\\${ch}`
      i += 1
    } else {
      regex += ch
      i += 1
    }
  }
  regex += "$"
  try {
    return new RegExp(regex).test(pathOnly)
  } catch {
    return false
  }
}

export interface PolicySimulationInput {
  method: string
  host: string
  path: string
}

export interface PolicySimulationResult {
  decision: "allow" | "deny"
  source: "preset" | "custom" | "default_deny"
  matchedIndex: number | null
  matchedRule: PolicyRule | null
  reason: string
}

function ruleMatches(
  rule: PolicyRule,
  methodUp: string,
  hostLc: string,
  pathOnly: string
): boolean {
  const methodOk =
    rule.methods.length === 0 ||
    rule.methods.some((m) => m === "*" || m.toUpperCase() === methodUp)
  if (!methodOk) return false

  const hostOk =
    rule.hosts.length === 0 ||
    rule.hosts.some((h) => h === "*" || hostMatchesPattern(hostLc, h))
  if (!hostOk) return false

  const pathOk =
    rule.paths.length === 0 ||
    rule.paths.some((p) => pathMatchesGlob(pathOnly, p))
  return pathOk
}

/**
 * Mirrors `cx_plugin::CompiledPolicy::evaluate` against preset + custom rules:
 * Explicit Deny wins immediately; otherwise at least one Allow must match; else default deny.
 */
export function simulatePlatformPolicy(
  presetName: string | null,
  presetRules: PolicyRule[],
  customRules: PolicyRule[],
  input: PolicySimulationInput
): PolicySimulationResult {
  const methodUp = input.method.trim().toUpperCase() || "GET"
  const hostLc = input.host.trim().replace(/\.+$/, "").toLowerCase()
  const pathOnly = (input.path.trim() || "/").split("?")[0] || "/"

  let allowHit: { source: "preset" | "custom"; idx: number; rule: PolicyRule } | null = null

  for (let idx = 0; idx < presetRules.length; idx++) {
    const rule = presetRules[idx]
    if (!ruleMatches(rule, methodUp, hostLc, pathOnly)) continue
    if (rule.effect === "deny") {
      return {
        decision: "deny",
        source: "preset",
        matchedIndex: idx,
        matchedRule: rule,
        reason: `命中预设 ${presetName ?? ""} 的拒绝规则 #${idx + 1}。`,
      }
    }
    if (!allowHit) allowHit = { source: "preset", idx, rule }
  }

  for (let idx = 0; idx < customRules.length; idx++) {
    const rule = customRules[idx]
    if (!ruleMatches(rule, methodUp, hostLc, pathOnly)) continue
    if (rule.effect === "deny") {
      return {
        decision: "deny",
        source: "custom",
        matchedIndex: idx,
        matchedRule: rule,
        reason: `命中自定义拒绝规则 #${idx + 1}（显式拒绝优先于所有允许规则和预设）。`,
      }
    }
    if (!allowHit) allowHit = { source: "custom", idx, rule }
  }

  if (allowHit) {
    return {
      decision: "allow",
      source: allowHit.source,
      matchedIndex: allowHit.idx,
      matchedRule: allowHit.rule,
      reason:
        allowHit.source === "preset"
          ? `命中预设 ${presetName ?? ""} 的允许规则 #${allowHit.idx + 1}，且未被任何拒绝规则拦截。`
          : `命中自定义允许规则 #${allowHit.idx + 1}，且未被任何拒绝规则拦截。`,
    }
  }

  return {
    decision: "deny",
    source: "default_deny",
    matchedIndex: null,
    matchedRule: null,
    reason: "未命中任何允许规则，按默认拒绝策略拦截。",
  }
}

export function describePolicyRule(rule: PolicyRule): string {
  const action = rule.effect === "allow" ? "允许" : "拒绝"
  const methods =
    rule.methods.length === 0 || rule.methods.includes("*")
      ? "任意方法"
      : rule.methods.join(" / ")
  const hosts =
    rule.hosts.length === 0 || rule.hosts.includes("*")
      ? "当前平台所有主机"
      : rule.hosts.join("、")
  const paths = rule.paths.length === 0 ? "任意路径" : rule.paths.join("、")
  return `${action} ${methods} ${hosts} ${paths}`
}
