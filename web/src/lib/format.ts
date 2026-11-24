import type { AuditEntry } from "@/lib/api"
import { getCurrentLocale, translate, type Locale } from "@/lib/i18n"

const fullDateFormatters: Record<Locale, Intl.DateTimeFormat> = {
  "zh-CN": new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }),
  en: new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }),
}

const shortDateFormatters: Record<Locale, Intl.DateTimeFormat> = {
  "zh-CN": new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }),
  en: new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }),
}

export function formatDateTime(
  epochSeconds: number,
  locale: Locale = getCurrentLocale()
): string {
  const formatted = fullDateFormatters[locale].format(new Date(epochSeconds * 1000))
  return locale === "zh-CN" ? formatted.replace(/\//g, "-") : formatted
}

export function formatShortTime(
  epochSeconds: number,
  locale: Locale = getCurrentLocale()
): string {
  const formatted = shortDateFormatters[locale].format(new Date(epochSeconds * 1000))
  return locale === "zh-CN" ? formatted.replace(/\//g, "-") : formatted
}

export function formatRelativeTime(
  epochSeconds: number,
  locale: Locale = getCurrentLocale()
): string {
  const diffSecs = Math.round(Date.now() / 1000 - epochSeconds)
  if (diffSecs < 0) {
    const ahead = Math.abs(diffSecs)
    if (ahead < 60) return translate(locale, "time.inSecs", { n: ahead })
    if (ahead < 3600)
      return translate(locale, "time.inMins", { n: Math.floor(ahead / 60) })
    if (ahead < 86400)
      return translate(locale, "time.inHours", { n: Math.floor(ahead / 3600) })
    return translate(locale, "time.inDays", { n: Math.floor(ahead / 86400) })
  }
  if (diffSecs < 10) return translate(locale, "time.justNow")
  if (diffSecs < 60) return translate(locale, "time.secsAgo", { n: diffSecs })
  if (diffSecs < 3600)
    return translate(locale, "time.minsAgo", { n: Math.floor(diffSecs / 60) })
  if (diffSecs < 86400)
    return translate(locale, "time.hoursAgo", {
      n: Math.floor(diffSecs / 3600),
    })
  return translate(locale, "time.daysAgo", {
    n: Math.floor(diffSecs / 86400),
  })
}

export function formatLatency(ms: number): string {
  if (ms < 1) return "<1 ms"
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`
  return `${ms} ms`
}

export function maskSecretValue(value: string): string {
  if (value.length <= 12) return "••••••••"
  return `${value.slice(0, 8)}••••${value.slice(-4)}`
}

export function getInitials(displayName: string, email: string): string {
  const source = (displayName || email || "U").trim()
  const parts = source.split(/\s+/).filter(Boolean)
  if (parts.length >= 2) {
    return `${Array.from(parts[0])[0] ?? ""}${Array.from(parts[1])[0] ?? ""}`.toUpperCase()
  }
  return Array.from(source).slice(0, 2).join("").toUpperCase()
}

function escapeCsvCell(value: string | number | null | undefined): string {
  const text = value === null || value === undefined ? "" : String(value)
  const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text
  if (/[",\n\r]/.test(safe)) {
    return `"${safe.replace(/"/g, '""')}"`
  }
  return safe
}

function triggerDownload(filename: string, content: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function exportAuditAsCsv(events: AuditEntry[]) {
  const headers = [
    "id",
    "occurred_at",
    "decision",
    "http_method",
    "target_host",
    "target_port",
    "http_path",
    "status_code",
    "latency_ms",
    "user_email",
    "profile_name",
    "route_tier",
    "client_ip",
    "session_id",
    "deny_reason",
  ]
  const rows = events.map((e) =>
    [
      e.id,
      formatDateTime(e.occurred_at),
      e.decision,
      e.http_method ?? "TCP",
      e.target_host,
      e.target_port,
      e.http_path ?? "",
      e.status_code ?? "",
      e.latency_ms,
      e.user_email,
      e.profile_name,
      e.route_tier,
      e.client_ip,
      e.session_id,
      e.deny_reason ?? "",
    ]
      .map(escapeCsvCell)
      .join(",")
  )
  const timestamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")
  triggerDownload(
    `cx-audit-${timestamp}.csv`,
    `\uFEFF${[headers.join(","), ...rows].join("\n")}\n`,
    "text/csv;charset=utf-8"
  )
}

export function exportAuditAsJson(events: AuditEntry[]) {
  const timestamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")
  triggerDownload(
    `cx-audit-${timestamp}.json`,
    `${JSON.stringify(events, null, 2)}\n`,
    "application/json;charset=utf-8"
  )
}
