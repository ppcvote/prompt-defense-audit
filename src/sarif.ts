/**
 * SARIF 2.1.0 emitter — envelope-conformant output for prompt-defense-audit
 *
 * Wraps the existing scanOutput() / auditWithDetails() results into SARIF 2.1.0
 * so findings interoperate with GitHub code scanning, ATR, and any SARIF
 * consumer. Aligns with the envelope RFC discussed in
 * aliksir/claude-code-skill-security-check#24:
 *
 *   - Rule IDs use the DRAFT-<scanner>-<slug> convention (DRAFT-pda-<id>) with a
 *     tracking-issue URL carried in reportingDescriptor.properties until the ATR
 *     PR-to-ID process assigns a canonical id. Tracked in
 *     ppcvote/prompt-defense-audit#1.
 *   - Each scanned artifact carries hashes["sha-256"] (64-char lowercase hex) so
 *     the same file dedups across scans (OQ1 agreement).
 *   - invocations[].executionSuccessful is always present; a failed scan emits
 *     toolExecutionNotifications[] with the stderr excerpt.
 *   - Taxonomy binding (result.taxa[] / run.taxonomies[]) is MAY in v1 and is
 *     intentionally not emitted yet.
 *
 * Pure, deterministic, zero npm dependencies (node:crypto is a builtin).
 */

import { createHash } from 'node:crypto'
import type { OutputScanResult, OutputThreat } from './output-scanner.js'
import type { AuditDetailedResult } from './types.js'

const TOOL_NAME = 'prompt-defense-audit'
const TOOL_URI = 'https://github.com/ppcvote/prompt-defense-audit'
const TRACKING_ISSUE = 'https://github.com/ppcvote/prompt-defense-audit/issues/1'
const DRAFT_PREFIX = 'DRAFT-pda-'

/** SARIF result level. */
export type SarifLevel = 'error' | 'warning' | 'note' | 'none'

/** Minimal SARIF 2.1.0 shapes — only the members this emitter produces. */
export interface SarifRegion {
  startLine?: number
  startColumn?: number
  endLine?: number
  endColumn?: number
  charOffset?: number
  charLength?: number
  snippet?: { text: string }
}

export interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string; index?: number }
    region?: SarifRegion
  }
}

export interface SarifReportingDescriptor {
  id: string
  name?: string
  shortDescription?: { text: string }
  fullDescription?: { text: string }
  defaultConfiguration?: { level: SarifLevel }
  properties?: Record<string, unknown>
}

export interface SarifResult {
  ruleId: string
  ruleIndex?: number
  level: SarifLevel
  message: { text: string }
  locations?: SarifLocation[]
  properties?: Record<string, unknown>
}

export interface SarifArtifact {
  location: { uri: string }
  hashes: { 'sha-256': string }
}

export interface SarifNotification {
  level: SarifLevel
  message: { text: string }
  properties?: { standardError?: string }
}

export interface SarifInvocation {
  executionSuccessful: boolean
  startTimeUtc?: string
  endTimeUtc?: string
  toolExecutionNotifications?: SarifNotification[]
}

export interface SarifRun {
  tool: {
    driver: {
      name: string
      version: string
      informationUri: string
      rules: SarifReportingDescriptor[]
    }
  }
  /**
   * Offsets and columns here are counted in UTF-16 code units (JS string
   * indices). Declaring columnKind makes that explicit so consumers do not
   * assume the SARIF default (unicodeCodePoints) and mislocate regions on
   * non-BMP input (emoji, CJK ext-B, …).
   */
  columnKind: 'utf16CodeUnits'
  invocations: SarifInvocation[]
  artifacts: SarifArtifact[]
  results: SarifResult[]
}

export interface SarifLog {
  $schema: string
  version: '2.1.0'
  runs: SarifRun[]
}

/** Options common to both emitters. */
export interface SarifEmitOptions {
  /** The exact text that was scanned (used to compute the artifact digest). */
  scannedText: string
  /** Logical URI for the scanned artifact. Defaults per emitter. */
  artifactUri?: string
  /** Tool version to report (defaults to the running package version if omitted). */
  toolVersion?: string
  /** ISO-8601 UTC start time (SHOULD). */
  startTimeUtc?: string
  /** ISO-8601 UTC end time (SHOULD). */
  endTimeUtc?: string
  /** Whether the scan completed. Defaults to true. */
  executionSuccessful?: boolean
  /** On failure, the error to surface in toolExecutionNotifications. */
  error?: { message: string; standardError?: string }
}

const SARIF_SCHEMA_URI =
  'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json'

/**
 * Rules whose match text is itself a live secret. Their matched span is located
 * (charOffset/charLength) but never reproduced in snippet.text, so a SARIF file
 * uploaded to code scanning or committed on a public repo does not republish the
 * very secret it flagged.
 */
function isSecretRule(id: string): boolean {
  return id.startsWith('credential-')
}

/** OutputThreat.severity -> SARIF level. critical/high are actionable errors. */
const SEVERITY_LEVEL: Record<OutputThreat['severity'], SarifLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
}

/** OutputThreat.severity -> GitHub code-scanning security-severity score. */
const SEVERITY_SCORE: Record<OutputThreat['severity'], string> = {
  critical: '9.0',
  high: '7.0',
  medium: '5.0',
  low: '3.0',
}

/** SHA-256 of the UTF-8 bytes of `text`, as 64-char lowercase hex. */
export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

/** Namespaced DRAFT rule id for a scanner-native rule slug. */
export function draftRuleId(slug: string): string {
  return `${DRAFT_PREFIX}${slug}`
}

/** 1-based line/column for a character offset into `text`. */
function lineColumn(text: string, offset: number): { line: number; column: number } {
  const clamped = Math.max(0, Math.min(offset, text.length))
  let line = 1
  let lastNewline = -1
  for (let i = 0; i < clamped; i++) {
    if (text.charCodeAt(i) === 10 /* \n */) {
      line++
      lastNewline = i
    }
  }
  return { line, column: clamped - lastNewline }
}

function invocation(opts: SarifEmitOptions): SarifInvocation {
  const successful = opts.executionSuccessful ?? true
  const inv: SarifInvocation = { executionSuccessful: successful }
  if (opts.startTimeUtc) inv.startTimeUtc = opts.startTimeUtc
  if (opts.endTimeUtc) inv.endTimeUtc = opts.endTimeUtc
  if (!successful && opts.error) {
    const note: SarifNotification = {
      level: 'error',
      message: { text: opts.error.message },
    }
    if (opts.error.standardError) {
      note.properties = { standardError: opts.error.standardError }
    }
    inv.toolExecutionNotifications = [note]
  }
  return inv
}

function driver(rules: SarifReportingDescriptor[], version: string) {
  return {
    name: TOOL_NAME,
    version,
    informationUri: TOOL_URI,
    rules,
  }
}

/**
 * Emit SARIF for an output scan (OWASP LLM02 — insecure output handling).
 *
 * Each OutputThreat becomes one result anchored to its region in the artifact.
 * Only rules that actually fired are included in tool.driver.rules, so the
 * per-artifact hash + region set is the finding identity.
 */
export function outputScanToSarif(
  scan: OutputScanResult,
  opts: SarifEmitOptions,
): SarifLog {
  const uri = opts.artifactUri ?? 'output.txt'
  const version = opts.toolVersion ?? '0.0.0'
  const text = opts.scannedText

  // One reportingDescriptor per distinct rule that fired, in first-seen order.
  const ruleIndexById = new Map<string, number>()
  const rules: SarifReportingDescriptor[] = []
  for (const t of scan.threats) {
    const id = draftRuleId(t.id)
    if (ruleIndexById.has(id)) continue
    ruleIndexById.set(id, rules.length)
    rules.push({
      id,
      name: t.name.replace(/[^A-Za-z0-9]/g, ''),
      shortDescription: { text: t.name },
      defaultConfiguration: { level: SEVERITY_LEVEL[t.severity] },
      properties: {
        'draft-id': id,
        'tracking-issue': TRACKING_ISSUE,
        'security-severity': SEVERITY_SCORE[t.severity],
      },
    })
  }

  const results: SarifResult[] = scan.threats.map((t) => {
    const id = draftRuleId(t.id)
    // NOTE: the scanner display-caps `match` at 100 chars, so for a payload
    // longer than 100 chars the region and snippet cover only the first 100.
    // The result stays internally consistent (snippet === text[charOffset ..
    // charOffset + charLength]); widening to the full match extent is a tracked
    // follow-up (see ppcvote/prompt-defense-audit#1).
    const start = lineColumn(text, t.position)
    const end = lineColumn(text, t.position + t.match.length)
    const region: SarifRegion = {
      startLine: start.line,
      startColumn: start.column,
      endLine: end.line,
      endColumn: end.column,
      charOffset: t.position,
      charLength: t.match.length,
    }
    // Locate secrets precisely but never reproduce their bytes.
    if (!isSecretRule(t.id)) {
      region.snippet = { text: t.match }
    }
    return {
      ruleId: id,
      ruleIndex: ruleIndexById.get(id),
      level: SEVERITY_LEVEL[t.severity],
      message: { text: `${t.name}: dangerous payload in model output` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri, index: 0 },
            region,
          },
        },
      ],
    }
  })

  return {
    $schema: SARIF_SCHEMA_URI,
    version: '2.1.0',
    runs: [
      {
        tool: { driver: driver(rules, version) },
        columnKind: 'utf16CodeUnits',
        invocations: [invocation(opts)],
        artifacts: [{ location: { uri }, hashes: { 'sha-256': sha256Hex(text) } }],
        results,
      },
    ],
  }
}

/**
 * Emit SARIF for a system-prompt defense audit.
 *
 * A missing defense is an *absence*, not a payload at a location, so each
 * missing vector becomes a note-level result with no physical region. Per the
 * #24 OQ1 resolution, results without a file-level artifactLocation are not
 * subject to the digest requirement — but we still emit one artifact for the
 * prompt itself so the run has a stable, hashable subject.
 */
export function auditToSarif(
  audit: AuditDetailedResult,
  opts: SarifEmitOptions,
): SarifLog {
  const uri = opts.artifactUri ?? 'system-prompt.txt'
  const version = opts.toolVersion ?? '0.0.0'
  const text = opts.scannedText

  const missingChecks = audit.checks.filter((c) => !c.defended)

  const rules: SarifReportingDescriptor[] = missingChecks.map((c) => {
    const id = draftRuleId(`missing-${c.id}`)
    return {
      id,
      name: c.name.replace(/[^A-Za-z0-9]/g, ''),
      shortDescription: { text: `Missing defense: ${c.name}` },
      fullDescription: { text: c.evidence },
      defaultConfiguration: { level: 'note' },
      properties: {
        'draft-id': id,
        'tracking-issue': TRACKING_ISSUE,
      },
    }
  })

  const results: SarifResult[] = missingChecks.map((c, i) => ({
    ruleId: draftRuleId(`missing-${c.id}`),
    ruleIndex: i,
    level: 'note',
    message: { text: `No defense detected against ${c.name}` },
  }))

  return {
    $schema: SARIF_SCHEMA_URI,
    version: '2.1.0',
    runs: [
      {
        tool: { driver: driver(rules, version) },
        columnKind: 'utf16CodeUnits',
        invocations: [invocation(opts)],
        artifacts: [{ location: { uri }, hashes: { 'sha-256': sha256Hex(text) } }],
        results,
      },
    ],
  }
}
