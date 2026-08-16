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
 *     the same file dedups across scans (OQ1 agreement). Per the adopted §2
 *     wording (2026-07-20), the digest is computed over the artifact's RAW
 *     OCTETS, before any character decoding — for a file this MUST equal
 *     `sha256sum` of that file. Callers that read an artifact from disk or a
 *     stream pass the original bytes via artifactBytes; hashing a decoded,
 *     normalized, or trimmed string representation is a spec violation.
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

/**
 * Where each scan mode documents how its results should be read, and in
 * particular what a clean run does and does not claim.
 *
 * Why this is a run-level pointer rather than rule-level `helpUri`/`help`:
 * only rules that actually fired appear in `tool.driver.rules`, so a clean run
 * carries zero rule objects. A caveat attached to a rule is therefore absent
 * from exactly the report that needs it most — the one with no findings, which
 * a consumer is most likely to read as an all-clear.
 *
 * Why not `tool.driver.informationUri`: that is defined as information about
 * the tool (SARIF 2.1.0 §3.19.3) and consumers commonly render it as a project
 * homepage link. Pointing it at a caveat section would make it mean something
 * narrower than the spec says, and would lose the homepage it currently gives.
 *
 * Anchors verified against GitHub's rendered README rather than derived from
 * the heading text, since the slug rules are not obvious ("Output scanning
 * (`--output`)" renders as `output-scanning---output`).
 */
const INTERPRETATION_ANCHOR = {
  output: 'output-scanning---output',
  audit: 'what-this-scanner-does-not-catch',
} as const

/**
 * Build the pointer, pinned to the release that produced the run.
 *
 * Pinning is the point. A SARIF file outlives the version that wrote it, and a
 * consumer reading a two-year-old artifact needs the caveat as it stood for
 * *that* version, not as it reads on the default branch today. An unpinned
 * pointer silently re-targets every time the README changes, which turns a
 * durable reference into a live one and defeats the reason for carrying it.
 *
 * Returns undefined when the version is not a release version (the `0.0.0`
 * sentinel used when package.json cannot be read, or a prerelease), and the
 * callers omit the field. This used to fall back to `master`, reasoning that a
 * dangling tag link would be worse — a false dichotomy: the alternative to a
 * mutable pointer is no pointer at all. An absent reference is honest about
 * what the build can promise; a `master` reference silently re-targets on
 * every push.
 *
 * Whether the field is emitted depends only on the version baked into the
 * running build, never on the outcome of a run, so presence cannot leak result
 * state: every artifact from one binary either carries it or none do.
 */
function interpretationUri(
  mode: keyof typeof INTERPRETATION_ANCHOR,
  version: string,
): string | undefined {
  if (!/^\d+\.\d+\.\d+$/.test(version) || version === '0.0.0') return undefined
  return `${TOOL_URI}/blob/v${version}/README.md#${INTERPRETATION_ANCHOR[mode]}`
}

/**
 * `{ interpretationUri }` when the build can pin one, otherwise undefined,
 * which spreads as a no-op so the key is omitted rather than set to undefined.
 */
function pointerProps(
  mode: keyof typeof INTERPRETATION_ANCHOR,
  version: string,
): { interpretationUri: string } | undefined {
  const uri = interpretationUri(mode, version)
  return uri === undefined ? undefined : { interpretationUri: uri }
}

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
  properties?: {
    standardError?: string
    /**
     * How many items this run held back. The bound it was measured against is
     * declared once at run level as `run.properties.appliedCap`, not repeated
     * here: the count is an event specific to this run, the cap is
     * configuration. Split per envelope v1
     * (aliksir/claude-code-skill-security-check#24); the pairing rationale
     * came out of OWASP/www-project-agentic-skills-top-10#49, where a count
     * without its bound could not distinguish 1-of-2 from 1-of-2000.
     */
    droppedCount?: number
  }
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
  /**
   * Run-level configuration. `appliedCap` lives here rather than in the
   * notification because it is a property of how the run was configured, true
   * whether or not the bound ever bit — per the split adopted for envelope v1
   * (aliksir/claude-code-skill-security-check#24, 2026-08-05).
   *
   * Declaring it unconditionally is what makes silence meaningful: a run with
   * no cap declared and no notification says "this emitter bounds nothing",
   * which is a different claim from "a bound exists and did not fire today".
   * Carrying both keys only in the notification would collapse those two.
   *
   * `interpretationUri` points at where this tool states how its results
   * should be read — specifically, that a clean scan is a lower bound rather
   * than a coverage claim. It is a pointer, not a declaration: it asserts
   * nothing about coverage, so unlike a completeness field it cannot misstate
   * coverage. See the note on SNIPPET_MAX_CHARS' sibling constant below for
   * why this cannot live on a rule.
   *
   * The spelling is this emitter's choice and is not a ratified key. The
   * behaviour being demonstrated is that the pointer travels with the run;
   * rename it freely if the RFC settles on something else.
   */
  properties?: { appliedCap?: number; interpretationUri?: string }
}

export interface SarifLog {
  $schema: string
  version: '2.1.0'
  runs: SarifRun[]
}

/** Options common to both emitters. */
export interface SarifEmitOptions {
  /**
   * The exact text that was scanned. Used for region offsets, and as the
   * digest subject only when the artifact is a true in-memory string (no
   * artifactBytes) — a string's canonical octets are its UTF-8 encoding.
   */
  scannedText: string
  /**
   * The raw octets of the scanned artifact, exactly as stored. REQUIRED
   * whenever the artifact originates from a file or stream: the envelope
   * digest (§2, adopted 2026-07-20) is SHA-256 over these bytes, before any
   * character decoding, and must equal `sha256sum` of the artifact. When
   * omitted, the digest falls back to the UTF-8 encoding of scannedText —
   * correct only for artifacts that never existed as bytes outside this
   * process. Decode-then-hash is many-to-one on invalid UTF-8 (every invalid
   * sequence collapses to U+FFFD), so passing decoded file content here via
   * scannedText alone would let two different files share one digest.
   */
  artifactBytes?: Uint8Array
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
 * Upper bound on a reproduced snippet, in characters.
 *
 * A pathological match (a multi-megabyte base64 blob, say) would otherwise
 * inline the whole payload into every consumer's report. Above this bound the
 * snippet is omitted entirely rather than shortened: a snippet that covers
 * less than its own region is an incomplete answer wearing the shape of a
 * complete one, and the region already tells a consumer exactly which bytes to
 * read from the artifact. The omission is declared in
 * invocations[].toolExecutionNotifications.
 */
export const SNIPPET_MAX_CHARS = 4096

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

/**
 * SHA-256 as 64-char lowercase hex.
 *
 * Pass the artifact's raw octets (Uint8Array) whenever they exist — the result
 * then equals `sha256sum` of the artifact, per the envelope's raw-octets basis.
 * A string input is hashed over its UTF-8 encoding, which is the canonical
 * octet form of an in-memory string; for well-formed UTF-8 the two paths are
 * byte-identical, and they intentionally diverge on invalid input (where
 * decoding has already destroyed information via U+FFFD substitution).
 */
export function sha256Hex(data: string | Uint8Array): string {
  const hash = createHash('sha256')
  if (typeof data === 'string') hash.update(data, 'utf8')
  else hash.update(data)
  return hash.digest('hex')
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

function invocation(
  opts: SarifEmitOptions,
  snippetsOmitted = 0,
): SarifInvocation {
  const successful = opts.executionSuccessful ?? true
  const inv: SarifInvocation = { executionSuccessful: successful }
  if (opts.startTimeUtc) inv.startTimeUtc = opts.startTimeUtc
  if (opts.endTimeUtc) inv.endTimeUtc = opts.endTimeUtc
  const notes: SarifNotification[] = []
  if (!successful && opts.error) {
    const note: SarifNotification = {
      level: 'error',
      message: { text: opts.error.message },
    }
    if (opts.error.standardError) {
      note.properties = { standardError: opts.error.standardError }
    }
    notes.push(note)
  }
  if (snippetsOmitted > 0) {
    // executionSuccessful stays true: the analysis did complete, and every
    // finding is present with a correct region. What is bounded is only how
    // much matched text the report reproduces, and that bound is declared
    // here rather than left for a consumer to infer from a missing field.
    notes.push({
      level: 'warning',
      message: {
        text:
          `${snippetsOmitted} result snippet(s) omitted: the matched span ` +
          `exceeds the ${SNIPPET_MAX_CHARS}-character snippet cap. Regions ` +
          `still describe the full matched extent — resolve charOffset and ` +
          `charLength against the artifact to read the payload in full.`,
      },
      properties: {
        droppedCount: snippetsOmitted,
      },
    })
  }
  if (notes.length > 0) inv.toolExecutionNotifications = notes
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
 * Emit SARIF for an output scan (OWASP LLM05:2025 improper output handling).
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
  const digestSubject = opts.artifactBytes ?? text

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

  // Snippets omitted because the matched span exceeds SNIPPET_MAX_CHARS. The
  // region still describes the full extent; only the reproduced text is held
  // back, and the count is declared in toolExecutionNotifications below.
  let snippetsOmittedForLength = 0

  const results: SarifResult[] = scan.threats.map((t) => {
    const id = draftRuleId(t.id)
    // The region describes the FULL matched span (t.matchLength), not the
    // display-capped `t.match`. Using the capped length here would report a
    // 500-character payload as a 100-character one, and a consumer resolving
    // charOffset+charLength against the artifact would silently read back a
    // truncated span.
    const start = lineColumn(text, t.position)
    const end = lineColumn(text, t.position + t.matchLength)
    const region: SarifRegion = {
      startLine: start.line,
      startColumn: start.column,
      endLine: end.line,
      endColumn: end.column,
      charOffset: t.position,
      charLength: t.matchLength,
    }
    // Locate secrets precisely but never reproduce their bytes.
    if (!isSecretRule(t.id)) {
      // Reconstruct the whole match from the scanned text rather than emitting
      // the display-capped copy: a snippet that covers less than its region is
      // an incomplete answer that looks like a complete one. Verify the
      // reconstruction against the capped prefix before trusting it, in case a
      // caller passed scannedText that is not what the scan actually ran on.
      const full = text.slice(t.position, t.position + t.matchLength)
      const trustworthy = full.startsWith(t.match)
      if (!trustworthy) {
        // Fall back to the capped text and keep the region honest by narrowing
        // it to what we can actually vouch for.
        region.charLength = t.match.length
        region.endLine = lineColumn(text, t.position + t.match.length).line
        region.endColumn = lineColumn(text, t.position + t.match.length).column
        region.snippet = { text: t.match }
      } else if (t.matchLength <= SNIPPET_MAX_CHARS) {
        region.snippet = { text: full }
      } else {
        snippetsOmittedForLength++
      }
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
        invocations: [invocation(opts, snippetsOmittedForLength)],
        artifacts: [
          { location: { uri }, hashes: { 'sha-256': sha256Hex(digestSubject) } },
        ],
        results,
        // Declared on every run, fired or not: a consumer must be able to tell
        // "this emitter bounds snippet text at 4096" from "this emitter bounds
        // nothing", and absence of a notification alone cannot say which.
        // The interpretation pointer is spread so an unpinnable build omits
        // the key rather than emitting a mutable reference.
        properties: {
          appliedCap: SNIPPET_MAX_CHARS,
          ...pointerProps('output', version),
        },
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
  const digestSubject = opts.artifactBytes ?? text

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

  // No appliedCap here: the prompt audit reproduces no matched text, so it
  // has no snippet bound to declare. The interpretation pointer still applies
  // — a grade is presence of defensive language, not proof that any of it is
  // enforced, and the linked section says so. An unpinnable build omits
  // `properties` entirely rather than carrying a mutable reference.
  const pointer = pointerProps('audit', version)
  return {
    $schema: SARIF_SCHEMA_URI,
    version: '2.1.0',
    runs: [
      {
        tool: { driver: driver(rules, version) },
        columnKind: 'utf16CodeUnits',
        invocations: [invocation(opts)],
        artifacts: [
          { location: { uri }, hashes: { 'sha-256': sha256Hex(digestSubject) } },
        ],
        results,
        ...(pointer && { properties: pointer }),
      },
    ],
  }
}
