#!/usr/bin/env node
/**
 * v1.4.0 Empirical Gap Rate Analysis
 *
 * Runs the 17-vector scanner against the same 4 leaked-prompt datasets used
 * in the v1.3 research (jujumilk3, x1xhlol, elder-plinius/CL4R1T4S, LouisShark).
 *
 * Reports per-vector gap rate. Especially important for the 5 NEW vectors —
 * we want to see how often production prompts already defend against them.
 *
 * Usage: node research/v14-empirical-gap-rates.mjs
 */

import { readFileSync, readdirSync, statSync, writeFileSync } from 'fs'
import { createHash } from 'crypto'
import { join, extname } from 'path'
import { audit, auditWithDetails, ATTACK_VECTORS } from '../dist/index.js'

function collectFiles(dir, exts = ['.md', '.txt']) {
  const results = []
  try {
    const entries = readdirSync(dir)
    for (const entry of entries) {
      if (entry.startsWith('.') || entry === 'node_modules') continue
      const full = join(dir, entry)
      try {
        const stat = statSync(full)
        if (stat.isDirectory()) {
          results.push(...collectFiles(full, exts))
        } else if (exts.includes(extname(entry).toLowerCase())) {
          if (
            !entry.toLowerCase().includes('readme') &&
            !entry.toLowerCase().includes('contributing') &&
            !entry.toLowerCase().includes('getting_started') &&
            !entry.toLowerCase().includes('license')
          ) {
            results.push(full)
          }
        }
      } catch {}
    }
  } catch {}
  return results
}

const datasets = [
  { name: 'jujumilk3/leaked-system-prompts', dir: 'C:/Users/User/leaked-system-prompts' },
  { name: 'x1xhlol/system-prompts-and-models', dir: 'C:/Users/User/syspr-x1x' },
  { name: 'elder-plinius/CL4R1T4S', dir: 'C:/Users/User/syspr-cl4r' },
  { name: 'LouisShark/chatgpt_system_prompt', dir: 'C:/Users/User/syspr-louis' },
]

const seenHashes = new Set()
const allPrompts = []

console.log('=== Collecting production prompts ===\n')
for (const ds of datasets) {
  const files = collectFiles(ds.dir)
  let added = 0
  for (const f of files) {
    try {
      const text = readFileSync(f, 'utf-8')
      if (text.trim().length < 50) continue
      const hash = createHash('md5').update(text.trim()).digest('hex')
      if (seenHashes.has(hash)) continue
      seenHashes.add(hash)
      allPrompts.push({ file: f.replace(/.*[/\\]/, ''), source: ds.name, text })
      added++
    } catch {}
  }
  console.log(`  ${ds.name}: ${files.length} files → ${added} unique prompts`)
}

console.log(`\nTotal unique prompts: ${allPrompts.length}\n`)

// Scan all with the v1.4 scanner
const totals = Object.fromEntries(
  ATTACK_VECTORS.map((v) => [v.id, { defended: 0, missing: 0, name: v.name }]),
)

const NEW_VECTOR_IDS = new Set([
  'encoding-injection',
  'function-immutable',
  'memory-provenance',
  'cross-agent-auth',
  'transaction-guardrails',
])

const grades = { A: 0, B: 0, C: 0, D: 0, F: 0 }
const scoreSum = { total: 0, n: 0 }
const newVectorDefendedSamples = Object.fromEntries(
  [...NEW_VECTOR_IDS].map((id) => [id, []]),
)

for (const p of allPrompts) {
  const r = auditWithDetails(p.text)
  for (const c of r.checks) {
    if (c.defended) {
      totals[c.id].defended++
      // Sample some defended cases for the new vectors to spot-check
      if (NEW_VECTOR_IDS.has(c.id) && newVectorDefendedSamples[c.id].length < 3) {
        newVectorDefendedSamples[c.id].push({ file: p.file, evidence: c.evidence })
      }
    } else {
      totals[c.id].missing++
    }
  }
  grades[r.grade]++
  scoreSum.total += r.score
  scoreSum.n++
}

const n = allPrompts.length

console.log('=== GAP RATES — ALL 17 VECTORS ===\n')
console.log('Sorted by gap rate (highest = least defended).\n')
console.log('| # | Vector | Gap Rate | Defended | Missing | New in v1.4? |')
console.log('|---|--------|---------:|---------:|--------:|:------------:|')

const sorted = Object.entries(totals)
  .map(([id, data]) => ({
    id,
    name: data.name,
    defended: data.defended,
    missing: data.missing,
    gapRate: data.missing / n,
    isNew: NEW_VECTOR_IDS.has(id),
  }))
  .sort((a, b) => b.gapRate - a.gapRate)

let i = 1
for (const v of sorted) {
  const gap = (v.gapRate * 100).toFixed(1)
  const tag = v.isNew ? ' **v1.4** ' : ''
  console.log(`| ${i++} | ${v.name} | ${gap}% | ${v.defended} | ${v.missing} | ${v.isNew ? '✅' : ''} |`)
}

console.log('\n=== GRADE DISTRIBUTION (17-vector scoring) ===\n')
console.log('| Grade | Count | % of dataset |')
console.log('|-------|------:|-------------:|')
for (const g of ['A', 'B', 'C', 'D', 'F']) {
  const pct = ((grades[g] / n) * 100).toFixed(1)
  console.log(`| ${g} | ${grades[g]} | ${pct}% |`)
}
const avg = Math.round(scoreSum.total / scoreSum.n)
console.log(`\nAverage score: ${avg}/100`)

console.log('\n=== NEW VECTORS — WHERE DEFENDED PROMPTS WERE FOUND ===\n')
for (const id of NEW_VECTOR_IDS) {
  const samples = newVectorDefendedSamples[id]
  console.log(`${id}: ${totals[id].defended}/${n} prompts defended`)
  for (const s of samples) {
    console.log(`  ↳ ${s.file}: ${s.evidence}`)
  }
  console.log()
}

// Persist results for future reference
const output = {
  meta: {
    version: '1.4.0',
    scanned_at: new Date().toISOString(),
    total_prompts: n,
    datasets: datasets.map((d) => d.name),
  },
  gap_rates: sorted.map((v) => ({
    id: v.id,
    name: v.name,
    gap_rate_pct: parseFloat((v.gapRate * 100).toFixed(2)),
    defended: v.defended,
    missing: v.missing,
    is_new_in_v14: v.isNew,
  })),
  grade_distribution: grades,
  average_score: avg,
  new_vector_samples: newVectorDefendedSamples,
}

writeFileSync(
  'research/gap-rates-v1.4.json',
  JSON.stringify(output, null, 2),
)
console.log('\nResults saved to research/gap-rates-v1.4.json')
