/**
 * Batch scan — audit multiple system prompts and output a summary table.
 *
 * Usage:
 *   npx tsx examples/batch-scan.ts prompts/*.txt
 *   npx tsx examples/batch-scan.ts --json prompts/*.txt
 */

import { readFileSync } from 'fs'
import { basename } from 'path'
import { audit } from 'prompt-defense-audit'

const args = process.argv.slice(2)
const jsonMode = args.includes('--json')
const files = args.filter((a) => !a.startsWith('--'))

if (files.length === 0) {
  console.error('Usage: npx tsx examples/batch-scan.ts [--json] <file1> <file2> ...')
  process.exit(1)
}

interface ScanRow {
  file: string
  grade: string
  score: number
  defended: number
  missing: string[]
}

const results: ScanRow[] = []

for (const file of files) {
  try {
    const prompt = readFileSync(file, 'utf8')
    const r = audit(prompt)
    results.push({
      file: basename(file),
      grade: r.grade,
      score: r.score,
      defended: r.defended,
      missing: r.missing,
    })
  } catch (e: any) {
    console.error(`Error reading ${file}: ${e.message}`)
  }
}

if (jsonMode) {
  console.log(JSON.stringify(results, null, 2))
} else {
  // Table output
  console.log('')
  console.log('File'.padEnd(30) + 'Grade  Score  Defended  Missing')
  console.log('-'.repeat(75))
  for (const r of results) {
    console.log(
      r.file.padEnd(30) +
        r.grade.padEnd(7) +
        String(r.score).padEnd(7) +
        `${r.defended}/12`.padEnd(10) +
        r.missing.slice(0, 3).join(', ') +
        (r.missing.length > 3 ? ` +${r.missing.length - 3} more` : ''),
    )
  }
  console.log('')

  // Summary
  const avg = Math.round(results.reduce((s, r) => s + r.score, 0) / results.length)
  const gradeF = results.filter((r) => r.grade === 'F').length
  console.log(`Scanned: ${results.length} prompts | Average score: ${avg}/100 | Grade F: ${gradeF}`)
  console.log('')
}
