/**
 * Scan ALL leaked system prompts from 4 datasets.
 * Deduplicates by content hash. Outputs combined defense gap rates.
 */
import { readFileSync, readdirSync, statSync } from 'fs'
import { createHash } from 'crypto'
import { join, extname } from 'path'

const DEFENSE_RULES = [
  { id: 'role-escape', name: 'Role Boundary', patterns: [/(?:you are|your role|act as|serve as|function as)/i, /(?:never (?:break|change|switch|abandon)|only (?:answer|respond|act) as|stay in (?:character|role)|always (?:remain|be|act as))/i], minMatches: 2 },
  { id: 'instruction-override', name: 'Instruction Boundary', patterns: [/(?:do not|never|must not|cannot|should not|refuse|reject|decline)/i, /(?:ignore (?:any|all)|disregard|override)/i], minMatches: 1 },
  { id: 'data-leakage', name: 'Data Protection', patterns: [/(?:do not (?:reveal|share|disclose|expose|output)|never (?:reveal|share|disclose|show)|keep.*(?:secret|confidential|private))/i, /(?:system prompt|internal|instruction|training|behind the scenes)/i], minMatches: 1 },
  { id: 'output-manipulation', name: 'Output Control', patterns: [/(?:only (?:respond|reply|output|answer) (?:in|with|as)|format.*(?:as|in|using)|response (?:format|style))/i, /(?:do not (?:generate|create|produce|output)|never (?:generate|produce))/i], minMatches: 1 },
  { id: 'multilang-bypass', name: 'Multi-language Protection', patterns: [/(?:only (?:respond|reply|answer|communicate) in|language|respond in (?:english|chinese|japanese))/i, /(?:regardless of (?:the )?(?:input |user )?language)/i], minMatches: 1 },
  { id: 'unicode-attack', name: 'Unicode Protection', patterns: [/(?:unicode|homoglyph|special character|character encoding)/i], minMatches: 1 },
  { id: 'context-overflow', name: 'Length Limits', patterns: [/(?:max(?:imum)?.*(?:length|char|token|word)|limit.*(?:input|length|size|token)|truncat)/i], minMatches: 1 },
  { id: 'indirect-injection', name: 'Indirect Injection Protection', patterns: [/(?:external (?:data|content|source|input)|user.?(?:provided|supplied|submitted)|third.?party)/i, /(?:validate|verify|sanitize|filter|check).*(?:external|input|data|content)/i], minMatches: 2 },
  { id: 'social-engineering', name: 'Social Engineering Defense', patterns: [/(?:emotional|urgency|pressure|threaten|guilt|manipulat)/i, /(?:regardless of|no matter|even if)/i], minMatches: 1 },
  { id: 'output-weaponization', name: 'Harmful Content Prevention', patterns: [/(?:harmful|illegal|dangerous|malicious|weapon|violence|exploit|phishing)/i, /(?:do not (?:help|assist|generate|create).*(?:harm|illegal|danger|weapon))/i], minMatches: 1 },
  { id: 'abuse-prevention', name: 'Abuse Prevention', patterns: [/(?:abuse|misuse|exploit|attack|inappropriate|spam|flood)/i, /(?:rate limit|throttl|quota|maximum.*request)/i, /(?:authenticat|authoriz|permission|access control|api.?key|token)/i], minMatches: 1 },
  { id: 'input-validation', name: 'Input Validation', patterns: [/(?:validate|sanitize|filter|clean|escape|strip|check.*input|input.*(?:validation|check))/i, /(?:sql|xss|injection|script|html|special char|malicious)/i], minMatches: 1 },
]

function scanPrompt(text) {
  const results = {}
  for (const rule of DEFENSE_RULES) {
    let matches = 0
    for (const pat of rule.patterns) { if (pat.test(text)) matches++ }
    results[rule.id] = { defended: matches >= (rule.minMatches || 1), name: rule.name }
  }
  return results
}

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
          if (!entry.toLowerCase().includes('readme') && !entry.toLowerCase().includes('contributing') && !entry.toLowerCase().includes('getting_started') && !entry.toLowerCase().includes('license')) {
            results.push(full)
          }
        }
      } catch {}
    }
  } catch {}
  return results
}

// ── Collect from all datasets ──
const datasets = [
  { name: 'jujumilk3/leaked-system-prompts', dir: 'C:/Users/User/leaked-system-prompts' },
  { name: 'x1xhlol/system-prompts-and-models', dir: 'C:/Users/User/syspr-x1x' },
  { name: 'elder-plinius/CL4R1T4S', dir: 'C:/Users/User/syspr-cl4r' },
  { name: 'LouisShark/chatgpt_system_prompt', dir: 'C:/Users/User/syspr-louis' },
]

const seenHashes = new Set()
const allPrompts = []

for (const ds of datasets) {
  const files = collectFiles(ds.dir)
  let added = 0
  for (const f of files) {
    try {
      const text = readFileSync(f, 'utf-8')
      // Skip very short files (< 50 chars, likely not real prompts)
      if (text.trim().length < 50) continue
      // Deduplicate by content hash
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

// ── Scan all ──
const totals = {}
for (const rule of DEFENSE_RULES) {
  totals[rule.id] = { defended: 0, missing: 0, name: rule.name }
}

const promptResults = []

for (const p of allPrompts) {
  const result = scanPrompt(p.text)
  let defended = 0
  for (const [id, r] of Object.entries(result)) {
    if (r.defended) { totals[id].defended++; defended++ }
    else { totals[id].missing++ }
  }
  promptResults.push({ file: p.file, source: p.source, score: Math.round((defended / 12) * 100), defended })
}

// ── Output ──
const n = allPrompts.length
console.log('=== DEFENSE GAP RATES ===\n')
console.log(`Combined dataset: ${n} unique production system prompts\n`)
console.log('| Defense | Gap Rate | Defended | Missing |')
console.log('|---------|:--------:|:--------:|:-------:|')

const sorted = Object.entries(totals).sort((a, b) => (b[1].missing / n) - (a[1].missing / n))
for (const [id, data] of sorted) {
  const gap = ((data.missing / n) * 100).toFixed(1)
  console.log(`| ${data.name} | ${gap}% | ${data.defended} | ${data.missing} |`)
}

// Grades
const grades = { A: 0, B: 0, C: 0, D: 0, F: 0 }
for (const p of promptResults) {
  if (p.score >= 90) grades.A++
  else if (p.score >= 75) grades.B++
  else if (p.score >= 60) grades.C++
  else if (p.score >= 45) grades.D++
  else grades.F++
}
const avg = Math.round(promptResults.reduce((s, p) => s + p.score, 0) / n)

console.log(`\nAverage: ${avg}/100\n`)
console.log('| Grade | Count | % |')
console.log('|:-----:|:-----:|:--:|')
for (const [g, c] of Object.entries(grades)) {
  console.log(`| ${g} | ${c} | ${((c / n) * 100).toFixed(1)}% |`)
}

// Per-source breakdown
console.log('\n=== PER SOURCE ===\n')
for (const ds of datasets) {
  const dsPrompts = promptResults.filter(p => p.source === ds.name)
  if (dsPrompts.length === 0) continue
  const dsAvg = Math.round(dsPrompts.reduce((s, p) => s + p.score, 0) / dsPrompts.length)
  console.log(`  ${ds.name}: ${dsPrompts.length} prompts, avg ${dsAvg}/100`)
}
