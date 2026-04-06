#!/usr/bin/env node

/**
 * CLI for prompt-defense-audit
 *
 * Usage:
 *   npx prompt-defense-audit "Your system prompt here"
 *   echo "Your prompt" | npx prompt-defense-audit
 *   npx prompt-defense-audit --file prompt.txt
 *   npx prompt-defense-audit --json "Your prompt"
 *   npx prompt-defense-audit --zh "你的系統提示"
 */

import { readFileSync } from 'fs'
import { auditWithDetails } from './scanner.js'
import { scanOutput } from './output-scanner.js'
import { ATTACK_VECTORS } from './vectors.js'

const args = process.argv.slice(2)

let prompt = ''
let jsonMode = false
let zhMode = false
let fileMode = false
let filePath = ''
let outputMode = false

for (let i = 0; i < args.length; i++) {
  const arg = args[i]
  if (arg === '--output' || arg === '-o') {
    outputMode = true
  } else if (arg === '--json' || arg === '-j') {
    jsonMode = true
  } else if (arg === '--zh' || arg === '--chinese') {
    zhMode = true
  } else if (arg === '--file' || arg === '-f') {
    fileMode = true
    filePath = args[++i] || ''
  } else if (arg === '--help' || arg === '-h') {
    printHelp()
    process.exit(0)
  } else if (arg === '--version' || arg === '-v') {
    try {
      const pkg = JSON.parse(
        readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
      )
      console.log(pkg.version)
    } catch {
      console.log('unknown')
    }
    process.exit(0)
  } else if (arg === '--vectors') {
    printVectors(zhMode)
    process.exit(0)
  } else if (!arg.startsWith('-')) {
    prompt = arg
  }
}

function printHelp() {
  console.log(`
prompt-defense-audit — Scan LLM system prompts and outputs for security issues

Usage:
  prompt-defense-audit "Your system prompt"              Scan prompt for missing defenses
  prompt-defense-audit --output "AI response text"       Scan output for dangerous payloads
  prompt-defense-audit --file prompt.txt
  echo "Your prompt" | prompt-defense-audit
  prompt-defense-audit --json "Your prompt"

Options:
  --output, -o        Scan AI output for XSS/SQLi/shell/credential threats (OWASP LLM02)
  --file, -f <path>   Read text from file
  --json, -j          Output as JSON
  --zh, --chinese     Output in Traditional Chinese
  --vectors           List all 12 attack vectors
  --version, -v       Show version
  --help, -h          Show this help

Examples:
  prompt-defense-audit "You are a helpful assistant."
  prompt-defense-audit --output "<script>alert(1)</script>"
  prompt-defense-audit --file my-chatbot-prompt.txt --json
`)
}

function printVectors(zh: boolean) {
  console.log(zh ? '\n12 攻擊向量：\n' : '\n12 Attack Vectors:\n')
  for (const v of ATTACK_VECTORS) {
    const name = zh ? v.nameZh : v.name
    const desc = zh ? v.descriptionZh : v.description
    console.log(`  ${v.id}`)
    console.log(`    ${name}`)
    console.log(`    ${desc}\n`)
  }
}

async function main() {
  // Read from file
  if (fileMode && filePath) {
    try {
      prompt = readFileSync(filePath, 'utf8')
    } catch (e: any) {
      console.error(`Error reading file: ${e.message}`)
      process.exit(1)
    }
  }

  // Read from stdin if no prompt provided
  if (!prompt && !process.stdin.isTTY) {
    const chunks: Buffer[] = []
    for await (const chunk of process.stdin) {
      chunks.push(chunk)
    }
    prompt = Buffer.concat(chunks).toString('utf8').trim()
  }

  if (!prompt) {
    printHelp()
    process.exit(1)
  }

  // Output scanning mode (OWASP LLM02)
  if (outputMode) {
    const result = scanOutput(prompt)
    if (jsonMode) {
      console.log(JSON.stringify(result, null, 2))
    } else {
      const riskColors: Record<string, string> = {
        safe: '\x1b[32m', low: '\x1b[36m', medium: '\x1b[33m', high: '\x1b[31m', critical: '\x1b[1m\x1b[31m',
      }
      const color = riskColors[result.riskLevel] || ''
      console.log(`\n${color}  Risk: ${result.riskLevel.toUpperCase()} \x1b[0m\x1b[2m(${result.threats.length} threat(s))\x1b[0m`)
      console.log()
      if (result.threats.length === 0) {
        console.log('  \x1b[32m✓\x1b[0m No dangerous payloads detected.')
      } else {
        for (const t of result.threats) {
          const sevColor = t.severity === 'critical' ? '\x1b[1m\x1b[31m' : t.severity === 'high' ? '\x1b[31m' : t.severity === 'medium' ? '\x1b[33m' : '\x1b[36m'
          console.log(`  ${sevColor}✗\x1b[0m ${t.name} \x1b[2m[${t.severity}]\x1b[0m`)
          console.log(`    \x1b[2m${t.match.substring(0, 80)}\x1b[0m`)
        }
      }
      console.log(`\n  \x1b[2m${result.summary}\x1b[0m\n`)
    }
    process.exit(result.safe ? 0 : 1)
  }

  const result = auditWithDetails(prompt)

  if (jsonMode) {
    console.log(JSON.stringify(result, null, 2))
    return
  }

  // Pretty print
  const gradeColors: Record<string, string> = {
    A: '\x1b[32m', // green
    B: '\x1b[36m', // cyan
    C: '\x1b[33m', // yellow
    D: '\x1b[33m', // yellow
    F: '\x1b[31m', // red
  }
  const reset = '\x1b[0m'
  const bold = '\x1b[1m'
  const dim = '\x1b[2m'
  const gc = gradeColors[result.grade] || ''

  console.log('')
  console.log(
    `${bold}${gc}  Grade: ${result.grade}  ${reset}${dim}(${result.score}/100, ${result.coverage} defenses)${reset}`,
  )
  console.log('')

  const header = zhMode ? '  防護狀態：' : '  Defense Status:'
  console.log(`${bold}${header}${reset}`)
  console.log('')

  for (const check of result.checks) {
    const icon = check.defended ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'
    const name = zhMode ? check.nameZh : check.name
    const conf = `${dim}(${Math.round(check.confidence * 100)}%)${reset}`
    console.log(`  ${icon} ${name} ${conf}`)
    console.log(`    ${dim}${check.evidence}${reset}`)
  }

  if (result.unicodeIssues.found) {
    console.log('')
    console.log(
      `  \x1b[33m⚠ ${zhMode ? 'Unicode 問題' : 'Unicode Issues'}: ${result.unicodeIssues.evidence}${reset}`,
    )
  }

  if (result.missing.length > 0) {
    console.log('')
    const missingHeader = zhMode ? '  缺少的防護：' : '  Missing Defenses:'
    console.log(`${bold}${missingHeader}${reset}`)
    for (const id of result.missing) {
      const vec = ATTACK_VECTORS.find((v) => v.id === id)
      if (vec) {
        const name = zhMode ? vec.nameZh : vec.name
        console.log(`  → ${name}`)
      }
    }
  }

  console.log('')
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
