# prompt-defense-audit

**Deterministic LLM prompt defense scanner.** Checks system prompts for missing defenses against 12 attack vectors. Pure regex — no LLM, no API calls, < 5ms, 100% reproducible.

[繁體中文版](README.zh-TW.md)

```
$ npx prompt-defense-audit "You are a helpful assistant."

  Grade: F  (8/100, 1/12 defenses)

  Defense Status:

  ✗ Role Boundary (80%)
    Partial: only 1/2 defense pattern(s)
  ✗ Instruction Boundary (80%)
    No defense pattern found
  ✗ Data Protection (80%)
    No defense pattern found
  ...
```

## Why

OWASP lists **Prompt Injection** as the [#1 threat to LLM applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/). Yet most developers ship system prompts with zero defense.

Existing security tools require LLM calls (expensive, non-deterministic) or cloud services (privacy concerns). This package runs **locally, instantly, for free**.

**Our philosophy:** The deterministic engine is the product. AI deep analysis is optional — because regex is already strong enough for 90%+ of use cases. Zero AI cost by default.

## Install

```bash
npm install prompt-defense-audit
# or install directly from GitHub
npm install ppcvote/prompt-defense-audit
```

## Usage

### Programmatic (TypeScript / JavaScript)

```typescript
import { audit, auditWithDetails } from 'prompt-defense-audit'

// Quick audit
const result = audit('You are a helpful assistant.')
console.log(result.grade)    // 'F'
console.log(result.score)    // 8
console.log(result.missing)  // ['instruction-override', 'data-leakage', ...]

// Detailed audit with evidence
const detailed = auditWithDetails(mySystemPrompt)
for (const check of detailed.checks) {
  console.log(`${check.defended ? '✅' : '❌'} ${check.name}: ${check.evidence}`)
}
```

### CLI

```bash
# Inline prompt
npx prompt-defense-audit "You are a helpful assistant."

# From file
npx prompt-defense-audit --file my-prompt.txt

# Pipe from stdin
cat prompt.txt | npx prompt-defense-audit

# JSON output (for CI/CD)
npx prompt-defense-audit --json "Your prompt"

# Traditional Chinese output
npx prompt-defense-audit --zh "你的系統提示"

# List all 12 attack vectors
npx prompt-defense-audit --vectors
```

## 12 Attack Vectors

Based on OWASP LLM Top 10 and real-world prompt injection research:

| # | Vector | What it checks |
|---|--------|----------------|
| 1 | **Role Escape** | Role definition + boundary enforcement |
| 2 | **Instruction Override** | Refusal clauses + meta-instruction protection |
| 3 | **Data Leakage** | System prompt / training data disclosure prevention |
| 4 | **Output Manipulation** | Output format restrictions |
| 5 | **Multi-language Bypass** | Language-specific defense |
| 6 | **Unicode Attacks** | Homoglyph / zero-width character detection |
| 7 | **Context Overflow** | Input length limits |
| 8 | **Indirect Injection** | External data validation |
| 9 | **Social Engineering** | Emotional manipulation resistance |
| 10 | **Output Weaponization** | Harmful content generation prevention |
| 11 | **Abuse Prevention** | Rate limiting / auth awareness |
| 12 | **Input Validation** | XSS / SQL injection / sanitization |

## Grading

| Grade | Score | Meaning |
|-------|-------|---------|
| **A** | 90-100 | Strong defense coverage |
| **B** | 70-89 | Good, some gaps |
| **C** | 50-69 | Moderate, significant gaps |
| **D** | 30-49 | Weak, most defenses missing |
| **F** | 0-29 | Critical, nearly undefended |

## API Reference

### `audit(prompt: string): AuditResult`

Quick audit. Returns grade, score, and list of missing defense IDs.

```typescript
interface AuditResult {
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  score: number       // 0-100
  coverage: string    // e.g. "4/12"
  defended: number    // count of defended vectors
  total: number       // 12
  missing: string[]   // IDs of undefended vectors
}
```

### `auditWithDetails(prompt: string): AuditDetailedResult`

Full audit with per-vector evidence.

```typescript
interface AuditDetailedResult extends AuditResult {
  checks: DefenseCheck[]
  unicodeIssues: { found: boolean; evidence: string }
}

interface DefenseCheck {
  id: string
  name: string          // English
  nameZh: string        // 繁體中文
  defended: boolean
  confidence: number    // 0-1
  evidence: string      // Human-readable explanation
}
```

### `ATTACK_VECTORS: AttackVector[]`

Array of all 12 attack vector definitions with bilingual names and descriptions.

## Use Cases

- **CI/CD pipeline** — Fail builds if prompt defense score drops below threshold
- **Security review** — Audit all system prompts in your codebase before deployment
- **Prompt engineering** — Get instant feedback while writing system prompts
- **Compliance** — Document defense coverage for security audits
- **Education** — Learn what defenses a well-crafted prompt should have

### CI/CD Example

```bash
# Fail if grade is below B
GRADE=$(npx prompt-defense-audit --json --file prompt.txt | node -e "
  const r = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
  console.log(r.grade);
")
if [[ "$GRADE" == "D" || "$GRADE" == "F" ]]; then
  echo "Prompt defense audit failed: grade $GRADE"
  exit 1
fi
```

## How It Works

1. Parses the system prompt text
2. For each of 12 attack vectors, applies regex patterns that detect defensive language
3. A defense is "present" when enough patterns match (usually ≥ 1, some require ≥ 2)
4. Also checks for suspicious Unicode characters embedded in the prompt
5. Calculates coverage score and assigns a letter grade

**This tool does NOT:**
- Send your prompt to any external service
- Use LLM calls (100% regex-based)
- Guarantee security (it checks for defensive *language*, not actual runtime behavior)
- Replace penetration testing

## Limitations

- Regex-based detection has inherent limitations — a prompt can contain defensive language but still be vulnerable
- Only checks the system prompt text, not the actual AI model behavior
- English and Traditional Chinese patterns only (contributions welcome for other languages)
- Defense patterns are heuristic — false positives/negatives are possible

## Contributing

PRs welcome. Key areas:

- **New language patterns** — Add regex patterns for Japanese, Korean, Spanish, etc.
- **New attack vectors** — Propose new vectors with test cases
- **Better patterns** — Improve existing regex for fewer false positives
- **Documentation** — More examples, integration guides

## License

MIT — Ultra Lab (https://ultralab.tw)

## Used In Production

This library powers the **Prompt Security** mode of [UltraProbe](https://ultralab.tw/probe) — a free, open-source scanner used by 7,500+ monthly users across 23 countries.

UltraProbe has two core scan modes:
- **Website Scan** — SEO + AEO combined into an AI Visibility Score ([ultralab-scanners](https://github.com/ppcvote/ultralab-scanners))
- **Prompt Security** — This library. 12 attack vectors in < 5ms.

**Contributing to:** [NVIDIA garak](https://github.com/NVIDIA/garak/issues/1666) · [Cisco AI Defense](https://github.com/cisco-ai-defense/skill-scanner/issues/81) · [OWASP LLM Top 10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/pull/816)

## Related

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [UltraProbe](https://ultralab.tw/probe) — Free AI security scanner (Website Scan + Prompt Security)
- [ultralab-scanners](https://github.com/ppcvote/ultralab-scanners) — SEO + AEO scanners (the other half of UltraProbe)
- [Prompt Injection Primer](https://github.com/jthack/PIPE) — Background research
