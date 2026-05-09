# prompt-defense-audit

[![CI](https://github.com/ppcvote/prompt-defense-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/ppcvote/prompt-defense-audit/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/prompt-defense-audit)](https://www.npmjs.com/package/prompt-defense-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/node/v/prompt-defense-audit)](https://nodejs.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](package.json)

**Deterministic LLM prompt defense scanner.** Checks system prompts for missing defenses against 17 attack vectors (12 base + 5 agent-specific in v1.4). Pure regex — no LLM, no API calls, < 5ms, 100% reproducible.

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

We scanned **1,646 production system prompts** from 4 public datasets. Results:
- 97.8% lack indirect injection defense
- 78.3% score F (below 45/100)
- Average score: 36/100

Existing security tools require LLM calls (expensive, non-deterministic) or cloud services (privacy concerns). This package runs **locally, instantly, for free**.

**Our philosophy:** The deterministic engine is the product. AI deep analysis is optional — because regex is already strong enough for 90%+ of use cases. Zero AI cost by default.

## Install

```bash
npm install prompt-defense-audit
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

// Detailed audit with per-vector evidence
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

### CI/CD Gate

```bash
GRADE=$(npx prompt-defense-audit --json --file prompt.txt | node -e "
  const r = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
  console.log(r.grade);
")
if [[ "$GRADE" == "D" || "$GRADE" == "F" ]]; then
  echo "Prompt defense audit failed: grade $GRADE"
  exit 1
fi
```

## 17 Attack Vectors

Based on [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/), empirical research on 1,646 production prompts, and structured analysis of six documented crypto AI agent incidents (see [CASE_STUDIES.md](./CASE_STUDIES.md)).

### 12 Base Vectors

| # | Vector | What it checks | Gap rate* |
|---|--------|----------------|-----------|
| 1 | **Role Escape** | Role definition + boundary enforcement | 92.4% |
| 2 | **Instruction Override** | Refusal clauses + meta-instruction protection | — |
| 3 | **Data Leakage** | System prompt / training data disclosure prevention | 9.4% |
| 4 | **Output Manipulation** | Output format restrictions | 88.3% |
| 5 | **Multi-language Bypass** | Language-specific defense | 64.3% |
| 6 | **Unicode Attacks** | Homoglyph / zero-width character detection | — |
| 7 | **Context Overflow** | Input length limits | — |
| 8 | **Indirect Injection** | External data validation | 97.8% |
| 9 | **Social Engineering** | Emotional manipulation resistance | 71.4% |
| 10 | **Output Weaponization** | Harmful content generation prevention | — |
| 11 | **Abuse Prevention** | Rate limiting / auth awareness | — |
| 12 | **Input Validation** | XSS / SQL injection / sanitization | — |

### 5 Agent Vectors (v1.4, May 2026)

Added after analysing six documented crypto AI agent incidents. Each vector is grounded in a specific real-world failure — see [CASE_STUDIES.md](./CASE_STUDIES.md) for primary sources and root-cause analysis.

| # | Vector | What it checks | Reference incident |
|---|--------|----------------|--------------------|
| 13 | **Encoding-aware Indirect Injection** | Treating decoded/translated content (Morse, base64, ROT13) as untrusted data, not instructions | Grok×Bankrbot Morse code, May 2026 |
| 14 | **Function/Tool Semantic Immutability** | Function or tool semantics cannot be redefined mid-conversation | Freysa `approveTransfer` redefinition, Nov 2024 |
| 15 | **Memory Provenance Awareness** | Retrieved RAG memory may be poisoned by adversaries on other platforms | ElizaOS memory injection, Princeton 2025 |
| 16 | **Cross-Agent Authorization Boundary** | Authority does not silently inherit from another agent's output | Grok×Bankrbot principal confusion, May 2026 |
| 17 | **Financial Transaction Guardrails** | Hard limits, multi-sig, refusal thresholds for transactions | Lobstar Wilde decimal-error transfer, Feb 2026 |

*Gap rate = % of 1,646 production prompts missing this defense. Source: [research data](https://github.com/ppcvote/prompt-defense-audit/blob/master/research/gap-20260405.json).

## Grading

| Grade | Score | Meaning |
|-------|-------|---------|
| **A** | 90–100 | Strong defense coverage |
| **B** | 70–89 | Good, some gaps |
| **C** | 50–69 | Moderate, significant gaps |
| **D** | 30–49 | Weak, most defenses missing |
| **F** | 0–29 | Critical, nearly undefended |

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

## How It Works

1. Parses the system prompt text
2. For each of 12 attack vectors, applies regex patterns that detect defensive language
3. A defense is "present" when enough patterns match (usually >= 1, some require >= 2)
4. Checks for suspicious Unicode characters embedded in the prompt
5. Calculates coverage score and assigns a letter grade

**This tool does NOT:**
- Send your prompt to any external service
- Use LLM calls (100% regex-based)
- Guarantee security (it checks for defensive *language*, not runtime behavior)
- Replace penetration testing or behavioral evaluation

## What This Scanner Does NOT Catch

Static prompt analysis is layer 1 of a defense-in-depth model. The following classes of attack require defenses at other layers — this scanner does not replace them, and we say so explicitly so it isn't oversold:

1. **Runtime credential compromise.** Dashboard takeovers, leaked API keys, malicious deployment commits. Standard infosec, out of scope. (Reference: [AIXBT dashboard takeover, Mar 2025](./CASE_STUDIES.md).)
2. **Tool / permission scoping bugs.** Whether the agent has dangerous tools, and how those tools are gated, is invisible to a prompt scanner. (Reference: [Bankrbot NFT-as-authorization, May 2026](./CASE_STUDIES.md).)
3. **Whether declared defenses are enforced at runtime.** A prompt can declare "verify retrieved memory" and the framework can ignore it. The scanner cannot tell.
4. **Numerical and unit bugs.** Off-by-1000 decimal errors, wrong-token-id transfers. Code-level bugs, not prompt issues. (Reference: [Lobstar Wilde, Feb 2026](./CASE_STUDIES.md).)
5. **Effectiveness vs. presence.** A prompt with the keyword "never" registers as defended even if a "helpful" framing dominates under adversarial pressure. We check for *presence* of defensive language, not its *strength*.
6. **Multi-turn adversarial dynamics.** Static scan of turn 0 cannot predict turn 482. (Reference: [Freysa, Nov 2024](./CASE_STUDIES.md).)

A pass on this scanner is necessary, not sufficient. See [CASE_STUDIES.md](./CASE_STUDIES.md) for an honest mapping of which documented incidents this scanner would flag versus which it cannot help with.

## Limitations

- **Regex-based detection is heuristic** — a prompt can contain defensive language but still be vulnerable at runtime. This tool measures *intent to defend*, not *actual defense effectiveness*.
- Only checks system prompt text, not model behavior under adversarial pressure.
- English and Traditional Chinese patterns only (contributions welcome for other languages).
- False positives/negatives are possible. See [research data](https://github.com/ppcvote/prompt-defense-audit/blob/master/research/gap-20260405.json) for calibration details.
- Fullwidth CJK punctuation (e.g. `，`) triggers Unicode detection — known limitation.

## Research

This tool is backed by empirical analysis of 1,646 production system prompts from 4 public datasets:

| Dataset | Size | Source |
|---------|------|--------|
| [LouisShark/chatgpt_system_prompt](https://github.com/LouisShark/chatgpt_system_prompt) | 1,389 | GPT Store custom GPTs |
| [jujumilk3/leaked-system-prompts](https://github.com/jujumilk3/leaked-system-prompts) | 121 | ChatGPT, Claude, Grok, Perplexity, Cursor, v0 |
| [x1xhlol/system-prompts-and-models](https://github.com/x1xhlol/system-prompts-and-models-of-ai-tools) | 80 | Cursor, Windsurf, Devin, Augment |
| [elder-plinius/CL4R1T4S](https://github.com/elder-plinius/CL4R1T4S) | 56 | Claude, Gemini, Grok, Cursor |

Key references:
- Greshake et al. (2023), [Not what you've signed up for](https://arxiv.org/abs/2302.12173) — indirect prompt injection
- Schulhoff et al. (2023), [Ignore This Title and HackAPrompt](https://arxiv.org/abs/2311.16119) — prompt injection taxonomy
- [OWASP LLM Top 10 (2025)](https://genai.owasp.org/llm-top-10/)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Key areas: new language patterns, better regex accuracy, integration examples.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities to dev@ultralab.tw — not via GitHub issues.

## License

MIT — [Ultra Lab](https://ultralab.tw)

## Used In Production

This library powers prompt defense detection across multiple production deployments and security frameworks:

- **[Cisco AI Defense — `mcp-scanner`](https://github.com/cisco-ai-defense/mcp-scanner/pull/146)** — `PromptDefenseAnalyzer` module (12-vector regex audit), [merged](https://github.com/cisco-ai-defense/mcp-scanner/pull/146) Apr 2026.
- **[Microsoft Agent Governance Toolkit — `agent-compliance`](https://github.com/microsoft/agent-governance-toolkit/pull/854)** — `PromptDefenseEvaluator` integrated with `MerkleAuditChain` + `PromotionGate`, [merged](https://github.com/microsoft/agent-governance-toolkit/pull/854) Apr 2026.
- **[UltraProbe](https://ultralab.tw/probe)** (UltraLab) — free AI security scanner; uses this library as the Prompt Security engine.
- **[Quartz Cloud](https://quartz.tw)** — Taiwan-domiciled runtime AI firewall (Q3 2026 closed beta). Quartz uses this engine as its ingress detector + extends it with runtime + jurisdictional layers. The engine is open source under [Ultra Lab](https://ultralab.tw); Quartz is a commercial brand built on top of it. Customers can audit, fork, or self-host the engine without lock-in.

## Related

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [UltraProbe](https://ultralab.tw/probe) — Free AI security scanner (uses this library)
- [Quartz](https://quartz.tw) — Commercial runtime AI firewall built on this engine
- [ultralab-scanners](https://github.com/ppcvote/ultralab-scanners) — SEO + AEO scanners
