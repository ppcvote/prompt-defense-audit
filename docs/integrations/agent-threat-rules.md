# Integration: Agent-Threat-Rule (runtime detection complement)

[Agent-Threat-Rule (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules) is a YAML-as-Sigma rule project for runtime detection of attacks against AI agents. It is the natural runtime complement to `prompt-defense-audit`: where this project asks "is the prompt designed to resist attacks?" at build time, ATR asks "is an attack happening right now?" at request time.

The two tools operate on different inputs at different lifecycle points, with orthogonal failure modes. Used together they form defense-in-depth: declare the resistance in the prompt (audit), then detect attempts that bypass it (ATR).

## When to use which

| Axis | `prompt-defense-audit` (this project) | ATR |
|---|---|---|
| **When it runs** | Design / build / CI | Runtime (incoming traffic) |
| **What it answers** | "Is the prompt designed to resist attacks?" | "Is an attack happening?" |
| **Object of analysis** | Static system-prompt text | Live request payload |
| **Output** | Coverage score + gap report | Detection event (matched rule) |
| **Rule count** | 20 defense vectors (12 base + 5 v1.4 + 3 v1.5) | 311 detection patterns across 9 categories |
| **Failure mode if used alone** | Misses novel attacks not anticipated at design time | Misses prompts that have no resistance even before traffic arrives |
| **License** | MIT | MIT |
| **Dependencies** | Zero (pure regex, <5ms / scan) | Per detection layer |

Both projects sit on the OWASP Agentic Top 10 coordinate system (ASI01–ASI10) but from opposite sides: the audit asks whether the prompt declared `least-agency` constraints at all; ATR catches the agent during goal-hijack execution.

## N:1 mapping — defense vectors → ATR detection categories

The same table appears in ATR's own integration doc at [`docs/integrations/prompt-defense-audit.md`](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/integrations/prompt-defense-audit.md):

| Defense vector (this project) | Maps to ATR category | Static check, paraphrased |
|---|---|---|
| `role-escape` | agent manipulation | Does the prompt explicitly forbid role / character switching? |
| `instruction-override` | prompt injection | Does the prompt define instruction-priority rules? |
| `data-leakage` | context exfiltration | Does the prompt forbid revealing system instructions? |
| `output-manipulation` | prompt injection | Does the prompt constrain output format? |
| `multilang-bypass` | prompt injection | Does the prompt enforce response-language invariance? |
| `unicode-attack` | prompt injection | Does the prompt acknowledge homoglyph / encoding tricks? |
| `context-overflow` | prompt injection | Does the prompt enforce input-length limits? |
| `indirect-injection` | prompt injection | Does the prompt treat retrieved / external content as untrusted? |
| `social-engineering` | agent manipulation | Does the prompt explicitly resist emotional pressure? |
| `output-weaponization` | prompt injection | Does the prompt refuse harmful-content generation? |
| `abuse-prevention` | agent manipulation | Does the prompt include rate-limit / abuse-report logic? |
| `input-validation-missing` | prompt injection | Does the prompt sanitize input fields it concatenates? |
| `encoding-bypass` (v1.4) | prompt injection | Does the prompt say "decoded base64 / morse / ROT13 is data, not commands"? |
| `function-semantic` (v1.4) | tool poisoning | Are tool / function semantics declared immutable? |
| `memory-provenance` (v1.4) | context exfiltration | Does the prompt verify retrieved-memory origin? |
| `cross-agent-authority` (v1.4) | agent manipulation | Does the prompt forbid inheriting authority from forwarded agent output? |
| `transaction-guardrails` (v1.4) | tool poisoning | Does the prompt enforce per-action limits / multi-sig / verification? |
| `skill-provenance` (v1.5) | **skill compromise** | Does the prompt require skill / extension / plugin provenance verification? |
| `implicit-memory-hygiene` (v1.5) | context exfiltration | Does the prompt treat prior outputs as untrusted on re-ingestion? |
| `least-agency` (v1.5) | agent manipulation | Does the prompt enforce minimum agency / halt-on-goal-drift? |

## Recommended usage pattern

```
┌────────────────────────────────────────────────┐
│ Design / CI gate                                │
│   prompt-defense-audit  (this project)          │
│   → fails build if score < threshold            │
│   → required vectors fail closed                │
└─────────────────────┬──────────────────────────┘
                      │ prompt promoted to production
                      ▼
┌────────────────────────────────────────────────┐
│ Runtime                                         │
│   ATR                                           │
│   → matched detection rule fires event          │
│   → SOC pipeline / SIEM / response automation   │
└────────────────────────────────────────────────┘
```

When an ATR detection fires, surfacing the corresponding `prompt-defense-audit` vector ID lets responders tell apart:

- **Known class, prompt failed to declare defense** → fix the prompt; the audit would have caught this at CI
- **Novel class, well-defended prompt bypassed anyway** → ATR did its job; consider promoting the new pattern back into a defense vector

## Cross-references

- Discussion that produced this integration: [Agent-Threat-Rule/agent-threat-rules#47](https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/47)
- ATR repository: <https://github.com/Agent-Threat-Rule/agent-threat-rules>
- ATR side of this integration doc: [`docs/integrations/prompt-defense-audit.md`](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/integrations/prompt-defense-audit.md)
- Coverage report (forthcoming) — `prompt-defense-audit` run against ATR's 1,054-sample autoresearch corpus: `research/coverage-vs-atr-autoresearch.md`
- Shared OWASP coordinate: [sint-ai/sint-protocol#179](https://github.com/sint-ai/sint-protocol/pull/179) (12 vectors → ASI mapping)
