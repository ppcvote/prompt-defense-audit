# MCP Official Servers — Defense Posture Audit (2026-04-29)

Scanned the 7 official servers in [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers/tree/main/src) using `prompt-defense-audit` v1.3.0.

## Methodology

1. Extract all `description` strings from server source (TypeScript + Python)
2. Concatenate per-server into a single text block
3. Run `npx prompt-defense-audit --json` against 12-vector defense checklist
4. Score: 0-100, mapped to OWASP LLM Top 10

## Results summary

| Server | Score | Grade | Coverage |
|---|---|---|---|
| everything | 17 | F | 2/12 |
| fetch | 17 | F | 2/12 |
| git | 17 | F | 2/12 |
| filesystem | 0 | F | 0/12 |
| memory | 0 | F | 0/12 |
| time | 0 | F | 0/12 |
| sequentialthinking | — | — | (no extractable descriptions) |

## 100% gap vectors (0/6 servers defended)

- role-escape
- output-manipulation
- multilang-bypass
- unicode-attack
- social-engineering
- output-weaponization
- abuse-prevention
- input-validation-missing

## Reproduce

```bash
git clone https://github.com/modelcontextprotocol/servers.git
for s in everything fetch filesystem git memory time; do
  prompts=$(grep -rE 'description.*"' "servers/src/$s/" | grep -oP '"[^"]{30,500}"')
  echo "$prompts" | npx prompt-defense-audit --json
done
```

## Caveat

This is **prompt-level** defense audit (pre-deploy posture) — checks whether tool descriptions encode refusal/scope/role-boundary language. Does not replace **parameter-level** validation (runtime input constraints) — that's a separate layer tracked in [modelcontextprotocol/servers#3537](https://github.com/modelcontextprotocol/servers/issues/3537).

The two are complementary: schema constraints catch malformed input at runtime; prompt-level audit catches missing defensive language at design time.
