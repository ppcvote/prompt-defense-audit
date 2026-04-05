# Defense Posture Study — 1,646 Production System Prompts

## How to Reproduce

```bash
# 1. Clone the 4 datasets
git clone --depth 1 https://github.com/jujumilk3/leaked-system-prompts.git
git clone --depth 1 https://github.com/x1xhlol/system-prompts-and-models-of-ai-tools.git
git clone --depth 1 https://github.com/LouisShark/chatgpt_system_prompt.git
git clone --depth 1 https://github.com/elder-plinius/CL4R1T4S.git

# 2. Run the scan (update paths in scan.mjs to match your local dirs)
node research/scan.mjs

# 3. Compare your output to defense-posture-results.json
```

## Results Summary

- **n = 1,646** unique prompts (deduplicated by content hash)
- **Average score: 36/100**
- **78.3% scored F** (below 45)
- **Only 1.1% scored A** (90+)
- **97.8% have zero indirect injection defense**

See [defense-posture-results.json](defense-posture-results.json) for full data.

## Datasets

| Source | Prompts | Avg Score |
|--------|:-------:|:---------:|
| jujumilk3/leaked-system-prompts | 121 | 43 |
| x1xhlol/system-prompts-and-models-of-ai-tools | 80 | 54 |
| elder-plinius/CL4R1T4S | 56 | 56 |
| LouisShark/chatgpt_system_prompt | 1,389 | 33 |

## Scanner

[prompt-defense-audit](https://www.npmjs.com/package/prompt-defense-audit) v1.0.0 — MIT license, zero dependencies, <5ms per prompt.

```bash
npx prompt-defense-audit "Your system prompt here"
```
