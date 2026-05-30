---
license: cc0-1.0
language:
  - en
tags:
  - prompt-injection
  - prompt-engineering
  - llm-security
  - owasp-llm-top-10
  - red-team
  - ai-safety
size_categories:
  - n<1K
configs:
  - config_name: gap_rates
    data_files:
      - split: aggregate
        path: data/gap_rates.parquet
  - config_name: grade_distribution
    data_files:
      - split: aggregate
        path: data/grade_distribution.parquet
pretty_name: Defense Posture in 1,646 Production System Prompts
---

# Defense Posture in 1,646 Production System Prompts

Aggregate dataset accompanying the preprint
[*Defense Posture in 1,646 Production System Prompts: A Deterministic Audit of Prompt Injection Mitigations*](https://github.com/ppcvote/prompt-defense-audit/tree/master/paper).

## What's in here

Two parquet files containing aggregate measurements from a population-level audit of 1,646 production LLM system prompts:

- **`gap_rates`** — one row per defense vector (12 rows total), with `gap_rate`, `defended` count, `missing` count, and the population total. This is the table reproduced in §3.2 of the preprint.
- **`grade_distribution`** — one row per letter grade (A–F), with `count`, `share`, and population total.

> ⚠ This is an **aggregate** dataset. Per-prompt rows are *not* shipped here because the source prompts themselves belong to four upstream corpora with their own licenses (MIT / GPL / public-domain). To regenerate per-prompt detail, clone the four corpora listed below and run the reproduction script (linked at the bottom).

## Quick start

```python
from datasets import load_dataset

gap = load_dataset("ppcvote/prompt-defense-1646", "gap_rates", split="aggregate")
print(gap.to_pandas().sort_values("gap_rate", ascending=False))

grades = load_dataset("ppcvote/prompt-defense-1646", "grade_distribution", split="aggregate")
print(grades.to_pandas())
```

Expected (truncated):

```
                            vector  gap_rate  defended  missing
0    Indirect Injection Protection     0.978        37     1609
1                Unicode Protection     0.973        44     1602
2                     Role Boundary     0.924       125     1521
...
```

## Headline findings

- **78.3% of audited prompts score F** (below 45 / 100). Only 1.1% score A.
- **97.8% lack indirect-injection defense.** This is the largest measured gap.
- **97.3% lack Unicode protection** (Tag chars, Math Alphanumeric, BiDi, Variation Selectors).
- The gap distribution is **bimodal**: structural defenses (Input Validation, Data Protection) are present in >90% of prompts; adversarial-context defenses are missing from >75%.

See the preprint for the full discussion and the *posture-as-substrate* framing.

## Source corpora

The 1,646 prompts are the deduplicated union of four publicly available leak corpora:

| Source | License | Approx. count |
|---|---|---|
| [`jujumilk3/leaked-system-prompts`](https://github.com/jujumilk3/leaked-system-prompts) | MIT | ~1,021 |
| [`x1xhlol/system-prompts-and-models-of-ai-tools`](https://github.com/x1xhlol/system-prompts-and-models-of-ai-tools) | GPL | ~137 |
| [`LouisShark/chatgpt_system_prompt`](https://github.com/LouisShark/chatgpt_system_prompt) | MIT | ~489 |
| [`elder-plinius/CL4R1T4S`](https://github.com/elder-plinius/CL4R1T4S) | public domain | ~217 |

After deduplication by SHA-256 of normalised content, `n = 1,646`.

## Reproducing the per-prompt data

1. Clone the four corpora above (`git clone --depth 1 …`).
2. Install the scanner: `npm i -g prompt-defense-audit@1.5`.
3. Run the scan script:
   [`prompt-defense-audit/research/scan.mjs`](https://github.com/ppcvote/prompt-defense-audit/blob/master/research/scan.mjs).

The aggregate JSON output should match this dataset.

## Scanner

The scanner used is [`prompt-defense-audit`](https://github.com/ppcvote/prompt-defense-audit) v1.0–v1.5 (MIT). It is pure-regex, runs in <5 ms per prompt, and has zero LLM-inference cost. Twelve defense rules are aligned to OWASP LLM Top 10; the v1.4+ release adds five further agent-specific rules (encoding-injection, function-immutable, memory-provenance, cross-agent-auth, transaction-guardrails) which are *not* applied in this corpus scan — see §2.2 of the preprint.

## License

This aggregate dataset is released under **[CC0 1.0 Universal (Public Domain Dedication)](https://creativecommons.org/publicdomain/zero/1.0/)**. The companion scanner is MIT-licensed; the preprint is CC-BY-4.0.

## Citation

```bibtex
@misc{xie2026_defense_posture_1646,
  title  = {Defense Posture in 1,646 Production System Prompts: A Deterministic Audit of Prompt Injection Mitigations},
  author = {Xie, Min Yi},
  year   = {2026},
  publisher = {Ultra Lab},
  url    = {https://github.com/ppcvote/prompt-defense-audit/tree/master/paper},
}
```

## Contact

Min Yi Xie · Ultra Creation Co., Ltd. (Ultra Lab) · contact@ultralab.tw · https://ultralab.tw
