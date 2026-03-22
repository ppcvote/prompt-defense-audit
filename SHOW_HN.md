# Show HN Draft — prompt-defense-audit

## Title (80 chars max)

Show HN: I open-sourced the prompt defense scanner behind our AI security tool

## Text

I built an AI security scanner (UltraProbe, https://ultralab.tw/probe) that audits LLM system prompts for missing defenses. The core scanner is now open source.

What it does: checks your system prompt against 12 attack vectors (based on OWASP LLM Top 10) and tells you what's missing. Pure regex — no LLM calls, no API keys, no network requests. Runs in < 1ms.

The 12 vectors:

1. Role Escape — can someone say "ignore all previous instructions"?
2. Instruction Override — are there explicit refusal clauses?
3. Data Leakage — can the prompt be tricked into revealing itself?
4. Output Manipulation — can someone force unintended output formats?
5. Multi-language Bypass — does it defend against attacks in other languages?
6. Unicode/Homoglyph — zero-width chars, Cyrillic lookalikes, RTL overrides
7. Context Overflow — input length limits?
8. Indirect Injection — external data validation?
9. Social Engineering — emotional manipulation resistance?
10. Output Weaponization — harmful content generation prevention?
11. Abuse Prevention — rate limiting awareness?
12. Input Validation — XSS/SQL injection sanitization?

Example:

    $ npx prompt-defense-audit "You are a helpful assistant."
    Grade: F  (8/100, 1/12 defenses)

Most "AI security" tools require sending your prompt to a cloud service or running an LLM to analyze it. This one is deterministic — same input always produces the same output, runs offline, costs nothing.

Bilingual: supports both English and Traditional Chinese prompts and output.

Technical details: ~200 lines of TypeScript. Each vector has regex patterns that detect defensive language (role boundaries, refusal clauses, etc.). A defense is "present" when enough patterns match. It checks for defense coverage, not attack simulation.

Limitations: regex-based detection has inherent limits. A prompt can contain defensive language but still be vulnerable. This doesn't replace pen testing — it's a fast sanity check.

We use this in production at UltraProbe (https://ultralab.tw/probe), which has scanned 500+ websites for AI security vulnerabilities. The scanner is the first phase — deterministic regex check in < 5ms, then optionally a deeper LLM-based analysis.

GitHub: https://github.com/ppcvote/prompt-defense-audit
Install: npm install ppcvote/prompt-defense-audit

Built by a one-person AI company in Taiwan (https://ultralab.tw). Happy to answer questions about prompt injection defense patterns.

---

## 投稿筆記

- **最佳時間**：週二～四，台灣時間晚上 6-9 點（= 美東 6-9 AM）
- **Title 備選**：
  - "Show HN: I open-sourced the prompt defense scanner behind our AI security tool"
  - "Show HN: Deterministic prompt defense audit — 12 vectors, pure regex, < 1ms"
  - "Show HN: Scan your LLM system prompt for missing defenses in < 1ms"
- **注意**：HN Text 不支援 markdown，純文字，空行分段
- **回覆策略**：技術細節越多越好。重點講 regex vs LLM 的取捨、為什麼確定性比 AI 分析更適合 CI/CD
