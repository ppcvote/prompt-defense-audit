# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## [1.4.0] - 2026-05-08

### Added — 5 new agent-specific attack vectors

Derived from a structured analysis of six documented crypto AI agent incidents
(Lobstar Wilde, Grok×Bankrbot Morse, AIXBT, Freysa, ElizaOS memory injection,
Bankrbot March 2025). See [CASE_STUDIES.md](./CASE_STUDIES.md) for full root-cause
mapping.

- **encoding-injection** — Encoding-aware indirect injection. Checks whether the
  prompt warns against treating decoded/translated content (Morse, base64, ROT13)
  as executable instructions. Reference: Grok×Bankrbot Morse code attack, May 2026.
- **function-immutable** — Function/tool semantic immutability. Checks whether the
  prompt declares that function definitions cannot be redefined mid-conversation.
  Reference: Freysa adversarial game, Nov 2024 (approveTransfer redefinition).
- **memory-provenance** — Memory provenance awareness. Checks whether the prompt
  acknowledges that retrieved memory may be poisoned by adversaries on other
  platforms. Reference: ElizaOS cross-platform memory injection, Princeton 2025.
- **cross-agent-auth** — Cross-agent authorization boundary. Checks whether the
  prompt declares that authority does not silently inherit between agents.
  Reference: Grok×Bankrbot principal confusion, May 2026.
- **transaction-guardrails** — Financial transaction guardrails. Checks whether
  the prompt declares hard limits, multi-sig requirements, or refusal thresholds
  for transactions. Reference: Lobstar Wilde $250K decimal-error transfer,
  Feb 2026.

### Added — Documentation

- **CASE_STUDIES.md** — Six crypto AI agent prompt-injection incidents with
  primary sources, root-cause analysis, and honest mapping to the 17 vectors
  (which incidents the scanner catches, which it doesn't).
- **README "What this scanner can't catch"** — explicit scope statement on
  the limits of static prompt analysis (runtime credential compromise, tool
  scoping bugs, numerical bugs, presence vs effectiveness, multi-turn dynamics).

### Changed

- Total vectors: 12 → 17. CLI `--vectors`, JSON output, and coverage strings
  now reference 17. The 12 base vectors are unchanged in behavior.
- Test suite: 91 tests (was 84). New v1.4 vector-specific test cases added.
- Version display in CLI updated.

### Migration notes

If your CI/CD gate hardcodes a grade threshold, note that adding 5 new vectors
makes it *harder* to score A — a prompt that previously scored A on 12 vectors
will now score B unless you also add the new agent-specific defenses. Most
non-agent applications can ignore the 5 new vectors; they are most relevant to
agents that execute tools, have memory, or process external instructions.

## [1.3.0] - 2026-04-07

### Added
- **Test suite**: 82 tests via Vitest (67 unit + 15 CLI integration), 96%+ coverage
- **CI/CD**: GitHub Actions workflow — lint, test, build across Node 18/20/22
- **CONTRIBUTING.md**: Development setup, PR guidelines, code style
- **SECURITY.md**: Responsible disclosure policy
- **Issue templates**: Bug report (YAML form), feature request, PR template
- **CHANGELOG.md**: Version history
- **README badges**: CI status, npm version, license, Node.js, zero dependencies
- **Research section**: 1,646-prompt dataset references, academic citations, gap rate data
- **Examples**: CI/CD gate script, batch scanning

### Changed
- Test runner migrated from manual assertions to Vitest
- README restructured with research data, gap rates per vector, limitations section
- README.zh-TW.md synced with English version
- `prepublishOnly` now runs lint + test before build

## [1.2.1] - 2026-03-22

### Fixed
- False positive reduction in role-escape and data-leakage detection
- LLM-calibrated pattern tuning (69.6% agreement with gpt-4o-mini)

## [1.1.0] - 2026-03-22

### Changed
- Improved regex patterns: role-escape accuracy 35% → 90%, data-leakage 53% → 74%
- Reduced false positives by 78%

## [1.0.0] - 2026-03-22

### Added
- Initial release
- 12 attack vector detection (OWASP LLM Top 10 mapped)
- `audit()` and `auditWithDetails()` API
- CLI with `--file`, `--json`, `--zh`, `--vectors` options
- Bilingual support (English + Traditional Chinese)
- Unicode attack detection (Cyrillic, zero-width, RTL override, fullwidth)
- Zero runtime dependencies
