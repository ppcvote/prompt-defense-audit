# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## [1.6.0] - 2026-07-20

### Added — SARIF 2.1.0 emitter (`--sarif`, `--sarif-out`)

Envelope-conformant SARIF output behind a new, fully separate emission path
(#3, ppcvote/prompt-defense-audit#1). Existing `--json` / pretty output is
byte-identical to v1.5.0 — a snapshot regression test pins it. Highlights:

- `DRAFT-pda-<slug>` rule ids per the envelope RFC's `DRAFT-<scanner>-<slug>`
  convention, each carrying its tracking-issue URL until ATR assigns canonical
  ids ([claude-code-skill-security-check#24](https://github.com/aliksir/claude-code-skill-security-check/issues/24)).
- One artifact per run with `hashes["sha-256"]`; `invocations[].executionSuccessful`
  always present, with `toolExecutionNotifications` + stderr excerpt on failure.
- `columnKind: utf16CodeUnits` declared; credential findings located by
  region but never reproduced in `snippet.text`.
- Vendored SARIF 2.1.0 schema; conformance tests validate against it with ajv
  (dev-dep only — runtime stays zero-dependency).

### Fixed — artifact digest is now SHA-256 over raw octets

The envelope RFC adopted a normative digest basis on 2026-07-20 (§2: raw
octets, before any character decoding, equal to `sha256sum`). Two distinct
defects in the pre-release emitter are fixed. **They are separate classes —
do not conflate them when reasoning about which digests moved:**

1. **Encoding basis (`--file` and API callers passing decoded file content).**
   The digest was computed over the UTF-8-*decoded* string, which substitutes
   U+FFFD for invalid sequences before hashing. Decode-then-hash is
   many-to-one: two files differing only in invalid bytes share one digest, so
   a verdict on one could replay as authoritative for the other with the join
   "succeeding". Affected digests: **only** artifacts containing invalid UTF-8
   or lone surrogates. Well-formed UTF-8 round-trips byte-identically, so
   those digests are unchanged.
2. **stdin trimming (broader).** The stdin path hashed a `.trim()`ed string,
   so **any** piped input with leading/trailing whitespace — including the
   trailing newline that ends most POSIX text files and every `echo`-piped
   string — produced a digest matching neither `sha256sum` nor any other
   envelope emitter, independent of UTF-8 validity.

Mechanics: the CLI now captures the artifact's raw bytes at the single point
it is read (file or stdin) and passes them via a new optional
`SarifEmitOptions.artifactBytes`; `sha256Hex()` accepts `string | Uint8Array`
(additive — string behavior unchanged). In SARIF mode, stdin is scanned
untrimmed so region offsets and the digest describe the same artifact; the
legacy pretty/`--json` stdin paths keep their historical trim and remain
byte-identical. Cross-implementation conformance is pinned in tests against
the shared `invalid-utf8/` fixture (skills-lock/skil-lock#41): raw
`0e5f6446…`, pre-fix decoded `eec1f132…`, one-byte-flip `1546f3f1…`.

**Migration:** no npm release ever shipped the wrong basis (it existed only on
git master between #3, 2026-07-09, and this fix). If you consumed SARIF from
master in that window, re-scan: digests differ for the two classes above.

### Docs

- README: `--sarif` usage + digest-basis note; fixed a stale "12 attack
  vectors" line (17 since v1.4).

## [1.5.0] - 2026-05-30

### Added — broader smuggling + output coverage

**Expanded suspicious Unicode detection (4 → 12 script categories).**
Previously detected: Cyrillic, Zero-width, RTL override, Fullwidth. v1.5 adds:

- **Cyrillic Supplement** (U+0500-052F) — extended homoglyph coverage
- **Greek** (U+0370-03FF) — omicron/Ο, mu/μ Latin lookalikes
- **Armenian, Cherokee, Coptic** — additional homoglyph sources
- **Mathematical Alphanumeric Symbols** (U+1D400-1D7FF) — Latin lookalikes that bypass keyword filters (e.g. 𝐢𝐠𝐧𝐨𝐫𝐞)
- **Variation Selectors** (U+FE00-FE0F) and **Supplement** (U+E0100-E01EF) — invisible byte smuggling
- **Tag characters** (U+E0020-E007F) — Bishop Fox's "ASCII smuggler" technique: bytes invisible to humans but tokenize as text
- Renamed "RTL override" → "BiDi override" (includes LTR override as well)

**New: embedded payload detector** (`detectEmbeddedPayloads`).
Surfaced through `AuditDetailedResult.embeddedPayloads`. Catches:

- Base64 blobs ≥ 40 chars (likely > 30 bytes payload)
- Hex runs ≥ 32 pairs
- `\x` and `\u` escape sequences (≥ 8 in a row)
- Binary octet runs
- Morse code (≥ 10 token run)

**Output-scanner: 6 new threat rules** for v1.5 attack surface:

- `schema-description-inject` — JSON Schema `description`/`title` field with classic injection directives ("ignore previous", "you are now"). Critical for MCP tool registries / OpenAPI specs imported into agent toolchains.
- `schema-html-comment-inject` — HTML comments smuggled inside schema text fields.
- `modality-marker-injection` — OCR / Whisper transcript / PDF-text marker blocks containing injection seeds. Mitigates "image OCR → text → LLM" exfil pipelines.
- `markdown-obfuscated-js-uri` — Markdown links with obfuscated `javascript:` protocol (whitespace splits, zero-width breaks, percent-encoding).
- `tool-arg-injection` — Function-call argument values containing classic prompt-injection seed phrases.
- `svg-foreign-object-html` — SVG payloads with `<foreignObject>` wrapping HTML (XSS smuggling vector).

### Tests

- 91 baseline tests still passing (no regressions).
- +30 new tests across Unicode expansion, embedded payload detection, and the 6 new output-scanner rules.

### API

- `AuditDetailedResult.embeddedPayloads?: { found: boolean; evidence: string }` (optional for backwards compatibility).
- No breaking changes to `audit()`, `auditWithDetails()`, or `scanOutput()` signatures.

---

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
