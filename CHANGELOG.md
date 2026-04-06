# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

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
