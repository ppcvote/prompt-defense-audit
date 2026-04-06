# Contributing to prompt-defense-audit

Thanks for your interest in improving LLM prompt security. Contributions are welcome.

## Development Setup

```bash
git clone https://github.com/ppcvote/prompt-defense-audit.git
cd prompt-defense-audit
npm install
npm test          # run tests
npm run lint      # type check
npm run build     # compile to dist/
```

Requires Node.js >= 18.

## Running Tests

```bash
npm test                # run all tests
npm run test:coverage   # run with coverage report
```

Tests use [Vitest](https://vitest.dev/). Coverage threshold is 80% (statements, branches, functions, lines).

## Pull Request Guidelines

1. **Open an issue first** for non-trivial changes. Discuss before coding.
2. **One PR per concern.** Don't bundle unrelated changes.
3. **Include tests.** New features need tests. Bug fixes need regression tests.
4. **Keep zero dependencies.** This package has no runtime dependencies by design.
5. **Run `npm test` and `npm run lint`** before submitting.

## What We're Looking For

- **New language patterns** — regex patterns for Japanese, Korean, Spanish, German, etc.
- **Better patterns** — reduce false positives/negatives in existing regex rules
- **New attack vectors** — propose new vectors with justification and test cases
- **Integration examples** — LangChain, Vercel AI SDK, LlamaIndex, etc.
- **Documentation** — clearer explanations, more examples

## Code Style

- TypeScript strict mode
- No runtime dependencies
- Regex patterns should be readable — use named groups or comments for complex patterns
- Bilingual: all user-facing strings need English + Traditional Chinese (`nameZh`, `descriptionZh`)

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Korean language patterns
fix: reduce false positives in role-escape detection
docs: add LangChain integration example
test: add edge cases for Unicode detection
```

## Security

If you discover a security vulnerability, **do not open an issue**. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
