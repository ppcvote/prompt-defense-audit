# Preprint — Defense Posture in 1,646 Production System Prompts

LaTeX source for the preprint accompanying `prompt-defense-audit` v1.5.

## Build

```bash
cd paper
pdflatex preprint.tex
pdflatex preprint.tex   # second pass for references
```

Or use [Overleaf](https://overleaf.com): create a new project, drop in
`preprint.tex`, compile.

## Targets

- **arXiv** (`cs.CR`) — requires endorsement from an existing arXiv
  author on first submission. If endorsement is a blocker, use Zenodo.
- **Zenodo** (https://zenodo.org/deposit) — no endorsement needed.
  Upload the compiled PDF + the source `.tex`. Choose CC-BY-4.0 for
  the paper, CC0 for the dataset, MIT for the code. You get a permanent
  DOI immediately.
- **OpenReview** — many workshops (e.g. NeurIPS SafeGen-AI, ICML
  Reliable AI) accept anytime; check workshop pages.
- **OSF** (https://osf.io/preprints) — alternative preprint server.

## License

Paper text: **CC-BY-4.0**. Companion code (`prompt-defense-audit`):
**MIT**. Companion aggregate dataset: **CC0**.
