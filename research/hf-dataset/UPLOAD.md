# How to upload this dataset to HuggingFace Hub

Everything is staged in this directory. Two paths:

## Path A — Web upload (no CLI required, ~5 min)

1. Go to https://huggingface.co/new-dataset
2. **Owner**: pick your HF account (e.g. `ppcvote`)
3. **Dataset name**: `prompt-defense-1646`
4. **License**: CC0 1.0 Universal
5. **Visibility**: Public
6. Click **Create dataset**.
7. On the new dataset page, drag-and-drop these files:
   - `README.md` (becomes the dataset card)
   - `croissant.json`
   - `data/gap_rates.parquet`
   - `data/grade_distribution.parquet`
8. Commit. Done.

## Path B — CLI upload (1-line, ~30 sec, requires token)

```bash
# Install
pip install -U huggingface_hub

# Log in once (paste your token from https://huggingface.co/settings/tokens — needs "write" scope)
huggingface-cli login

# Upload the staged dataset (run from this hf-dataset/ directory)
huggingface-cli upload --repo-type=dataset ppcvote/prompt-defense-1646 . .
```

That's it. The dataset will be live at `https://huggingface.co/datasets/ppcvote/prompt-defense-1646` and immediately loadable via `datasets.load_dataset("ppcvote/prompt-defense-1646")`.

## After upload

- Add the link to https://github.com/ppcvote/prompt-defense-audit/blob/master/README.md
- Add it to https://ultralab.tw/minyi (the "AI Builder" credentials block — counts as a permanent citation artefact)
- Cross-reference from the preprint
- Tweet / Threads it once
