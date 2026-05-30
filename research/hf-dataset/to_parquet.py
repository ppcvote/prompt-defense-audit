"""Convert defense-posture-results.json into HuggingFace-ready parquet files.

Output:
  hf-dataset/data/gap_rates.parquet      — one row per defense vector
  hf-dataset/data/grade_distribution.parquet — one row per letter grade

The full per-prompt detail is NOT included in this aggregate dataset
(the source corpora that would let you regenerate it are listed in
README.md and the reproduction script lives at ../scan.mjs).
"""

from __future__ import annotations

import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SOURCE = ROOT / "research" / "defense-posture-results.json"
OUT_DIR = HERE / "data"
OUT_DIR.mkdir(exist_ok=True)


def main() -> None:
    payload = json.loads(SOURCE.read_text(encoding="utf-8"))

    meta = payload["meta"]
    gap_rates = payload["gap_rates"]
    grades = payload["grade_distribution"]

    # 1. gap_rates table
    vectors = list(gap_rates.keys())
    gap_table = pa.table(
        {
            "vector": vectors,
            "gap_rate": [gap_rates[v]["gap_rate"] for v in vectors],
            "defended": [gap_rates[v]["defended"] for v in vectors],
            "missing": [gap_rates[v]["missing"] for v in vectors],
            "total_prompts": [meta["total_prompts"]] * len(vectors),
            "scan_date": [meta["scan_date"]] * len(vectors),
            "scanner_version": [meta["scanner"]] * len(vectors),
        }
    )
    gap_path = OUT_DIR / "gap_rates.parquet"
    pq.write_table(gap_table, gap_path)
    print(f"wrote {gap_path} ({gap_path.stat().st_size} bytes)")

    # 2. grade_distribution table
    letters = list(grades.keys())
    grade_table = pa.table(
        {
            "grade": letters,
            "count": [grades[l] for l in letters],
            "share": [grades[l] / meta["total_prompts"] for l in letters],
            "total_prompts": [meta["total_prompts"]] * len(letters),
            "scan_date": [meta["scan_date"]] * len(letters),
        }
    )
    grade_path = OUT_DIR / "grade_distribution.parquet"
    pq.write_table(grade_table, grade_path)
    print(f"wrote {grade_path} ({grade_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
