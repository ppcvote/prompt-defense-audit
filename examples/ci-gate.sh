#!/bin/bash
# CI/CD quality gate — fail the build if prompt defense grade is below threshold.
#
# Usage:
#   ./examples/ci-gate.sh prompt.txt       # default: fail on D or F
#   ./examples/ci-gate.sh prompt.txt B     # fail on anything below B
#
# Add to your CI pipeline:
#   - name: Prompt defense audit
#     run: npx prompt-defense-audit --json --file prompt.txt | node examples/ci-gate.js

PROMPT_FILE="${1:?Usage: ci-gate.sh <prompt-file> [min-grade]}"
MIN_GRADE="${2:-C}"

if [ ! -f "$PROMPT_FILE" ]; then
  echo "Error: file not found: $PROMPT_FILE"
  exit 1
fi

RESULT=$(npx prompt-defense-audit --json --file "$PROMPT_FILE")
GRADE=$(echo "$RESULT" | node -e "
  let d=''; process.stdin.on('data',c=>d+=c);
  process.stdin.on('end',()=>console.log(JSON.parse(d).grade));
")
SCORE=$(echo "$RESULT" | node -e "
  let d=''; process.stdin.on('data',c=>d+=c);
  process.stdin.on('end',()=>console.log(JSON.parse(d).score));
")

# Grade ordering: A=5 B=4 C=3 D=2 F=1
grade_to_num() {
  case "$1" in
    A) echo 5 ;; B) echo 4 ;; C) echo 3 ;; D) echo 2 ;; F) echo 1 ;; *) echo 0 ;;
  esac
}

CURRENT=$(grade_to_num "$GRADE")
MINIMUM=$(grade_to_num "$MIN_GRADE")

if [ "$CURRENT" -lt "$MINIMUM" ]; then
  echo "❌ Prompt defense audit FAILED: grade $GRADE ($SCORE/100), minimum required: $MIN_GRADE"
  exit 1
else
  echo "✅ Prompt defense audit PASSED: grade $GRADE ($SCORE/100)"
  exit 0
fi
