#!/usr/bin/env bash
set -uo pipefail

RUNS="${RUNS:-1}"
ARMS="${ARMS:-prompt native}"
APP="app/build/install/app/bin/app"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="data/runs/$STAMP"

[ -n "${ANTHROPIC_API_KEY:-}" ] || { echo "ANTHROPIC_API_KEY is not set" >&2; exit 1; }
[ -x "$APP" ] || ./gradlew installDist -q
[ -f data/corpus/manifest.json ] || { echo "corpus not frozen: run '$APP freeze'" >&2; exit 1; }

mkdir -p "$OUT/raw"
"$APP" manifest > "$OUT/manifest.json"
"$APP" csv-header > "$OUT/results.csv"

CVES=$(tail -n +2 data/corpus.csv | cut -d, -f1)
total=$(( $(echo "$CVES" | wc -l) * $(echo $ARMS | wc -w) * RUNS ))
i=0

for arm in $ARMS; do
  for run in $(seq 1 "$RUNS"); do
    for cve in $CVES; do
      i=$((i + 1))
      printf '[%3d/%d] %-7s %-16s run %d ' "$i" "$total" "$arm" "$cve" "$run"
      row=$("$APP" "$cve" --arm "$arm" --run "$run" --format csv --raw "$OUT/raw/run$run")
      echo "$row" >> "$OUT/results.csv"
      echo "$row" | cut -d, -f5,6,14 | tr ',' ' '
    done
  done
done

echo
echo "results:  $OUT/results.csv"
echo "manifest: $OUT/manifest.json"
echo "raw:      $OUT/raw"
