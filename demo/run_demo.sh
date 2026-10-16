#!/usr/bin/env sh
set -e

# Run salvage on demo inputs to demo outputs
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running Salvage Demo ==="
"$ROOT_DIR/salvage" "$ROOT_DIR/demo/input" "$ROOT_DIR/demo/output"

echo ""
echo "=== Salvage Execution Completed ==="
echo "Summary from report.json:"
python3 -c "
import json
from pathlib import Path
report = json.loads(Path('$ROOT_DIR/demo/output/report.json').read_text(encoding='utf-8'))
print(json.dumps(report['summary'], indent=2))
print('\nFiles Processed:')
for f in report['files']:
    carved_cnt = f.get('analysis_summary', {}).get('carved_count', 0)
    verif = f.get('verified_records', 0)
    heur = f.get('heuristic_records', 0)
    verif_cov = f.get('verified_coverage_pct', 0.0)
    heur_cov = f.get('heuristic_coverage_pct', 0.0)
    print(f' - {f[\"file\"]}: format={f[\"format\"]} (conf={f[\"confidence\"]}), records={f[\"records_recovered\"]} (verif={verif}, heur={heur}), carved={carved_cnt}, verif_cov={verif_cov}%, heur_cov={heur_cov}%, damages={f[\"damage_count\"]}')
"
