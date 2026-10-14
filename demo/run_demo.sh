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
    print(f' - {f[\"file\"]}: format={f[\"format\"]}, valid_header={f[\"is_valid_header\"]}, records={f[\"records_recovered\"]}, damages={f[\"damage_count\"]}')
"
