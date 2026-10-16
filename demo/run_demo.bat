@echo off
setlocal

echo === Running Salvage Demo ===
call salvage.bat demo\input demo\output
if errorlevel 1 (
    echo Error during salvage run!
    exit /b 1
)

echo.
echo === Salvage Execution Completed ===
echo Summary from report.json:
python -c "import json; r = json.loads(open('demo/output/report.json').read()); print(json.dumps(r['summary'], indent=2)); print('\nFiles Processed:'); [print(f' - {f[\"file\"]}: format={f[\"format\"]} (conf={f[\"confidence\"]}), records={f[\"records_recovered\"]} (verif={f.get(\"verified_records\",0)}, heur={f.get(\"heuristic_records\",0)}), carved={f.get(\"analysis_summary\",{}).get(\"carved_count\", 0)}, verif_cov={f.get(\"verified_coverage_pct\",0.0)}%%, heur_cov={f.get(\"heuristic_coverage_pct\",0.0)}%%, damages={f[\"damage_count\"]}') for f in r['files']]"
