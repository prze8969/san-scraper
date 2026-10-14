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
python -c "import json; r = json.loads(open('demo/output/report.json').read()); print(json.dumps(r['summary'], indent=2)); print('\nFiles Processed:'); [print(f' - {f[\"file\"]}: format={f[\"format\"]}, valid_header={f[\"is_valid_header\"]}, records={f[\"records_recovered\"]}, damages={f[\"damage_count\"]}') for f in r['files']]"
