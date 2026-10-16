@echo off
setlocal
if "%~1"=="" (
    set "OUT_DIR=output"
) else (
    set "OUT_DIR=%~1"
)
python -c "import json, os, sys; p = os.path.join(r'%OUT_DIR%', 'report.json'); (print('\n=== Salvage Report Summary ===\nPath:', p, '\n') or [print(f'  {k.ljust(15)}: {v}') for k, v in json.loads(open(p, encoding='utf-8').read()).get('totals', {}).items()] or print('')) if os.path.exists(p) else print('Error: report.json not found in', r'%OUT_DIR%')"
