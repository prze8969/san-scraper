@echo off
setlocal
if "%~1"=="" (
    echo Usage: show_file.bat ^<path_to_json_file^>
    exit /b 1
)
python -c "import json, sys; d = json.loads(open(r'%~1', encoding='utf-8').read()); print('\n=== File Recovery Info ==='); print('File   :', d.get('source_file')); print('Format :', d.get('format')); print('Status :', d.get('status')); print('Damages:', len(d.get('damage', []))); print('Records:', len(d.get('records', []))); print('\n--- Records Sample (first 5) ---'); [print(json.dumps(r, indent=2)) for r in d.get('records', [])[:5]]"
