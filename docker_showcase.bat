@echo off
REM ==============================================================================
REM Track 3 PS 02 - Salvage: Docker Showcase Script for Judges
REM ==============================================================================

echo [1/4] Checking Docker daemon status...
docker info >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Docker daemon is not running!
    echo Please start Docker Desktop from your Start Menu and wait until it is ready.
    pause
    exit /b 1
)

echo [OK] Docker daemon is running.
echo.

echo [2/4] Building Docker Image: 'salvage'...
docker build -t salvage .
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Docker build failed.
    pause
    exit /b %ERRORLEVEL%
)
echo [OK] Docker image built successfully.
echo.

echo [3/4] Running 55-test suite INSIDE the Docker container...
docker run --rm --entrypoint python3 salvage -m unittest discover tests
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Tests failed inside container.
    pause
    exit /b %ERRORLEVEL%
)
echo [OK] All tests passed inside Docker.
echo.

echo [4/4] Executing ./salvage on sample files...
set SAMPLES_DIR=E:\sample\Genesis_Track3_PS2_Sample_Files-main\samples
set OUTPUT_DIR=E:\sample\decoded_output

if not exist "%SAMPLES_DIR%" (
    echo Samples directory not found at %SAMPLES_DIR%, falling back to local demo/input
    set SAMPLES_DIR=%~dp0demo\input
    set OUTPUT_DIR=%~dp0demo\output
)

docker run --rm -v "%SAMPLES_DIR%:/data/in" -v "%OUTPUT_DIR%:/data/out" salvage /data/in /data/out

echo.
echo ==============================================================================
echo [SUCCESS] Salvage execution completed with exit code 0!
echo Displaying generated report.json summary:
echo ==============================================================================
powershell -NoProfile -Command "(Get-Content '%OUTPUT_DIR%\report.json' -Raw | ConvertFrom-Json).files | Select-Object file, format, status, records, damage | Format-Table -AutoSize"

pause
