@echo off
setlocal enabledelayedexpansion

:: GCS/Drone Cryptographic Framework Test Script
:: Usage: run_test.bat [crypto_code]
::    e.g. run_test.bat c1  (for ASCON)
::         run_test.bat c2  (for AES)
::         run_test.bat c6  (for Kyber)

echo === GCS/Drone Cryptographic Framework Test ===

:: Validate input parameter
if "%~1"=="" (
  echo ERROR: Please specify a crypto code as parameter.
  echo Usage: run_test.bat [c1-c8]
  echo    c1 = ASCON
  echo    c2 = AES
  echo    c3 = Camellia
  echo    c4 = SPECK
  echo    c5 = HIGHT
  echo    c6 = Kyber
  echo    c7 = Dilithium
  echo    c8 = Falcon
  exit /b 1
)

set CRYPTO_CODE=%~1
set CRYPTO_NAME=Unknown

:: Map crypto codes to names for better display
if "%CRYPTO_CODE%"=="c1" set CRYPTO_NAME=ASCON
if "%CRYPTO_CODE%"=="c2" set CRYPTO_NAME=AES
if "%CRYPTO_CODE%"=="c3" set CRYPTO_NAME=Camellia
if "%CRYPTO_CODE%"=="c4" set CRYPTO_NAME=SPECK
if "%CRYPTO_CODE%"=="c5" set CRYPTO_NAME=HIGHT
if "%CRYPTO_CODE%"=="c6" set CRYPTO_NAME=Kyber
if "%CRYPTO_CODE%"=="c7" set CRYPTO_NAME=Dilithium
if "%CRYPTO_CODE%"=="c8" set CRYPTO_NAME=Falcon

:: Map crypto codes to script names
if "%CRYPTO_CODE%"=="c1" set DRONE_SCRIPT=drone_ascon.py
if "%CRYPTO_CODE%"=="c2" set DRONE_SCRIPT=drone_aes.py
if "%CRYPTO_CODE%"=="c3" set DRONE_SCRIPT=drone_camellia.py
if "%CRYPTO_CODE%"=="c4" set DRONE_SCRIPT=drone_speck.py
if "%CRYPTO_CODE%"=="c5" set DRONE_SCRIPT=drone_hight.py
if "%CRYPTO_CODE%"=="c6" set DRONE_SCRIPT=drone_kyber_hybrid.py
if "%CRYPTO_CODE%"=="c7" set DRONE_SCRIPT=drone_dilithium.py
if "%CRYPTO_CODE%"=="c8" set DRONE_SCRIPT=drone_falcon.py

:: Validate the crypto code
if "%CRYPTO_NAME%"=="Unknown" (
  echo ERROR: Invalid crypto code '%CRYPTO_CODE%'
  echo Valid codes are: c1, c2, c3, c4, c5, c6, c7, c8
  exit /b 1
)

echo Starting test for %CRYPTO_NAME% (%CRYPTO_CODE%)...

:: Check if conda environment is activated
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
  echo ERROR: Python not found in PATH.
  echo Please activate your conda environment first:
  echo   conda activate gcs-env
  exit /b 1
)

:: First, start the crypto manager in a new window
echo [1/3] Starting Crypto Manager...
start "Crypto Manager" cmd /k "python gcs\crypto_manager.py"

:: Wait a few seconds for the manager to initialize
timeout /t 3 /nobreak > nul

:: Then start the drone proxy in another window
echo [2/3] Starting Drone Proxy for %CRYPTO_NAME%...
start "Drone Proxy - %CRYPTO_NAME%" cmd /k "python drone\%DRONE_SCRIPT%"

:: Wait for the drone proxy to initialize
echo Waiting for services to initialize...
timeout /t 5 /nobreak > nul

:: Finally, use the controller to switch to the matching GCS proxy
echo [3/3] Connecting GCS to Drone using %CRYPTO_NAME%...
python gcs\gcs_controller.py switch %CRYPTO_CODE%

echo.
echo === Test Running ===
echo The test is now running with:
echo   - Crypto Manager    (window title: Crypto Manager)
echo   - %CRYPTO_NAME% Drone Proxy (window title: Drone Proxy - %CRYPTO_NAME%)
echo   - %CRYPTO_NAME% GCS Proxy   (managed by Crypto Manager)
echo.
echo You can close this window. To stop the test, close the other windows
echo or run: python gcs\gcs_controller.py stop
echo.

endlocal
