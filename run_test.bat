@echo off
REM ==============================================================================
REM run_test.bat
REM
REM PURPOSE:
REM   Automates the testing of the GCS/Drone cryptographic framework.
REM   This script launches the necessary components in separate windows
REM   to simulate the full communication pipeline.
REM
REM USAGE:
REM   run_test.bat <crypto_code>
REM
REM   <crypto_code> is the code for the algorithm to test (e.g., c1, c2, ... c8).
REM
REM EXAMPLE:
REM   To test Kyber+AES (c6):
REM   > run_test.bat c6
REM
REM   To test Dilithium (c7):
REM   > run_test.bat c7
REM
REM PRE-REQUISITES:
REM   - Your conda environment 'gcs-env' must be activated or python must be in the path.
REM   - Dependencies must be installed (pip install -r requirements.txt in gcs and drone folders).
REM ==============================================================================

SETLOCAL

IF [%1]==[] (
    ECHO ERROR: No crypto code provided.
    ECHO.
    ECHO Usage: run_test.bat ^<crypto_code^>
    ECHO   (e.g., run_test.bat c6)
    GOTO :EOF
)

SET CODE=%1
ECHO.
ECHO =================================================
ECHO  GCS/DRONE FRAMEWORK TEST LAUNCHER
ECHO =================================================
ECHO.
ECHO  Testing Algorithm Code: %CODE%
ECHO.

REM --- Define the script paths ---
SET GCS_DIR=%~dp0gcs
SET DRONE_DIR=%~dp0drone

REM --- Map codes to drone script names ---
IF %CODE%==c1 SET DRONE_SCRIPT=drone_ascon.py
IF %CODE%==c2 SET DRONE_SCRIPT=drone_aes.py
IF %CODE%==c3 SET DRONE_SCRIPT=drone_camellia.py
IF %CODE%==c4 SET DRONE_SCRIPT=drone_speck.py
IF %CODE%==c5 SET DRONE_SCRIPT=drone_hight.py
IF %CODE%==c6 SET DRONE_SCRIPT=drone_kyber_hybrid.py
IF %CODE%==c7 SET DRONE_SCRIPT=drone_dilithium.py
IF %CODE%==c8 SET DRONE_SCRIPT=drone_falcon.py

IF NOT DEFINED DRONE_SCRIPT (
    ECHO ERROR: Invalid crypto code '%CODE%'. Please use c1 through c8.
    GOTO :EOF
)

ECHO  1. Starting Crypto Manager...
START "Crypto Manager" cmd /c "cd /d %GCS_DIR% && python crypto_manager.py"

ECHO  2. Starting Drone Proxy (%DRONE_SCRIPT%)...
START "Drone Proxy" cmd /c "cd /d %DRONE_DIR% && python %DRONE_SCRIPT%"

ECHO.
ECHO  Waiting 5 seconds for components to initialize...
timeout /t 5 /nobreak > NUL

ECHO.
ECHO  3. Sending command to GCS Controller to switch to %CODE%...
cd /d %GCS_DIR%
python gcs_controller.py switch %CODE%

ECHO.
ECHO =================================================
ECHO  TESTING INSTRUCTIONS
ECHO =================================================
ECHO.
ECHO - Two new windows have been opened: 'Crypto Manager' and 'Drone Proxy'.
ECHO - The GCS proxy has been started via the manager.
ECHO - Check the output in all three windows (this one, and the two new ones)
ECHO   to verify that the components have connected and are running without errors.
ECHO.
ECHO - To end the test, simply close the two new command prompt windows.
ECHO.

ENDLOCAL
