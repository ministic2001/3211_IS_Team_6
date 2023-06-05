cd C:\Users\Student\Documents\SmartMeterData\Meter2
for /f %%i in ('dir /b/a-d/od/t:c') do set LATEST_FILE_NAME=%%i
echo The most recently created file is %LATEST_FILE_NAME%
powershell -Command "(gc %LATEST_FILE_NAME%) | Out-File %LATEST_FILE_NAME%"

cd C:\Users\Student\Documents\SmartMeterData\Meter3
for /f %%i in ('dir /b/a-d/od/t:c') do set LATEST_FILE_NAME=%%i
echo The most recently created file is %LATEST_FILE_NAME%
powershell -Command "(gc %LATEST_FILE_NAME%) | Out-File %LATEST_FILE_NAME%"

cd C:\Users\Student\Documents\SmartMeterData\Meter4
for /f %%i in ('dir /b/a-d/od/t:c') do set LATEST_FILE_NAME=%%i
echo The most recently created file is %LATEST_FILE_NAME%
powershell -Command "(gc %LATEST_FILE_NAME%) | Out-File %LATEST_FILE_NAME%"