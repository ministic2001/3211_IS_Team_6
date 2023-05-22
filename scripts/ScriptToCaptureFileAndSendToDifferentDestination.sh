#!/bin/sh

sshpass -p 'Student12345@' ssh student@172.16.2.223 -o ConnectTimeout=5 "C:\Windows\Temp\SmartMetertest\ScriptToCaptureFileAndSendToDifferentDestination.bat
