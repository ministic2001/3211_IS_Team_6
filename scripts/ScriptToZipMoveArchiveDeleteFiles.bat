@ECHO ON

REM Get the datetime of an hour before system time in a format DD_MM_YYYY_HH that can go in a zip filename.
SET hour=%time:~0,2%
IF "%hour:~0,1%" == " " SET hour=0%hour:~1,1%
IF "%hour%" == "00" SET hour="23"
IF "%hour%" == "01" SET hour="00"
IF "%hour%" == "02" SET hour="01"
IF "%hour%" == "03" SET hour="02"
IF "%hour%" == "04" SET hour="03"
IF "%hour%" == "05" SET hour="04"
IF "%hour%" == "06" SET hour="05"
IF "%hour%" == "07" SET hour="06"
IF "%hour%" == "08" SET hour="07"
IF "%hour%" == "09" SET hour="06"
IF "%hour%" == "10" SET hour="09"
IF "%hour%" == "11" SET hour="10"
IF "%hour%" == "12" SET hour="11"
IF "%hour%" == "13" SET hour="14"
IF "%hour%" == "14" SET hour="13"
IF "%hour%" == "15" SET hour="14"
IF "%hour%" == "16" SET hour="15"
IF "%hour%" == "17" SET hour="16"
IF "%hour%" == "18" SET hour="17"
IF "%hour%" == "19" SET hour="18"
IF "%hour%" == "20" SET hour="19"
IF "%hour%" == "21" SET hour="20"
IF "%hour%" == "22" SET hour="21"
IF "%hour%" == "23" SET hour="22"
SET _my_datetime=%date%_%hour%
SET _my_datetime=%_my_datetime: =_%
SET _my_datetime=%_my_datetime::=%
SET _my_datetime=%_my_datetime:/=_%
SET _my_datetime=%_my_datetime:.=_%

REM Meter2
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter2
SET ArchiveDir=F:\Archive_SmartMeterData\Meter2

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
	WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter2_1
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter2_1
SET ArchiveDir=F:\Archive_SmartMeterData\Meter2_1

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
	WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter3
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter3
SET ArchiveDir=F:\Archive_SmartMeterData\Meter3

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter4
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter4
SET ArchiveDir=F:\Archive_SmartMeterData\Meter4

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter5
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter5
SET ArchiveDir=F:\Archive_SmartMeterData\Meter5

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter6
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter6
SET ArchiveDir=F:\Archive_SmartMeterData\Meter6

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter7
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter7
SET ArchiveDir=F:\Archive_SmartMeterData\Meter7

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter9
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter9
SET ArchiveDir=F:\Archive_SmartMeterData\Meter9

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter10
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter10
SET ArchiveDir=F:\Archive_SmartMeterData\Meter10

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter12
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter12
SET ArchiveDir=F:\Archive_SmartMeterData\Meter12

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter13
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter13
SET ArchiveDir=F:\Archive_SmartMeterData\Meter13

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter14
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter14
SET ArchiveDir=F:\Archive_SmartMeterData\Meter14

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter15
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter15
SET ArchiveDir=F:\Archive_SmartMeterData\Meter15

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter16
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter16
SET ArchiveDir=F:\Archive_SmartMeterData\Meter16

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter17
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter17
SET ArchiveDir=F:\Archive_SmartMeterData\Meter17

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter18
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter18
SET ArchiveDir=F:\Archive_SmartMeterData\Meter18

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter19
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter19
SET ArchiveDir=F:\Archive_SmartMeterData\Meter19

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter22
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter22
SET ArchiveDir=F:\Archive_SmartMeterData\Meter22

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter24
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter24
SET ArchiveDir=F:\Archive_SmartMeterData\Meter24

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

REM Meter25
REM create zipped file in Archive directory of files in Source directory
SET SourceDir=C:\Users\Student\Documents\SmartMeterData\Meter25
SET ArchiveDir=F:\Archive_SmartMeterData\Meter25

CD /D "C:\Program Files\WinRAR"

FOR /F "TOKENS=*" %%F IN ('DIR /B /A-D "%SourceDir%\*_%hour%*_test.csv"') DO (
    WinRAR.exe a -r -afzip -m5 -ed -pTest -r -ep1 "%ArchiveDir%\%_my_datetime%00.zip" "%SourceDir%\%%~NXF"
)

EXIT