@echo off
cd /d "C:\Users\Matheus\Downloads\ConsoleApplication7 (15)"
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" ConsoleApplication7.sln /p:Configuration=Release /p:Platform=x64 /t:ConsoleApplication7 /v:minimal
echo EXIT_CODE=%ERRORLEVEL%
