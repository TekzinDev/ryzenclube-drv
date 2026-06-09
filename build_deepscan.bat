@echo off
cd /d "%~dp0DeepScan"
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" DeepScan.vcxproj /p:Configuration=Release /p:Platform=x64 /v:m
