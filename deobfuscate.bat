@echo off
setlocal

set "ROOT=%~dp0"
set "INPUT=%ROOT%input.lua"
set "BYTECODE=%ROOT%input.luac"
set "OUTPUT=%ROOT%input.deobfuscated.lua"

if not exist "%INPUT%" (
  echo Missing input file: "%INPUT%"
  exit /b 1
)

if not exist "%ROOT%extract_payload.lua" (
  echo Missing extractor: "%ROOT%extract_payload.lua"
  exit /b 1
)

if not exist "%ROOT%unluac.jar" (
  echo Missing decompiler: "%ROOT%unluac.jar"
  exit /b 1
)

lua "%ROOT%extract_payload.lua" "%INPUT%" "%BYTECODE%"
if errorlevel 1 exit /b %errorlevel%

java -jar "%ROOT%unluac.jar" "%BYTECODE%" > "%OUTPUT%"
if errorlevel 1 exit /b %errorlevel%

echo Wrote "%OUTPUT%"
