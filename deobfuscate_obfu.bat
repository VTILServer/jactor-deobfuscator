@echo off
setlocal

set "ROOT=%~dp0"
set "INPUT=%ROOT%input.obfu.lua"
set "BYTECODE=%ROOT%input.obfu.luac"
set "OUTPUT=%ROOT%input.obfu.deobfuscated.lua"

if not exist "%INPUT%" (
  echo Missing input file: "%INPUT%"
  exit /b 1
)

if not exist "%ROOT%deobfu_obfu.lua" (
  echo Missing deobfuscator: "%ROOT%deobfu_obfu.lua"
  exit /b 1
)

if not exist "%ROOT%unluac.jar" (
  echo Missing decompiler: "%ROOT%unluac.jar"
  exit /b 1
)

lua "%ROOT%deobfu_obfu.lua" "%INPUT%" "%OUTPUT%" "%BYTECODE%"
if errorlevel 1 exit /b %errorlevel%

echo Wrote "%OUTPUT%"
