@echo off
setlocal

set "ROOT=%~dp0"
set "INPUT=%~1"
set "OUTPUT=%~2"

if "%INPUT%"=="" set "INPUT=%ROOT%input.obfuv3.lua"
if "%OUTPUT%"=="" set "OUTPUT=%ROOT%input.obfuv3.deobfuscated.lua"

if not exist "%INPUT%" (
  echo Missing input file: "%INPUT%"
  exit /b 1
)

if not exist "%ROOT%deobfu_vm_v3.lua" (
  echo Missing deobfuscator: "%ROOT%deobfu_vm_v3.lua"
  exit /b 1
)

lua "%ROOT%deobfu_vm_v3.lua" "%INPUT%" "%OUTPUT%"
if errorlevel 1 exit /b %errorlevel%

echo Wrote "%OUTPUT%"
