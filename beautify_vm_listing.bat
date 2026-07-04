@echo off
setlocal

set "ROOT=%~dp0"
set "INPUT=%~1"
set "OUTPUT=%~2"

if "%INPUT%"=="" set "INPUT=%ROOT%input.obfuv3.deobfuscated.lua"
if "%OUTPUT%"=="" set "OUTPUT=%ROOT%input.obfuv3.beautified.lua"

if not exist "%INPUT%" (
  echo Missing VM listing file: "%INPUT%"
  exit /b 1
)

if not exist "%ROOT%beautify_vm_listing.lua" (
  echo Missing beautifier: "%ROOT%beautify_vm_listing.lua"
  exit /b 1
)

lua "%ROOT%beautify_vm_listing.lua" "%INPUT%" "%OUTPUT%"
if errorlevel 1 exit /b %errorlevel%

echo Wrote "%OUTPUT%"
