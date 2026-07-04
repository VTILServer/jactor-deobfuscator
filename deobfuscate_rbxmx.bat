@echo off
setlocal

set "ROOT=%~dp0"
set "INPUT=%~1"
set "OUTPUT=%~2"

if "%INPUT%"=="" (
  echo Usage: deobfuscate_rbxmx.bat input.rbxmx [output.rbxmx]
  exit /b 1
)

if not exist "%INPUT%" (
  echo Missing input file: "%INPUT%"
  exit /b 1
)

if not exist "%ROOT%deobfuscate_rbxmx.lua" (
  echo Missing tool: "%ROOT%deobfuscate_rbxmx.lua"
  exit /b 1
)

if "%OUTPUT%"=="" (
  lua "%ROOT%deobfuscate_rbxmx.lua" "%INPUT%"
) else (
  lua "%ROOT%deobfuscate_rbxmx.lua" "%INPUT%" "%OUTPUT%"
)

exit /b %errorlevel%
