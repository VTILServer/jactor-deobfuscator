@echo off
REM devirtualize.bat  -  full deobfuscator for the jactor/luau VM obfuscator.
REM Usage:  devirtualize.bat <input.lua> [output.lua]
REM Produces:  <output>.pseudo.txt   (devirtualized opcode listing)
REM            <output>.luac         (reconstructed Lua 5.1 bytecode)
REM            <output>             (runnable Lua source via unluac)
setlocal
if "%~1"=="" (
  echo Usage: devirtualize.bat ^<input.lua^> [output.lua]
  exit /b 1
)
python "%~dp0devirtualize.py" %*
endlocal
