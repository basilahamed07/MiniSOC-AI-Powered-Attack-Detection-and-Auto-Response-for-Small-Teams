@echo off
title basil copilot Code
where omnirush.cmd >nul 2>&1
if errorlevel 1 (
  echo omnirush.cmd was not found on PATH. Install OmniRush or add it to PATH.
  exit /b 1
)
omnirush.cmd %*
