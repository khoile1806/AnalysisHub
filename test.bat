@echo off
start "Test" /wait powershell.exe -NoProfile -ExecutionPolicy Bypass -File "test.ps1"
