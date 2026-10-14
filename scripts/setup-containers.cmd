@echo off
setlocal
cd /d "%~dp0.."
if not exist .env (
  powershell.exe -NoProfile -Command "$taskBytes = New-Object byte[] 48; $taskRandom = [System.Security.Cryptography.RandomNumberGenerator]::Create(); try { $taskRandom.GetBytes($taskBytes) } finally { $taskRandom.Dispose() }; $taskPassword = [Convert]::ToBase64String($taskBytes); [IO.File]::WriteAllText((Join-Path (Get-Location) '.env'), ('TRIAGEMATE_DB_OWNER_PASSWORD=' + $taskPassword + [Environment]::NewLine + 'TRIAGEMATE_PORT=5190' + [Environment]::NewLine))"
  if errorlevel 1 exit /b 1
)
docker compose up -d --build --wait --wait-timeout 300
if errorlevel 1 exit /b 1
for /f "tokens=*" %%P in ('docker compose port app 8000') do echo TriageMate is ready at http://%%P.
