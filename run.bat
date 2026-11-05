@echo off
setlocal

echo ========================================
echo  Nodar
echo ========================================
echo.

where dotnet >nul 2>nul
if %errorlevel% neq 0 (
    echo .NET SDK nao encontrado. Instala em https://dotnet.microsoft.com/download
    pause
    exit /b 1
)

cd /d "%~dp0"

echo A iniciar a aplicacao Windows...
echo Pressiona Ctrl+C para parar.
echo.
dotnet run --project NetworkScanner\NetworkScanner.csproj

if %errorlevel% neq 0 (
    echo.
    echo Falha ao iniciar a aplicacao.
    pause
)
