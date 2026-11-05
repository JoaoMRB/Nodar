@echo off
echo ============================================
echo   Nodar - Build
echo ============================================
echo.

dotnet publish NetworkScanner\NetworkScanner.csproj ^
  -c Release ^
  -r win-x64 ^
  --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:IncludeNativeLibrariesForSelfExtract=true ^
  -p:EnableCompressionInSingleFile=true ^
  -o dist

if %errorlevel% neq 0 (
    echo.
    echo ERRO na compilacao.
    pause
    exit /b 1
)

echo.
echo ============================================
echo   Compilado com sucesso!
echo   Executavel: dist\Nodar.exe
echo ============================================
echo.
pause
