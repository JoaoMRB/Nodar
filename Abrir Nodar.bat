@echo off
cd /d "%~dp0"

if not exist "dist\Nodar.exe" (
    echo dist\Nodar.exe ainda nao existe. A compilar pela primeira vez...
    echo.
    where dotnet >nul 2>nul
    if errorlevel 1 (
        echo .NET SDK nao encontrado. Instala em https://dotnet.microsoft.com/download
        pause
        exit /b 1
    )
    dotnet publish src\Nodar.App\Nodar.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -o dist
    if errorlevel 1 (
        echo.
        echo ERRO na compilacao.
        pause
        exit /b 1
    )
)

start "" "%~dp0dist\Nodar.exe"
