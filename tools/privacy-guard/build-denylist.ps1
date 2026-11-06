# Gera a lista dos valores REAIS da rede deste PC que nunca devem ir para o repositório
# (MACs, nomes de dispositivos, nomes e notas que escreveste, chave da NVD, utilizador do Windows...).
#
# A lista é lida dos teus ficheiros de dados (%LOCALAPPDATA%\Nodar\*.json) e escrita para
# %LOCALAPPDATA%\Nodar\private-denylist.txt, FORA do repositório. Este script não contém nenhum valor real
# e não imprime nenhum: só diz quantos encontrou.
#
# Uso:  powershell -File tools\privacy-guard\build-denylist.ps1
# Volta a correr depois de um scan novo (surgem dispositivos novos) ou de dares nomes a dispositivos.

param(
    [string]$DataDir = (Join-Path $env:LOCALAPPDATA 'Nodar'),
    [string]$Out = (Join-Path $DataDir 'private-denylist.txt')
)

$values = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$generic = '^(router|unknown|desconhecido|dispositivo|device|online|offline|home|local|localhost)$'
$macPattern = '^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$'
$nameProps = 'Hostname', 'FriendlyName', 'Name', 'Note', 'nvdApiKey'

function Add-Value([string]$v) {
    $t = $v.Trim()
    if ($t.Length -ge 5 -and $t -notmatch $generic) { [void]$values.Add($t) }
}

function Add-Mac([string]$mac) {
    $hex = ($mac -replace '[:-]', '').ToUpperInvariant()
    if ($hex -match '^0{12}$|^F{12}$') { return }               # endereço nulo e de difusão
    Add-Value ($hex -replace '(.{2})(?=.)', '$1:')               # AA:BB:CC:00:00:01
    Add-Value ($hex -replace '(.{2})(?=.)', '$1-')               # AA-BB-CC-00-00-01
    Add-Value $hex                                               # AABBCC000001
}

function Walk($node, [string]$property) {
    if ($null -eq $node) { return }
    if ($node -is [string]) {
        if ($node -match $macPattern) { Add-Mac $node }
        elseif ($nameProps -contains $property) { Add-Value $node }
        return
    }
    if ($node -is [System.Collections.IEnumerable]) { foreach ($item in $node) { Walk $item $property }; return }
    if ($node -is [pscustomobject]) {
        foreach ($p in $node.PSObject.Properties) {
            if ($p.Name -match $macPattern) { Add-Mac $p.Name }  # chaves que são MACs (ex.: o histórico)
            Walk $p.Value $p.Name
        }
    }
}

$files = 'history.json', 'watchlist.json', 'known-devices.json', 'gateway.json', 'upnp-mappings.json', 'settings.json'
$read = 0
foreach ($name in $files) {
    $path = Join-Path $DataDir $name
    if (-not (Test-Path $path)) { continue }
    try { Walk (Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json) '' ; $read++ }
    catch { Write-Warning "Não consegui ler $name (ignorado)." }
}

# O utilizador e o nome do computador também não devem aparecer em nenhum ficheiro.
Add-Value $env:USERNAME
Add-Value $env:COMPUTERNAME

# Valores que já reviste e aceitas no repositório (por exemplo o teu alias na licença, ou um hostname genérico).
# O ficheiro é teu, fica fora do repositório e tem um valor por linha.
$allow = Join-Path $DataDir 'private-allow.txt'
if (Test-Path $allow) {
    foreach ($line in [System.IO.File]::ReadAllLines($allow)) { [void]$values.Remove($line.Trim()) }
}

New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
[System.IO.File]::WriteAllText($Out, (($values | Sort-Object) -join "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
"{0} valores guardados (de {1} ficheiros de dados) em {2}" -f $values.Count, $read, $Out
