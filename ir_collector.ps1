<#
.SYNOPSIS
    Incident Response Toolkit — triage forense inicial para Windows.
    Coleta processos, conexões TCP, autoruns, eventos de segurança,
    arquivos modificados e sessões ativas. Gera HTML + JSON + ZIP.
.NOTES
    Execute como Administrador para coleta completa.
#>

#Requires -Version 5.1

$ErrorActionPreference = 'SilentlyContinue'

$hostname   = $env:COMPUTERNAME
$ts         = Get-Date -Format 'yyyyMMdd_HHmmss'
$geradoEm   = Get-Date -Format 'dd/MM/yyyy HH:mm:ss'
$saida      = Join-Path $PSScriptRoot "ir_output"
$MINUTOS    = 60

if (-not (Test-Path $saida)) { New-Item -ItemType Directory -Path $saida | Out-Null }

Write-Host "`n  INCIDENT RESPONSE TOOLKIT — Triage (PowerShell)" -ForegroundColor Cyan
Write-Host "  Host: $hostname | $geradoEm`n"
Write-Host "  [!] Execute como Administrador para coleta completa.`n" -ForegroundColor Yellow

# ── Processos ─────────────────────────────────────────────────────────────────
Write-Host "  Coletando processos..." -ForegroundColor Gray
$processos = Get-Process | ForEach-Object {
    $hash = 'N/A'
    if ($_.Path -and (Test-Path $_.Path)) {
        try { $hash = (Get-FileHash $_.Path -Algorithm SHA256).Hash } catch {}
    }
    [PSCustomObject]@{
        PID       = $_.Id
        Nome      = $_.Name
        CPU       = [math]::Round($_.CPU, 2)
        RAM_MB    = [math]::Round($_.WorkingSet / 1MB, 1)
        Caminho   = $_.Path ?? ''
        Empresa   = $_.Company ?? ''
        Inicio    = if ($_.StartTime) { $_.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
        SHA256    = $hash
    }
} | Sort-Object CPU -Descending

# ── Conexões TCP ──────────────────────────────────────────────────────────────
Write-Host "  Coletando conexões TCP..." -ForegroundColor Gray
$conexoes = Get-NetTCPConnection -State Established, Listen | ForEach-Object {
    $proc = try { (Get-Process -Id $_.OwningProcess).Name } catch { 'N/A' }
    [PSCustomObject]@{
        LocalAddr   = $_.LocalAddress
        LocalPort   = $_.LocalPort
        RemoteAddr  = $_.RemoteAddress
        RemotePort  = $_.RemotePort
        Estado      = $_.State
        PID         = $_.OwningProcess
        Processo    = $proc
    }
}

# ── Autoruns ──────────────────────────────────────────────────────────────────
Write-Host "  Coletando autoruns do registro..." -ForegroundColor Gray
$autorunKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$autoruns = foreach ($key in $autorunKeys) {
    $props = Get-ItemProperty $key
    if ($props) {
        $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            [PSCustomObject]@{ Chave = $key; Nome = $_.Name; Valor = $_.Value }
        }
    }
}

# ── Eventos de segurança ──────────────────────────────────────────────────────
Write-Host "  Coletando eventos de segurança recentes..." -ForegroundColor Gray
$inicio = (Get-Date).AddMinutes(-$MINUTOS)
$eventos = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = @(4624, 4625, 4648, 4672, 4688, 4720, 4726, 4740)
    StartTime = $inicio
} -MaxEvents 200 | ForEach-Object {
    [PSCustomObject]@{
        ID    = $_.Id
        Tempo = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        Msg   = ($_.Message -split "`n")[0]
    }
}

# ── Arquivos modificados recentemente ─────────────────────────────────────────
Write-Host "  Coletando arquivos modificados recentemente..." -ForegroundColor Gray
$alvos = @(
    $env:TEMP,
    'C:\Windows\System32',
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop"
)
$arquivos = foreach ($pasta in $alvos) {
    if (Test-Path $pasta) {
        try {
            Get-ChildItem $pasta -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $inicio } |
                Select-Object FullName, Length,
                    @{N='Modificado';E={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}} |
                Sort-Object Modificado -Descending |
                Select-Object -First 20
        } catch {}
    }
}

# ── Sessões de usuários ───────────────────────────────────────────────────────
Write-Host "  Coletando sessões de usuários..." -ForegroundColor Gray
$sessoes = query session 2>$null | Select-Object -Skip 1 | ForEach-Object {
    [PSCustomObject]@{ Sessao = $_.Trim() }
}

# ── Gerar relatório HTML ───────────────────────────────────────────────────────
function ConvertTo-HtmlTable($titulo, $dados, $campos) {
    if (-not $dados) { return "<section><h3>$titulo</h3><p class='empty'>Sem dados.</p></section>" }
    $ths = ($campos | ForEach-Object { "<th>$_</th>" }) -join ''
    $rows = ($dados | Select-Object -First 200 | ForEach-Object {
        $obj = $_
        $tds = ($campos | ForEach-Object {
            $v = ($obj.$_ ?? '—').ToString()
            if ($v.Length -gt 80) { $v = $v.Substring(0,80) + '…' }
            "<td>$([System.Web.HttpUtility]::HtmlEncode($v))</td>"
        }) -join ''
        "<tr>$tds</tr>"
    }) -join ''
    $cnt = @($dados).Count
    return "<section><h3>$titulo <span class='cnt'>($cnt)</span></h3><div class='tw'><table><thead><tr>$ths</tr></thead><tbody>$rows</tbody></table></div></section>"
}

$html = @"
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<title>IR Triage — $hostname</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#020c1b;color:#c9d1d9}
header{background:linear-gradient(135deg,#4a0000,#1a0a0a);border-bottom:1px solid #ef444433;padding:22px 32px}
header h1{font-size:1.4rem;color:#ef4444}header p{opacity:.7;margin-top:4px;font-size:.85rem;color:#fca5a5}
.banner{background:#7f1d1d;border:1px solid #ef444488;border-radius:8px;padding:12px 20px;
  margin:20px;font-size:.9rem;color:#fca5a5}
.container{max-width:1300px;margin:0 auto;padding:16px}
section{background:#0a1628;border:1px solid #ef444422;border-radius:8px;padding:16px 20px;margin-bottom:14px}
h3{font-size:.8rem;text-transform:uppercase;letter-spacing:.08em;color:#ef4444;
  margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid #ef444422}
.cnt{color:#7ecfff;font-weight:400}.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.76rem}
th{background:#1a0a0a;text-align:left;padding:7px 9px;color:#fca5a5;font-weight:500}
td{padding:6px 9px;border-bottom:1px solid #ffffff06;font-family:monospace}
tr:hover td{background:#0d1628}tr:last-child td{border:none}
.empty{color:#484f58;font-size:.83rem;padding:8px 0}
footer{text-align:center;padding:16px;color:#484f58;font-size:.73rem}
</style></head><body>
<header>
  <h1>⚠ Incident Response — Triage Report</h1>
  <p>Host: <strong>$hostname</strong> &nbsp;|&nbsp; Coletado: <strong>$geradoEm</strong>
     &nbsp;|&nbsp; Janela: últimos $MINUTOS minutos</p>
</header>
<div class="banner">Este relatório contém dados forenses coletados automaticamente. Preserve a evidência.</div>
<div class="container">
$(ConvertTo-HtmlTable 'Processos em Execução' $processos @('PID','Nome','CPU','RAM_MB','Caminho','SHA256'))
$(ConvertTo-HtmlTable 'Conexões TCP Ativas' $conexoes @('LocalAddr','LocalPort','RemoteAddr','RemotePort','Estado','Processo'))
$(ConvertTo-HtmlTable 'Entradas de Autorun' $autoruns @('Chave','Nome','Valor'))
$(ConvertTo-HtmlTable 'Eventos de Segurança' $eventos @('ID','Tempo','Msg'))
$(ConvertTo-HtmlTable 'Arquivos Modificados' $arquivos @('FullName','Length','Modificado'))
$(ConvertTo-HtmlTable 'Sessões de Usuários' $sessoes @('Sessao'))
</div>
<footer>Incident Response Toolkit · PowerShell · github.com/Luca-css/incident-response-toolkit · $geradoEm</footer>
</body></html>
"@

# ── Salvar arquivos ───────────────────────────────────────────────────────────
$base = Join-Path $saida "ir_${hostname}_${ts}"

$artefatos = [PSCustomObject]@{
    hostname        = $hostname
    geradoEm        = $geradoEm
    processos       = $processos
    conexoes        = $conexoes
    autoruns        = $autoruns
    eventos         = $eventos
    arquivos        = $arquivos
    sessoes         = $sessoes
}

$jsonPath = "$base.json"
$htmlPath = "$base.html"
$zipPath  = "$base.zip"

$artefatos | ConvertTo-Json -Depth 5 | Out-File $jsonPath -Encoding UTF8
$html | Out-File $htmlPath -Encoding UTF8

Compress-Archive -Path $jsonPath, $htmlPath -DestinationPath $zipPath -Force

Write-Host "`n  Processos coletados:  $(@($processos).Count)"
Write-Host "  Conexões TCP:         $(@($conexoes).Count)"
Write-Host "  Autoruns:             $(@($autoruns).Count)"
Write-Host "  Eventos recentes:     $(@($eventos).Count)"
Write-Host "  Arquivos modificados: $(@($arquivos).Count)"
Write-Host "`n  HTML: $htmlPath"
Write-Host "  JSON: $jsonPath"
Write-Host "  ZIP:  $zipPath`n"

try { Start-Process $htmlPath } catch {}
