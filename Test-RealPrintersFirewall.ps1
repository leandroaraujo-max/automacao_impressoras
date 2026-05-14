<#
    .SYNOPSIS
    Validador de Conectividade em Massa usando IPs reais do inventário (impressoras.csv).
#>

param (
    [string]$CsvPath = "C:\Projetos\Impressoras\impressoras.csv",
    [int]$AmostrasPorTipoPorCD = 2,
    [int]$TimeoutMs = 2000
)

Write-Host "Lendo arquivo de inventário: $CsvPath" -ForegroundColor Cyan
if (-not (Test-Path $CsvPath)) {
    Write-Host "ERRO: Arquivo CSV não encontrado!" -ForegroundColor Red
    exit
}

$CsvData = Import-Csv $CsvPath -Encoding UTF8

# Agrupando por Filial (CD) e Tipo (Laser/Térmica) para pegar uma amostra de IPs reais
$TargetPrinters = @()
$Groups = $CsvData | Group-Object filial, tipo

foreach ($Group in $Groups) {
    # Seleciona até N impressoras reais de cada tipo em cada CD
    $TargetPrinters += $Group.Group | Select-Object -First $AmostrasPorTipoPorCD
}

Write-Host "Encontradas $($TargetPrinters.Count) impressoras para amostragem representativa. Iniciando testes..." -ForegroundColor Yellow

[byte[]]$SnmpPayload = 0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02, 0x04, 0x01, 0x02, 0x03, 0x04, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00

$Results = @()

foreach ($Printer in $TargetPrinters) {
    $IP = $Printer.ip
    $CD = $Printer.filial
    $Tipo = $Printer.tipo
    $Fab = $Printer.fabricante

    Write-Host "Testando [CD $CD] $IP ($Fab - $Tipo) ..." -ForegroundColor Gray
    
    $HostResult = [PSCustomObject]@{
        CD           = $CD
        Fabricante   = $Fab
        Tipo         = $Tipo
        HostIP       = $IP
        TCP_80_HTTP  = "Timeout/Drop"
        TCP_443_HTTPS= "Timeout/Drop"
        TCP_9100_RAW = "Timeout/Drop"
        UDP_161_SNMP = "Timeout/Drop"
    }

    # 1. Testes TCP (Fail-Fast via Async Wait)
    $TcpPorts = @(80, 443, 9100)
    foreach ($Port in $TcpPorts) {
        $PropertyName = if ($Port -eq 80) { "TCP_80_HTTP" } elseif ($Port -eq 443) { "TCP_443_HTTPS" } else { "TCP_9100_RAW" }
        
        try {
            $TcpClient = New-Object System.Net.Sockets.TcpClient
            $ConnectTask = $TcpClient.BeginConnect($IP, $Port, $null, $null)
            $Wait = $ConnectTask.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
            
            if ($Wait -and $TcpClient.Connected) {
                $HostResult.$PropertyName = "Aberta"
            } elseif ($Wait -and -not $TcpClient.Connected) {
                $HostResult.$PropertyName = "Recusada (Reject)"
            }
        } catch {
            $HostResult.$PropertyName = "Erro/Timeout"
        } finally {
            if ($null -ne $TcpClient) { $TcpClient.Close() ; $TcpClient.Dispose() }
        }
    }

    # 2. Teste UDP (SNMP)
    try {
        $UdpClient = New-Object System.Net.Sockets.UdpClient
        $UdpClient.Client.ReceiveTimeout = $TimeoutMs
        $UdpClient.Connect($IP, 161)
        
        # Envia pacote SNMP
        [void]$UdpClient.Send($SnmpPayload, $SnmpPayload.Length)
        
        $SenderEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $ReceiveBytes = $UdpClient.Receive([ref]$SenderEp)
        
        if ($ReceiveBytes.Length -gt 0) {
            $HostResult.UDP_161_SNMP = "Respondendo (OK)"
        }
    } catch {
        if ($_.Exception.InnerException -is [System.Net.Sockets.SocketException]) {
            if ($_.Exception.InnerException.SocketErrorCode -eq 'TimedOut') {
                $HostResult.UDP_161_SNMP = "Timeout/Drop"
            } else {
                $HostResult.UDP_161_SNMP = "Erro"
            }
        } else {
            $HostResult.UDP_161_SNMP = "Erro/Bloqueado"
        }
    } finally {
        if ($null -ne $UdpClient) { $UdpClient.Close() ; $UdpClient.Dispose() }
    }

    $Results += $HostResult
}

# Exportar Resultado
$LogPath = Join-Path $PWD "Report_Firewall_RealIPs_$((Get-Date).ToString('yyyyMMdd_HHmm')).csv"
$Results | Export-Csv -Path $LogPath -NoTypeInformation -Encoding UTF8
Write-Host "`n==== CONCLUÍDO ====" -ForegroundColor Green
Write-Host "Foram geradas $($Results.Count) linhas de evidência usando IPs reais."
Write-Host "Relatório salvo em: $LogPath" -ForegroundColor Cyan