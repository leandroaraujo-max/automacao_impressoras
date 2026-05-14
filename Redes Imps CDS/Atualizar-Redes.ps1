# =================================================================================
# Script:       Atualizar-Redes.ps1 (Versão com Sufixo DNS Automático)
# Descrição:    Resolve nomes curtos e FQDNs (.magazineluiza.intranet)
# =================================================================================

$caminhoArquivoEntrada = Join-Path $PSScriptRoot "Endereçamento de Rede CDS - Rede CDS.csv"
$caminhoArquivoSaida = Join-Path $PSScriptRoot "Endereçamento_Atualizado.csv"
$sufixoDNS = ".magazineluiza.intranet"

if (-not (Test-Path $caminhoArquivoEntrada)) {
    Write-Host "ERRO: Arquivo de entrada não encontrado." -ForegroundColor Red
    exit
}

try {
    Write-Host "Iniciando atualização com tentativa de sufixo $sufixoDNS..." -ForegroundColor Cyan

    # Trata colunas duplicadas
    $linhas = Get-Content -Path $caminhoArquivoEntrada -Encoding UTF8
    $delimitador = if ($linhas[0] -match ";") { ";" } else { "," }
    $cabecalhoOriginal = $linhas[0] -split $delimitador
    $novoCabecalho = @()
    $contagem = @{}

    foreach ($col in $cabecalhoOriginal) {
        $colLimpa = $col.Replace('"','')
        if ($contagem.ContainsKey($colLimpa)) {
            $contagem[$colLimpa]++
            $novoCabecalho += "$colLimpa`_$($contagem[$colLimpa])"
        } else {
            $contagem[$colLimpa] = 0
            $novoCabecalho += $colLimpa
        }
    }

    $linhas[0] = $novoCabecalho -join $delimitador
    $dados = $linhas | ConvertFrom-Csv -Delimiter $delimitador

    $colunasParaProcessar = @(
        @{ Dns = "DNS Imps Lasers";         Rede = "Rede Imps Lasers" },
        @{ Dns = "DNS imps Térmicas Mesa";  Rede = "Rede imps Térmicas Mesa" },
        @{ Dns = "DNS imps Térmicas Mesa_1"; Rede = "Rede ImpsTérmicas WIFI" } 
    )

    foreach ($linha in $dados) {
        Write-Host "Processando CD $($linha.CD)..." -ForegroundColor White

        foreach ($par in $colunasParaProcessar) {
            $colDns = $par.Dns
            $colRede = $par.Rede
            $nomeBusca = $linha.$colDns

            if (-not [string]::IsNullOrWhiteSpace($nomeBusca) -and [string]::IsNullOrWhiteSpace($linha.$colRede)) {
                $ipResolvido = $null
                
                # TENTATIVA 1: Nome Curto
                try {
                    $ipResolvido = [System.Net.Dns]::GetHostAddresses($nomeBusca) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
                } catch {
                    # TENTATIVA 2: Com Sufixo Intranet
                    try {
                        $nomeCompleto = "$nomeBusca$sufixoDNS"
                        $ipResolvido = [System.Net.Dns]::GetHostAddresses($nomeCompleto) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
                    } catch { $ipResolvido = $null }
                }

                if ($ipResolvido) {
                    $ipString = $ipResolvido.IPAddressToString
                    $octetos = $ipString.Split('.')
                    $rede = "$($octetos[0]).$($octetos[1]).$($octetos[2]).0/24"
                    $linha.$colRede = $rede
                    Write-Host "    [OK] $nomeBusca -> $ipString -> $rede" -ForegroundColor Green
                } else {
                    $linha.$colRede = "DNS_NAO_ENCONTRADO"
                    Write-Host "    [FALHA] $nomeBusca (mesmo com sufixo)" -ForegroundColor Red
                }
            }
        }
    }

    $dados | Export-Csv -Path $caminhoArquivoSaida -NoTypeInformation -Encoding UTF8 -Delimiter $delimitador
    Write-Host "`nSucesso! Verifique o arquivo: $caminhoArquivoSaida" -ForegroundColor Cyan
}
catch {
    Write-Host "Erro crítico: $($_.Exception.Message)" -ForegroundColor Red
}

Read-Host "`nPressione Enter para fechar..."
