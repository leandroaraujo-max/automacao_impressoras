# 🖨️ Gerenciador de Filas Enterprise (Print Queue Manager)

Ferramenta de automação desenvolvida em PowerShell com interface gráfica (WinForms) para padronização, migração de drivers, configuração em massa e gerenciamento de portas TCP/IP de filas de impressão em ambientes Windows Server.

## 🚀 Funcionalidades (Versão 12.0)

* **Migração de Drivers em Massa:** Substituição automatizada de drivers antigos (ex: Samsung) para novos padrões (ex: HP Universal Printing).
* **Clonagem de Configurações (PrintTicket):** Padronização de preferências do usuário (ex: forçar impressão Simplex, selecionar Bandeja 2, papel A4).
* **Configuração de Porta TCP/IP (RAW / LPR):** Alteração do protocolo de porta das filas diretamente nos servidores remotos.
  * **RAW:** Protocolo 9100, SNMP desativado.
  * **LPR:** Nome da fila LPR configurado automaticamente com o mesmo nome da impressora, LPR Byte Counting desativado.
* **Multi-Server via WinRM:** Disparo simultâneo de configurações para múltiplos Print Servers na rede com timeout configurado (15s conexão / 60s operação) — tolerante a instabilidades SD-WAN.
* **Arquitetura Anti-Freeze:** Timer assíncrono com `Invoke-Command -AsJob` garante que a interface nunca trava, mesmo com spoolers lentos.
* **Coleta Real de Resultados:** Cada job remoto tem seu resultado coletado via `Receive-Job`. A ListView exibe status real: verde (OK) ou vermelho (ERRO) por fila/servidor.
* **Auditoria Automática (CSV):** Log `Log_Gerenciador_YYYY-MM-DD.csv` gerado na pasta do script com schema completo: `Usuario, DataHora, Servidor, FilaImpressao, Acao, Status, Mensagem`.

## 📋 Pré-requisitos

* **Sistema Operacional:** Windows Server 2012 R2, 2016, 2019 ou 2022.
* **Privilégios:** Administrador Local na máquina de origem. Domain Admin recomendado para execução multi-servidor.
* **Rede:** WinRM (porta 5985) habilitado e acessível nos servidores de destino.
* **Porta TCP/IP:** Para uso da ação de configuração de porta, a fila deve utilizar uma porta do tipo TCP/IP padrão (Standard TCP/IP Port Monitor). Portas USB ou outros tipos são ignoradas sem erro.

## ⚙️ Instalação e Execução

1. Copie os arquivos para uma pasta na máquina de origem (ex: `C:\IT_Tools\GerenciadorFilas`).
2. A pasta deve conter os dois arquivos:
   * `parametrizar_filas_network.ps1` — código fonte
   * `Iniciar_Parametrizador.bat` — launcher com auto-elevação UAC
3. **NÃO execute o `.ps1` diretamente.**
4. Dê duplo clique em `Iniciar_Parametrizador.bat`. O launcher solicita elevação de privilégios (UAC) e faz bypass da ExecutionPolicy automaticamente.

## 🖥️ Como Utilizar (Guia Rápido)

1. **Seção 1 — Origem (Template):** Selecione na máquina local a fila modelo. Ela deve estar com driver correto, bandejas e preferências já configuradas.
2. **Seção 2 — Ações:** Marque o que deseja executar (combinações são permitidas):
   * *Aplicar Parametrização:* Copia PrintTicket (Bandeja, Simplex, A4).
   * *Alterar Driver:* Selecione o driver alvo no combo abaixo do checkbox.
   * *Configurar Tipo de Porta TCP/IP:* Escolha RAW (9100) ou LPR (fila = nome da impressora).
3. **Seção 3 — Destino:** Busque e marque as filas que receberão as ações. Os nomes são buscados nos servidores remotos pelo mesmo nome.
4. **Seção 4 — Servidores:** Cole os hostnames ou IPs dos Print Servers de destino (um por linha). Use `localhost` para testar localmente.
5. Clique em **DISPARAR AÇÕES SELECIONADAS** e acompanhe o resultado em tempo real no console interno.

## 📂 Arquivos Gerados

* **`Log_Gerenciador_YYYY-MM-DD.csv`** — Criado automaticamente na raiz do script. Contém auditoria completa de cada operação: usuário executor, servidor, fila, ação, status e mensagem de retorno do servidor remoto.

## 🔄 Histórico de Versões

| Versão | Data | Principais Mudanças |
|--------|------|---------------------|
| 12.0.0 | 2026-05-07 | Log CSV auditável; coleta real de resultados WinRM (Receive-Job); timeout de sessão WinRM; remoção do limite de 200 filas; configuração de porta TCP/IP (RAW/LPR); status visual real na ListView (OK/ERRO) |
| 11.0.0 | — | Separação de ações Driver vs Config; arquitetura Anti-Freeze com Timer |

---
*Desenvolvido para administração de infraestrutura de impressão em alta escala.*