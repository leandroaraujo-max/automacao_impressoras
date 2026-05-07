# 🖨️ Scanner de Impressoras de Rede

Kit de automação para inventário e diagnóstico de impressoras distribuídas nos Centros de Distribuição (CDs). Composto por um backend Flask em Python para descoberta ativa na rede e um script PowerShell para manutenção do mapeamento de endereçamento CIDR.

---

## 📦 Estrutura do Projeto

```
Impressoras/
├── scan_printers.py          # Backend Flask — scanner de rede
├── Templates/
│   ├── index.html            # Página inicial da interface web
│   ├── results.html          # Dashboard de resultados do scan
│   └── probe.html            # Página de diagnóstico de conectividade
└── Redes Imps CDS/
    ├── Atualizar-Redes.ps1                  # Script PowerShell de atualização DNS
    ├── Endereçamento de Rede CDS - Rede CDS.csv  # Planilha fonte de endereçamento
    └── Endereçamento_Atualizado.csv         # Lida pelo scanner (saída do PS1)
```

---

## 🚀 Componentes

### 1. `scan_printers.py` — Scanner Web (Flask + nmap + SNMP)

Backend web que realiza descoberta ativa de impressoras em todas as redes dos CDs.

**Fabricantes suportados:** HP, Samsung, Zebra, Honeywell

**O que coleta por impressora:**

| Campo | Descrição |
|-------|-----------|
| IP | Endereço IPv4 detectado |
| Fabricante | Identificado por banner HTTP/SNMP |
| Serial | Via SNMP — OID padrão `1.3.6.1.2.1.43.5.1.1.17.1`; para Zebra tenta `1.3.6.1.4.1.10642.1.9.0` e `1.3.6.1.4.1.683.6.2.3.2.1.6.1` |
| Contador | Páginas totais (somente laser HP/Samsung) via SNMP OID `1.3.6.1.2.1.43.10.2.1.4.1.1` |
| Tipo | `laser` ou `termica` |
| Filial | Número do CD (extraído do CSV) |
| Status | Estado do dispositivo |

**Parâmetros técnicos:**

- Scan de portas: `80, 443, 631, 9100` via nmap (`-T4 --open`)
- Concorrência: até 10 processos nmap simultâneos
- Timeout SNMP: 2 s por OID | Timeout HTTP: 3 s por requisição
- **Sem resolução DNS** — usa apenas CIDRs já preenchidos no CSV (IPs sem PTR reverso não causam falhas)
- Fonte de redes: lê `Redes Imps CDS/Endereçamento_Atualizado.csv` (gerado por `Atualizar-Redes.ps1`), colunas `Rede Imps Lasers`, `Rede imps Térmicas Mesa` e `Rede ImpsTérmicas WIFI`
- Interface web: `http://localhost:5001`

**Dashboard (`results.html`):**

- Botão **Parar Scan** — interrompe a varredura via `POST /scan/stop` (banner laranja ao parar)
- Resultados agrupados por CD com expand/colapso individual e botões globais
- Filtros em tempo real: IP, CD/Filial, Fabricante, Tipo, Serial
- Cards de totalizadores: Total, Laser, Térmica, CDs encontrados
- Sem limite de linhas — todas as impressoras encontradas são exibidas
- Ícone 🔍 em cada IP abre a página de diagnóstico `/probe?ip=X`

**Página de Diagnóstico (`probe.html` — rota `/probe`):**

Permite testar a conectividade e coletar informações detalhadas de qualquer IP antes ou depois do scan.

| Teste | O que verifica |
|-------|---------------|
| TCP 80 / 443 / 631 / 9100 | Se a porta está aberta e latência |
| HTTP (porta 80) | Status code, header `Server`, trecho do body, fabricante identificado |
| SNMP Serial RFC3805 | `1.3.6.1.2.1.43.5.1.1.17.1` — distingue timeout, noSuchObject, valor vazio |
| SNMP Contador | `1.3.6.1.2.1.43.10.2.1.4.1.1` |
| SNMP Zebra OID 1 | `1.3.6.1.4.1.10642.1.9.0` |
| SNMP Zebra OID 2 | `1.3.6.1.4.1.683.6.2.3.2.1.6.1` |

> Acesso direto: `http://localhost:5001/probe?ip=<endereço>`

---

### 2. `Redes Imps CDS/Atualizar-Redes.ps1` — Atualizador de Endereçamento

Script PowerShell que enriquece a planilha de endereçamento resolvendo hostnames para IPs e calculando as redes `/24` correspondentes.

**Colunas processadas:**

| Coluna DNS (entrada) | Coluna Rede (saída) | Tipo |
|----------------------|---------------------|------|
| DNS Imps Lasers | Rede Imps Lasers | Laser |
| DNS imps Térmicas Mesa | Rede imps Térmicas Mesa | Térmica |
| DNS imps Térmicas Mesa_1 | Rede ImpsTérmicas WIFI | Térmica Wi-Fi |

**Comportamento:**
- Trata colunas duplicadas no cabeçalho automaticamente (sufixo `_N`)
- Detecta delimitador automaticamente (`,` ou `;`)
- Resolução em dois passos: nome curto → FQDN com `.magazineluiza.intranet`
- Registra `DNS_NAO_ENCONTRADO` quando nenhuma tentativa resolve
- Não sobrescreve redes que já estão preenchidas na planilha fonte

---

## 📋 Pré-requisitos

### Scanner Web (`scan_printers.py`)

```bash
pip install flask pandas python-nmap pysnmp
```

| Dependência | Uso |
|-------------|-----|
| `flask` | Interface web |
| `pandas` | Leitura do CSV de endereçamento |
| `python-nmap` | Varredura de portas |
| `pysnmp` | Coleta de serial e contador (opcional — serial/contador ficam indisponíveis sem ela) |

> **nmap** deve estar instalado no sistema e acessível no PATH.

### Script PowerShell (`Atualizar-Redes.ps1`)

- PowerShell 5.1 ou superior
- Acesso DNS à intranet `.magazineluiza.intranet`
- Não requer módulos externos

---

## ⚙️ Como Usar

### Executar o scanner web

```bash
python scan_printers.py
```

Acesse `http://localhost:5001` no navegador. Clique em **Iniciar Scan** para disparar a varredura nas redes carregadas do CSV. Use o botão **Parar Scan** na tela de resultados para interromper a varredura a qualquer momento.

### Atualizar o endereçamento de rede

1. Abra a pasta `Redes Imps CDS\`
2. Execute `Atualizar-Redes.ps1` (duplo clique ou via PowerShell)
3. O arquivo `Endereçamento_Atualizado.csv` será gerado/atualizado na mesma pasta

> Execute a atualização de endereçamento sempre que CDs novos forem incluídos na planilha fonte ou quando o endereçamento IP de um CD for alterado.

---

## 📂 Arquivos de Saída

| Arquivo | Gerado por | Conteúdo |
|---------|-----------|---------|
| `Redes Imps CDS/Endereçamento_Atualizado.csv` | `Atualizar-Redes.ps1` | Planilha com colunas de rede preenchidas (CIDR /24) |

---

## 🛠️ Ambiente de Desenvolvimento

### Python

| Item | Detalhe |
|------|---------|
| Versão mínima | Python 3.10+ (testado em 3.14 64-bit) |
| Interpretador recomendado | `C:\Users\_araujo\AppData\Local\Python\pythoncore-3.14-64\python.exe` |
| Gerenciador de pacotes | `pip` (embutido) |

**Instalar todas as dependências:**

```powershell
& "C:\Users\_araujo\AppData\Local\Python\pythoncore-3.14-64\python.exe" -m pip install python-nmap flask pandas pysnmp
```

**Verificar instalação:**

```powershell
& "C:\Users\_araujo\AppData\Local\Python\pythoncore-3.14-64\python.exe" -c "import nmap, pandas, flask; print('OK')"
```

**Dependências completas (incluindo transitivas):**

| Pacote | Versão instalada | Finalidade |
|--------|-----------------|-----------|
| `python-nmap` | 0.7.1 | Wrapper do nmap para varredura de portas |
| `flask` | 3.1.3 | Servidor web / interface de usuário |
| `pandas` | 3.0.2 | Leitura e processamento do CSV de endereçamento |
| `pysnmp` | 7.1.26 | Coleta de serial e contador via SNMP (opcional) |
| `numpy` | 2.4.4 | Dependência do pandas |
| `werkzeug` | 3.1.8 | Servidor WSGI do Flask |
| `jinja2` | 3.1.6 | Engine de templates HTML |
| `pyasn1` | 0.6.3 | Dependência do pysnmp |

### nmap (obrigatório no sistema)

O `python-nmap` é apenas um wrapper — o binário `nmap` precisa estar instalado separadamente.

**Download:** https://nmap.org/download.html  
**Verificar instalação:**

```powershell
nmap --version
```

> Se `nmap` não estiver no PATH, adicione o diretório de instalação (ex: `C:\Program Files (x86)\Nmap`) à variável de ambiente `PATH`.

### PowerShell

| Item | Detalhe |
|------|---------|
| Versão mínima | PowerShell 5.1 |
| Módulos externos | Nenhum |
| Privilégios necessários | Usuário padrão (sem elevação) |
| Acesso de rede | DNS resolúvel para `.magazineluiza.intranet` |

### Editor recomendado

- **VS Code** com as extensões:
  - `ms-python.python` — suporte Python / IntelliSense
  - `ms-vscode.powershell` — suporte PowerShell

### Executar em desenvolvimento

```powershell
# A partir da raiz do projeto
cd "C:\Projetos\Impressoras"
& "C:\Users\_araujo\AppData\Local\Python\pythoncore-3.14-64\python.exe" scan_printers.py
```

O Flask sobe em `http://127.0.0.1:5001` com `use_reloader=False` (evita dupla inicialização no Windows).

---

*Desenvolvido para inventário de infraestrutura de impressão em ambientes multi-CD.*