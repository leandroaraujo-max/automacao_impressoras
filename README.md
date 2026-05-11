# 🖨️ Scanner de Impressoras de Rede — Automação de Inventário CDs

Kit de automação para inventário e diagnóstico de impressoras distribuídas nos Centros de Distribuição (CDs) Magazine Luiza. Descobre ativamente impressoras via nmap, coleta modelo, serial, contadores e consumíveis por fabricante (HP, Samsung, Zebra, Honeywell), gera um inventário HTML estático, serve um painel web em tempo real e permite configurar credenciais e aplicar DNS remotamente.

---

## Índice

1. [Requisitos do Sistema](#-requisitos-do-sistema)
2. [Estrutura do Projeto](#-estrutura-do-projeto)
3. [Uso Rápido](#-uso-rápido)
4. [Funcionalidades](#-funcionalidades)
5. [Fluxo de Execução](#-fluxo-de-execução)
6. [API Flask — Referência de Rotas](#-api-flask--referência-de-rotas)
7. [Modelo de Dados](#-modelo-de-dados--printerinfo)
8. [Referência de OIDs SNMP](#-referência-de-oids-snmp)
9. [CSV de Endereçamento](#-csv-de-endereçamento)
10. [Constantes Configuráveis](#-constantes-configuráveis)
11. [Referência de Funções](#-referência-de-funções)
12. [Acesso de Rede e Firewall](#-acesso-de-rede-e-firewall)

---

## 💻 Requisitos do Sistema

Esta seção detalha **todos** os pré-requisitos que devem ser atendidos antes de executar o scanner em qualquer máquina, seja em ambiente de desenvolvimento ou produção.

---

### 1. Sistema Operacional

| Requisito | Detalhe |
|-----------|---------|
| **SO** | Windows 10 ou Windows 11 (64-bit) |
| **Privilégios** | Conta de usuário comum é suficiente para rodar o scanner. Para criar regras de firewall é necessário `Executar como Administrador`. |

> **Nota:** O script foi desenvolvido e testado exclusivamente em Windows. Adaptações são necessárias para Linux/macOS (caminhos de arquivo, instalação do nmap, comandos de firewall).

---

### 2. Python

O scanner requer **Python 3.10 ou superior**, versão **64-bit**.

#### Download

- Site oficial: https://www.python.org/downloads/
- Testado com: `Python 3.14.0a7 (64-bit)` em `C:\Users\_araujo\AppData\Local\Python\pythoncore-3.14-64\`

#### Instalação recomendada (Windows)

1. Baixe o instalador `.exe` de https://www.python.org/downloads/
2. Na tela de instalação, marque **"Add Python to PATH"** obrigatoriamente
3. Escolha **"Install Now"** (instalação padrão) ou "Customize installation" — ambas funcionam

#### Verificar instalação

```powershell
python --version
# Saída esperada: Python 3.14.x  (ou 3.10, 3.11, 3.12, 3.13)
python -c "import sys; print(sys.maxsize > 2**32)"
# Saída esperada: True  ← confirma 64-bit
```

> Se o comando `python` não for reconhecido, adicione o diretório do Python manualmente ao `PATH` do sistema em  
> **Painel de Controle → Sistema → Variáveis de Ambiente → Path**.

---

### 3. nmap (Obrigatório)

O nmap é o engine de descoberta de rede. **Sem ele, o scan de novas impressoras não funciona.** Os modos `--update` e `--probe-only` funcionam sem nmap (usam apenas o cache existente).

#### Download

- Site oficial: https://nmap.org/download.html
- Escolha o instalador **"Latest stable release self-installer"** para Windows (ex: `nmap-7.95-setup.exe`)

#### Instalação

1. Execute o instalador como Administrador
2. Aceite os padrões — o instalador adiciona o nmap ao PATH automaticamente
3. Reinicie o terminal após a instalação

#### Verificar instalação

```powershell
nmap --version
# Saída esperada: Nmap version 7.95 ( https://nmap.org )
```

> **Importante:** O nmap no Windows executa com permissões de rede elevadas internamente (usa pacotes raw). Se surgir o erro `Failed to open device` durante o scan, execute o terminal como Administrador.

#### Alternativa — Npcap

Durante a instalação do nmap, a opção de instalar o **Npcap** (driver de captura de pacotes) é apresentada. **Deixe marcada** — sem o Npcap, o nmap no Windows pode não conseguir realizar scans em algumas redes.

---

### 4. Pacotes Python

Instale todas as dependências com um único comando:

```powershell
pip install flask pandas python-nmap pysnmp
```

Caso a máquina tenha múltiplos Pythons instalados, especifique o executável desejado:

```powershell
# Exemplo com Python 3.14 em path específico
C:\Users\_araujo\AppData\Local\Python\pythoncore-3.14-64\python.exe -m pip install flask pandas python-nmap pysnmp
```

#### Tabela de dependências

| Pacote | Versão testada | Obrigatório | Uso no projeto |
|--------|---------------|-------------|----------------|
| `flask` | 3.1.3 | **Sim** | Servidor web HTTP na porta 5001; rotas da API REST; serviço do painel `/results` e `/probe` |
| `pandas` | 3.0.2 | **Sim** | Leitura e parsing do CSV de endereçamento de redes por CD |
| `python-nmap` | 0.7.1 | **Sim** | Wrapper Python do executável `nmap`; realiza scan de portas 80/443/631/9100 em cada rede CIDR |
| `pysnmp` | 7.1.26 | Recomendado | SNMP GET de alto nível via `pysnmp.hlapi`; o script possui fallback BER puro-Python se não instalado |

> **Sobre o `pysnmp`:** Sem ele, o script usa uma implementação SNMP própria em Python puro (`_snmp_get_raw`). O fallback funciona para a maioria dos casos, mas pode ter comportamentos diferentes com impressoras que usam variantes não-padrão do protocolo SNMP v1. **Recomenda-se instalar o `pysnmp`.**

#### Verificar instalação dos pacotes

```powershell
pip show flask pandas python-nmap pysnmp
```

---

### 5. Conectividade de Rede

O scanner precisa de acesso de rede direto (Layer 3) às sub-redes das impressoras. Verifique:

#### 5.1 Roteamento até as redes dos CDs

O PC que executa o scanner deve ter **rota de rede** para cada CIDR listado no CSV. Isso normalmente é garantido pela VPN corporativa ou por ser uma máquina na mesma rede da infraestrutura.

```powershell
# Testar conectividade com um IP de impressora de um CD
ping 10.70.82.10

# Verificar tabela de rotas
route print | Select-String "10.70"
```

#### 5.2 Portas que devem estar abertas nas impressoras

| Porta | Protocolo | Uso |
|-------|-----------|-----|
| **80** | TCP (HTTP) | Interface web EWS (HP), SyncThru (Samsung), ZebraNet (Zebra) |
| **443** | TCP (HTTPS) | Interface web com SSL auto-assinado (principalmente HP) |
| **631** | TCP (IPP) | Internet Printing Protocol — scan de descoberta |
| **9100** | TCP (JetDirect / ZPL) | Impressão RAW / identificação por banner |
| **161** | **UDP** (SNMP) | Coleta de serial, contador de páginas, toner, modelo |

> **Atenção ao SNMP (UDP 161):** Firewalls de borda costumam bloquear UDP. Se as impressoras respondem ao ping mas o SNMP não retorna dados, verifique se UDP/161 está liberado entre o PC e as redes de impressoras.

#### 5.3 Community SNMP

O script usa **SNMP v1** com community `public` (somente leitura). As impressoras devem estar configuradas com:

- Community read-only: `public`
- SNMP v1 habilitado (ou v2c — ambas funcionam com os OIDs utilizados)

> A community de escrita (`SNMP_WRITE_COMMUNITY`) é usada apenas na função `apply_dns_config` para configurar DNS via SNMP SET em impressoras HP. O valor padrão também é `public` — altere a constante no script se necessário.

---

### 6. Arquivos Necessários na Pasta do Projeto

Antes de executar o scanner pela primeira vez, confirme que os seguintes arquivos existem:

| Arquivo | Obrigatório | Descrição |
|---------|------------|-----------|
| `scan_printers.py` | **Sim** | Script principal |
| `Redes Imps CDS/Endereçamento_Atualizado.csv` | **Sim** | CSV com redes CIDR por CD |
| `Templates/inventory_template.html` | **Sim** | Template do inventário estático |
| `Templates/results.html` | **Sim** | Dashboard de scan ao vivo |
| `Templates/probe.html` | **Sim** | Página de diagnóstico individual |
| `cache.json` | Não (gerado automaticamente) | Cache incremental de impressoras |
| `inventory.html` | Não (gerado automaticamente) | Inventário estático gerado |
| `printer_credentials.json` | Não (gerado automaticamente) | Credenciais manuais por IP |

> **`cache.json`** é criado automaticamente no primeiro scan. **`printer_credentials.json`** é criado automaticamente ao salvar credenciais pelo modal da interface.

---

### 7. Resumo — Checklist de Instalação

Execute esta lista em ordem antes de rodar o scanner em uma máquina nova:

```powershell
# [1] Verificar Python 3.10+ 64-bit instalado e no PATH
python --version

# [2] Verificar nmap instalado e no PATH
nmap --version

# [3] Instalar dependências Python
pip install flask pandas python-nmap pysnmp

# [4] Verificar sintaxe do script (deve retornar sem erros)
cd "C:\Projetos\Impressoras"
python -m py_compile scan_printers.py

# [5] Verificar que o CSV de redes existe
Test-Path "Redes Imps CDS\Endereçamento_Atualizado.csv"
# Saída esperada: True

# [6] Verificar conectividade com ao menos um IP de impressora
ping 10.70.82.10   # substitua pelo IP real de uma impressora

# [7] (Opcional) Verificar SNMP em uma impressora
# O nmap pode testar a porta UDP 161:
nmap -sU -p 161 10.70.82.10
```

---

## 📦 Estrutura do Projeto

```
Impressoras/
├── scan_printers.py                     # Backend principal — scanner + API Flask
├── cache.json                           # Cache incremental (gerado automaticamente)
├── inventory.html                       # Inventário HTML estático (gerado automaticamente)
├── printer_credentials.json             # Credenciais manuais por IP (gerado automaticamente)
├── Templates/
│   ├── inventory_template.html          # Template injetado com dados do scan → inventory.html
│   ├── results.html                     # Dashboard de scan ao vivo
│   └── probe.html                       # Diagnóstico de conectividade individual
└── Redes Imps CDS/
    ├── Atualizar-Redes.ps1              # Script PowerShell de atualização do CSV de endereçamento
    ├── Endereçamento de Rede CDS - Rede CDS.csv   # Planilha fonte (editada manualmente)
    └── Endereçamento_Atualizado.csv     # Lida pelo scanner (colunas: CD, Range 01..16)
```

---

## 🚀 Uso Rápido

```powershell
cd "C:\Projetos\Impressoras"

# Scan completo — descobre novas impressoras + atualiza cache
python scan_printers.py

# Apenas atualiza contadores/consumíveis sem novo scan nmap (mais rápido)
python scan_printers.py --update

# Apenas o servidor Flask de probe/inventário (sem varredura de rede)
python scan_printers.py --probe-only
```

Após iniciar, acesse:
- **Painel ao vivo:** `http://localhost:5001/results`
- **Inventário estático:** abra o arquivo `inventory.html` diretamente no navegador
- **Diagnóstico:** `http://localhost:5001/probe`

> O servidor Flask fica disponível em `http://0.0.0.0:5001`. Para acesso de outras máquinas da rede, veja a seção [Acesso de Rede e Firewall](#-acesso-de-rede-e-firewall).

---

## ✨ Funcionalidades

### Inventário Estático (`inventory.html`)

Arquivo HTML auto-contido gerado pelo script. Pode ser aberto diretamente no navegador **sem** o Flask estar em execução — mas algumas funcionalidades dinâmicas (probe, aplicação de DNS, exportação CSV, modal de credenciais) requerem que o Flask esteja rodando em `localhost:5001`.

**Recursos:**

| Funcionalidade | Descrição |
|---------------|-----------|
| Sidebar de CDs | Lista lateral com contador de impressoras por CD; campo de busca para filtrar |
| Filtros em tempo real | Busca por IP, fabricante, modelo, serial, hostname |
| Cards de totalizadores | Total, Laser, Térmica, CDs |
| Tabela de impressoras | Todas as colunas coletadas, com badges coloridos por fabricante e alertas de toner baixo |
| **↓ Exportar CSV** | Botão na topbar — exporta impressoras do CD ativo (ou todos) via `/api/export-csv` |
| **🔑 Ícone de auth** | Ícone por impressora: verde = login HTTP OK, vermelho = falha, cinza = não tentado |
| **Modal de credenciais** | Clique no 🔑 para abrir formulário com IP/Fabricante + usuário/senha; "Salvar e Testar" aplica imediatamente |
| Probe individual | Ícone 🔍 por IP abre diagnóstico completo em nova aba |
| Aplicação de DNS em lote | Botão no topbar aplica DNS target a todas as impressoras do CD via `/api/apply-dns` |
| Coluna DNS Apply Status | Resultado da última aplicação de DNS (`OK`, `FALHOU`, etc.) |

### Painel ao Vivo (`/results`)

Dashboard com polling em tempo real durante o scan.

| Funcionalidade | Descrição |
|---------------|-----------|
| Progresso do scan | Barra de progresso com redes concluídas/total e impressoras encontradas |
| Auto-refresh | Polling a cada 5 s durante scan; reload automático ao finalizar |
| Botão Parar Scan | Interrompe a varredura via `POST /scan/stop` |
| Resultados por CD | Grupos expansíveis por CD |
| Exportar CSV | Botão para download do CSV com impressoras descobertas |

### Rastreamento de Autenticação HTTP

O scanner tenta autenticação HTTP (Basic Auth) na interface web de cada impressora para coletar configurações de rede (DNS, hostname, gateway) que não estão disponíveis via SNMP somente.

| Status | Significado |
|--------|-------------|
| `auth_ok = None` | SNMP foi suficiente; login HTTP não foi necessário ou não tentado |
| `auth_ok = False` | Login HTTP tentado com todas as credenciais conhecidas — todas falharam |
| `auth_ok = True` | Login HTTP bem-sucedido; `auth_user` indica o usuário que funcionou |

### Credenciais Manuais (`printer_credentials.json`)

Quando as credenciais padrão não funcionam, o usuário pode inserir credenciais específicas por impressora diretamente no modal da interface. As credenciais são:

1. Salvas em `printer_credentials.json` (formato: `{ "IP": { "user": "...", "password": "..." } }`)
2. Usadas com **prioridade máxima** nas próximas tentativas de autenticação HTTP para aquele IP
3. Testadas imediatamente ao salvar — o resultado (auth_ok, dns1, dns2) é mostrado no modal

### Aplicação de DNS Remota

Permite configurar DNS primário e secundário em impressoras HP e Samsung diretamente pelo painel, sem acesso físico.

| Fabricante | Método de aplicação |
|-----------|-------------------|
| HP | SNMP SET via JetDirect MIB → EWS JSON API → SyncThru (fallback em cascata) |
| Samsung | SyncThru Web Service HTTP POST |
| Zebra | HTTP POST em `/server/NWSET.htm` (via credenciais) |
| Honeywell | Não suportado (manual) |

---

## ⚙️ Fluxo de Execução

```
python scan_printers.py
│
├── [1] load_network_entries()        — lê CSV → lista de {network, cd}
├── [2] load_cache()                  — carrega cache.json existente
│
├── Fase A — hosts CONHECIDOS (paralelo, sem nmap)
│   └── update_metrics_from_cache()  — atualiza contador/toner/modelo/rede por IP
│       ├── get_page_count()          — páginas (laser) ou odômetro (Zebra)
│       ├── get_hp_consumables()      — toner + kit manutenção (%)
│       ├── get_samsung_consumables() — toner + unidade de imagem (%)
│       ├── get_zebra_odometer()      — polegadas da cabeça de impressão
│       ├── get_model()               — somente se modelo atual é inválido
│       └── get_network_config()      — DNS/hostname se dns1 ausente
│
├── save_cache()                      — salva após fase A
│
├── Fase B — hosts NOVOS (nmap paralelo por rede)
│   └── scan_network()
│       ├── nmap.scan()               — descobre IPs com portas 80/443/631/9100 abertas
│       ├── detect_manufacturer()     — SNMP → HTTP → banner TCP 9100
│       ├── get_serial()
│       ├── get_model()
│       ├── get_page_count() / get_zebra_odometer()
│       ├── get_hp_consumables() / get_samsung_consumables()
│       └── get_network_config()      — DNS/hostname/gateway/ip_mode
│
├── save_cache()                      — salva após fase B (incremental a cada rede)
│
├── generate_inventory_html()         — injeta dados no template → inventory.html
└── Flask serve :5001                 — regenera HTML a cada /results a partir do cache
```

---

## 🌐 API Flask — Referência de Rotas

| Método | Rota | Descrição |
|--------|------|-----------|
| `GET` | `/results` | Regenera `inventory.html` a partir do cache e serve |
| `GET` | `/probe` | Página HTML de diagnóstico individual |
| `GET` | `/api/status` | JSON com status do scan (`running`, `total`, `networks_done`, `networks_total`, `started_at`, `finished_at`) |
| `GET` | `/api/cds` | JSON com lista de CDs disponíveis no cache |
| `GET` | `/api/cd/<cd>` | JSON com impressoras de um CD específico |
| `GET` | `/api/probe?ip=<ip>` | JSON com resultado completo de diagnóstico (portas TCP, HTTP, 10 OIDs SNMP) |
| `GET` | `/api/export-csv?cd=<cd>` | Download CSV das impressoras (parâmetro `cd` opcional; sem ele exporta tudo) |
| `POST` | `/api/set-credentials` | Salva credenciais de uma impressora e retesta conexão imediatamente |
| `POST` | `/api/apply-dns` | Aplica DNS em lote em um CD ou em IPs específicos |
| `POST` | `/scan/stop` | Interrompe o scan em andamento |

#### `POST /api/set-credentials` — Corpo da requisição

```json
{
  "ip": "10.70.82.15",
  "user": "admin",
  "password": "simpress1934@"
}
```

**Resposta de sucesso:**

```json
{
  "ok": true,
  "auth_ok": true,
  "auth_user": "admin",
  "dns1": "10.70.1.10",
  "dns2": "10.70.1.11",
  "netcfg": { "hostname": "HP-Laser-CD350", "gateway": "10.70.82.1", ... }
}
```

#### `GET /api/export-csv` — Campos do CSV

| Campo | Tipo | Descrição |
|-------|------|-----------|
| `ip` | string | Endereço IPv4 |
| `filial` | string | Número do CD |
| `fabricante` | string | HP / Samsung / Zebra / Honeywell |
| `modelo` | string | Modelo detectado |
| `serial` | string | Número de série |
| `tipo` | string | laser / termica |
| `metrica` | string | Páginas ou polegadas |
| `toner` | string | Nível de toner (%) |
| `consumivel2` | string | Kit manutenção ou unidade de imagem (%) |
| `hostname` | string | Nome do host na rede |
| `dns1` | string | DNS primário configurado |
| `dns2` | string | DNS secundário configurado |
| `gateway` | string | Gateway padrão |
| `ip_mode` | string | DHCP / Manual / AutoIP |
| `status` | string | Online |
| `first_seen` | string | ISO datetime do primeiro scan |
| `last_updated` | string | ISO datetime da última atualização |
| `dns_apply_status` | string | Resultado da última aplicação de DNS |
| `auth_ok` | bool/null | Status de autenticação HTTP |
| `auth_user` | string | Usuário que autenticou com sucesso |

---

## 📊 Modelo de Dados — `PrinterInfo`

Dataclass Python que representa uma impressora no cache e na API.

```python
@dataclass
class PrinterInfo:
    # Identificação básica
    ip:           str          # Endereço IPv4
    fabricante:   str          # HP | Samsung | Zebra | Honeywell | Desconhecido
    modelo:       Optional[str]  # Modelo do equipamento (HTTP ou SNMP)
    serial:       str          # Número de série
    tipo:         str          # 'laser' | 'termica'
    filial:       str          # Número do CD (ex: '350')
    status:       str          # 'Online'

    # Métricas de uso
    metrica:      Optional[str]  # Páginas impressas (laser) | Polegadas cabeça (Zebra)
    toner:        Optional[str]  # Nível de toner em % (laser HP/Samsung)
    consumivel2:  Optional[str]  # Kit manutenção % (HP) | Unidade de imagem % (Samsung)

    # Auditoria de tempo
    first_seen:   str          # ISO datetime do primeiro scan
    last_updated: str          # ISO datetime da última atualização de métricas

    # Configuração de rede (coletada via HTTP/SNMP)
    hostname:     Optional[str] = None
    dns1:         Optional[str] = None
    dns2:         Optional[str] = None
    gateway:      Optional[str] = None
    ip_mode:      Optional[str] = None   # 'DHCP' | 'Manual' | 'AutoIP'

    # Status de aplicação de DNS
    dns_apply_status: Optional[str] = None

    # Autenticação HTTP
    auth_ok:      Optional[bool] = None  # True=OK | False=falhou | None=não tentado
    auth_user:    Optional[str]  = None  # Usuário que autenticou com sucesso
```

---

## 📡 Referência de OIDs SNMP

### Padrão (RFC 3805 / RFC 1213)

| OID | Descrição |
|-----|-----------|
| `1.3.6.1.2.1.43.5.1.1.17.1` | Serial (padrão impressoras) |
| `1.3.6.1.2.1.43.10.2.1.4.1.1` | Contador de páginas |
| `1.3.6.1.2.1.25.3.2.1.3.1` | Modelo genérico (hrDeviceDescr) |
| `1.3.6.1.2.1.43.5.1.1.16.1` | Modelo genérico (prtGeneralPrinterName) |
| `1.3.6.1.2.1.1.5.0` | Hostname (sysName — RFC 1213) |

### HP JetDirect MIB

| OID | Descrição |
|-----|-----------|
| `1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.3.0` | Modelo HP |
| `1.3.6.1.4.1.11.2.3.9.4.2.1.1.5.28.1` | Toner preto (%) |
| `1.3.6.1.4.1.11.2.3.9.4.2.1.1.5.28.5` | Kit de manutenção (%) |
| `1.3.6.1.4.1.11.2.4.3.5.2.0` | Hostname |
| `1.3.6.1.4.1.11.2.4.3.5.29.0` | DNS primário |
| `1.3.6.1.4.1.11.2.4.3.5.30.0` | DNS secundário |
| `1.3.6.1.4.1.11.2.4.3.5.20.0` | Gateway padrão |
| `1.3.6.1.4.1.11.2.4.3.5.16.0` | Modo IP (1=DHCP, 2=Manual) |

### Samsung CLX/SL MIB

| OID | Descrição |
|-----|-----------|
| `1.3.6.1.4.1.236.11.5.1.1.1.1.0` | Modelo Samsung |
| `1.3.6.1.4.1.236.11.5.11.81.1.1.1.20.1` | Toner (%) |
| `1.3.6.1.4.1.236.11.5.11.81.1.1.1.40.1` | Unidade de imagem (%) |

### Zebra MIBs

| OID | MIB | Descrição |
|-----|-----|-----------|
| `1.3.6.1.4.1.10642.1.9.0` | ZebraNet | Serial (modelos ZT/ZD/ZQ) |
| `1.3.6.1.4.1.683.6.2.3.2.1.6.1` | Eltron/legado | Serial (modelos GK/LP) |
| `1.3.6.1.4.1.10642.1.1.7.0` | ZebraNet | Modelo |
| `1.3.6.1.4.1.10642.1.1.8.0` | ZebraNet | Odômetro em dots (÷ 203 = polegadas) |
| `1.3.6.1.4.1.683.6.2.3.6.1.2.1` | Eltron/legado | Odômetro já em polegadas |

### Honeywell/Intermec

| OID | Descrição |
|-----|-----------|
| `1.3.6.1.4.1.1248.1.1.3.1.3.0` | Modelo Honeywell |

---

## 📂 CSV de Endereçamento

**Arquivo:** `Redes Imps CDS/Endereçamento_Atualizado.csv`

**Formato esperado:**

```csv
CD,Range 01,Range 02,Range 03,...,Range 16
350,10.70.82.0/24,10.70.85.0/24,10.70.73.0/24,
490,10.60.217.0/24,10.60.220.0/24,,,
```

- Coluna `CD` deve conter o número do CD (ex: `350`, `490`)
- Colunas `Range 01` até `Range 16` contêm redes CIDR (ex: `10.70.82.0/24`)
- Células vazias ou com `nan` são ignoradas automaticamente
- CIDRs malformados geram aviso no log e são ignorados (não interrompem o scan)
- O scanner detecta as colunas `Range XX` dinamicamente — nome exato não precisa ser `Range 01`, desde que comece com a palavra `range` (case-insensitive)

**Como atualizar o CSV:**

```powershell
# Script PowerShell que atualiza o CSV a partir da planilha fonte
cd "C:\Projetos\Impressoras\Redes Imps CDS"
.\Atualizar-Redes.ps1
```

---

## 🔧 Constantes Configuráveis

Abra `scan_printers.py` e ajuste as constantes no topo do arquivo conforme o ambiente:

| Constante | Valor padrão | Descrição |
|-----------|-------------|-----------|
| `CSV_PATH` | `Redes Imps CDS/Endereçamento_Atualizado.csv` | Arquivo de redes por CD |
| `CACHE_PATH` | `cache.json` | Cache incremental de impressoras |
| `CREDENTIALS_PATH` | `printer_credentials.json` | Credenciais manuais por IP |
| `INVENTORY_PATH` | `inventory.html` | Saída HTML gerada |
| `TEMPLATE_PATH` | `Templates/inventory_template.html` | Template do inventário |
| `PROBE_PORT` | `5001` | Porta do servidor Flask |
| `SNMP_COMMUNITY` | `public` | Community SNMP read-only |
| `SNMP_WRITE_COMMUNITY` | `public` | Community SNMP para SNMP SET (aplicação de DNS) |
| `SNMP_TIMEOUT` | `2` (segundos) | Timeout por OID SNMP |
| `HTTP_TIMEOUT` | `3` (segundos) | Timeout por requisição HTTP |
| `NMAP_ARGS` | `-p 80,443,631,9100 --open -T4` | Argumentos do scan nmap |
| `MAX_CONCURRENT` | `10` | Semáforo de scans nmap paralelos |
| `ZEBRA_DEFAULT_DPI` | `203` | DPI padrão Zebra para conversão dot→polegada |

### Credenciais de autenticação HTTP

```python
# HP — EWS Basic Auth (tentadas em ordem)
HP_EWS_USERS     = ['administrador', 'admin']
HP_EWS_PASSWORDS = ['simpress1934@', '12345678', '']

# Samsung SyncThru
SAMSUNG_USER      = 'admin'
SAMSUNG_PASSWORDS = ['sec00000', '1111', 'simpress1934@', '12345678', '3737', '']

# Zebra ZebraNet
ZEBRA_USER      = 'admin'
ZEBRA_PASSWORDS = ['1234', '1934', '3737', '']
```

> Credenciais salvas manualmente via modal (`printer_credentials.json`) têm **prioridade sobre estas listas** — são inseridas no início da fila de tentativas para o IP correspondente.

---

## 📋 Referência de Funções

### Carregamento e cache

| Função | Descrição |
|--------|-----------|
| `load_network_entries()` | Lê CSV → lista de `{network, cd}` para cada rede CIDR válida |
| `load_cache()` | Carrega `cache.json` → dicionário `{ip → printer_dict}` |
| `save_cache(printers)` | Persiste lista de impressoras em `cache.json` |
| `load_printer_credentials()` | Carrega `printer_credentials.json` → dict `{ip → {user, password}}` |
| `save_printer_credentials(creds)` | Persiste credenciais em `printer_credentials.json` |

### Detecção por fabricante

| Função | Descrição |
|--------|-----------|
| `detect_manufacturer(ip)` | SNMP → HTTP específico → HTTP genérico → banner TCP 9100 |
| `get_model(ip, manufacturer)` | HTTP/SNMP por fabricante; rejeita modelos inválidos via `_is_valid_model` |
| `get_serial(ip, manufacturer)` | SNMP OID específico por fabricante; fallback para OID padrão |

### Coleta de métricas

| Função | Descrição |
|--------|-----------|
| `get_page_count(ip)` | XML HP EWS → SNMP OID padrão |
| `get_zebra_odometer(ip)` | HTTP SYSINFO → SNMP Eltron (pol.) → SNMP ZebraNet (dots ÷ DPI) |
| `get_hp_consumables(ip)` | XML ConsumableConfigDyn → HTML EWS → SNMP |
| `get_samsung_consumables(ip)` | HTML SyncThru → SNMP |
| `get_network_config(ip, mfr)` | Coleta DNS/hostname/gateway/ip_mode via SNMP e HTTP com auth tracking |

### Scan de rede

| Função | Descrição |
|--------|-----------|
| `scan_network(entry, known_ips)` | nmap + coleta completa para IPs novos em uma rede CIDR |
| `update_metrics_from_cache(cached)` | Atualiza campos dinâmicos de impressora já conhecida |
| `run_full_scan(update_only)` | Orquestrador: Fase A (cache) + Fase B (nmap novos hosts) |

### DNS e credenciais

| Função | Descrição |
|--------|-----------|
| `apply_dns_config(ip, mfr, dns1, dns2)` | Aplica DNS em cascata (SNMP SET → EWS → SyncThru) |
| `load_printer_credentials()` | Lê `printer_credentials.json` |
| `save_printer_credentials(creds)` | Salva `printer_credentials.json` |

### Diagnóstico (probe)

| Função | Descrição |
|--------|-----------|
| `_probe_tcp(ip, port)` | Testa porta TCP com diagnóstico detalhado de erro |
| `_probe_snmp_oid(ip, oid)` | SNMP GET com diferenciação de timeout/noSuchObject/BER error |
| `_probe_http(ip)` | GET HTTP com status code, header Server, fabricante e snippet |

---

## 🔒 Acesso de Rede e Firewall

O Flask escuta em `0.0.0.0:5001` para aceitar conexões de qualquer IP. Para permitir acesso de outras máquinas:

```powershell
# Criar regra de firewall — executar como Administrador
New-NetFirewallRule `
  -DisplayName "Scanner Impressoras — Flask 5001" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 5001 `
  -Action Allow `
  -Profile Any

# Verificar se a regra foi criada
Get-NetFirewallRule -DisplayName "Scanner Impressoras*" | Select-Object DisplayName, Enabled, Direction
```

Após criar a regra, o inventário fica acessível em:
- **Mesmo PC:** `http://localhost:5001/results`
- **Rede local:** `http://<IP-do-PC>:5001/results`
- **Inventário estático offline:** abrir `inventory.html` diretamente no navegador (sem Flask)

> O inventário estático `inventory.html` pode ser copiado para qualquer máquina e aberto offline. As funcionalidades que requerem o Flask (probe, aplicar DNS, modal de credenciais, exportar CSV) mostrarão erro de conexão se o servidor não estiver rodando.

---

## 🛠️ Ambiente de Desenvolvimento

| Item | Detalhe |
|------|---------|
| Python | 3.14.0a7 (64-bit) |
| SO | Windows 11 |
| nmap | 7.95 |
| flask | 3.1.3 |
| pandas | 3.0.2 |
| python-nmap | 0.7.1 |
| pysnmp | 7.1.26 |

```powershell
# Verificar sintaxe após edição
cd "C:\Projetos\Impressoras"
python -m py_compile scan_printers.py && Write-Host "SYNTAX OK"

# Git — commit e push
git add scan_printers.py Templates/inventory_template.html
git commit -m "mensagem"
git push origin main
```
