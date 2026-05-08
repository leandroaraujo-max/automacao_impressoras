# 🖨️ Scanner de Impressoras de Rede

Kit de automação para inventário e diagnóstico de impressoras distribuídas nos Centros de Distribuição (CDs). Descobre ativamente impressoras via nmap, coleta modelo, serial, contadores e consumíveis por fabricante, gera um inventário HTML estático e serve um painel web em tempo real.

---

## 📦 Estrutura do Projeto

```
Impressoras/
├── scan_printers.py              # Backend principal — scanner + Flask
├── cache.json                    # Cache incremental gerado automaticamente
├── inventory.html                # Inventário HTML gerado automaticamente
├── Templates/
│   ├── inventory_template.html   # Template Jinja-like injetado com os dados do scan
│   └── probe.html                # Página de diagnóstico de conectividade individual
└── Redes Imps CDS/
    ├── Atualizar-Redes.ps1                           # Script PowerShell de atualização DNS
    ├── Endereçamento de Rede CDS - Rede CDS.csv      # Planilha fonte (editada manualmente)
    └── Endereçamento_Atualizado.csv                  # Lida pelo scanner (colunas: CD, Range 01..16)
```

---

## 🚀 Uso Rápido

```powershell
# Scan completo (descobre novas impressoras + atualiza cache)
python scan_printers.py

# Apenas atualiza contadores/consumíveis sem novo scan nmap
python scan_printers.py --update

# Apenas o servidor de probe (sem varredura de rede)
python scan_printers.py --probe-only
```

Acesse `http://localhost:5001/results` ou `http://<seu-ip>:5001/results`.

---

## 📋 Pré-requisitos

```powershell
pip install flask pandas python-nmap pysnmp
```

| Dependência   | Versão testada | Uso |
|---------------|---------------|-----|
| `flask`       | 3.1.3          | Servidor web |
| `pandas`      | 3.0.2          | Leitura do CSV de endereçamento |
| `python-nmap` | 0.7.1          | Wrapper do nmap para varredura de portas |
| `pysnmp`      | 7.1.26         | Suporte SNMP de alto nível (opcional — há fallback puro-Python) |

> **nmap** deve estar instalado no sistema (`nmap --version`). Download: https://nmap.org/download.html

---

## ⚙️ Fluxo de Execução

```
scan_printers.py
│
├── [1] load_network_entries()        — lê CSV → lista de {network, cd}
├── [2] load_cache()                  — carrega cache.json existente
│
├── Fase A — hosts CONHECIDOS (paralelo, sem nmap)
│   └── update_metrics_from_cache()  — atualiza contador/toner/modelo por IP
│       ├── get_page_count()
│       ├── get_hp_consumables()
│       ├── get_samsung_consumables()
│       ├── get_zebra_odometer()
│       └── get_model()  ← só se modelo inválido/ausente
│
├── save_cache()                      — salva após fase A
│
├── Fase B — hosts NOVOS (nmap paralelo por rede)
│   └── scan_network()
│       ├── nmap.scan()               — descobre IPs com portas 80/443/631/9100 abertas
│       ├── detect_manufacturer()
│       ├── get_serial()
│       ├── get_model()
│       ├── get_page_count() / get_zebra_odometer()
│       └── get_hp_consumables() / get_samsung_consumables()
│
├── save_cache()                      — salva após fase B (incremental a cada rede)
│
├── generate_inventory_html()         — injeta dados no template → inventory.html
└── Flask serve /results              — regenera HTML a cada F5 a partir do cache
```

---

## 🔧 Referência de Funções — `scan_printers.py`

### Constantes e configuração

| Constante | Valor padrão | Descrição |
|-----------|-------------|-----------|
| `CSV_PATH` | `Redes Imps CDS/Endereçamento_Atualizado.csv` | Arquivo de redes por CD |
| `CACHE_PATH` | `cache.json` | Cache incremental de impressoras |
| `INVENTORY_PATH` | `inventory.html` | Saída HTML gerada |
| `TEMPLATE_PATH` | `Templates/inventory_template.html` | Template do inventário |
| `PROBE_PORT` | `5001` | Porta do servidor Flask |
| `SNMP_COMMUNITY` | `public` | Community SNMP read-only |
| `SNMP_TIMEOUT` | `2 s` | Timeout por OID SNMP |
| `HTTP_TIMEOUT` | `3 s` | Timeout por requisição HTTP |
| `NMAP_ARGS` | `-p 80,443,631,9100 --open -T4` | Argumentos do scan nmap |
| `MAX_CONCURRENT` | `10` | Semáforo de scans nmap paralelos |
| `ZEBRA_DEFAULT_DPI` | `203` | DPI padrão para conversão dot→polegada |

---

### OIDs SNMP utilizados

| Constante | OID | Fabricante | Campo |
|-----------|-----|-----------|-------|
| `OID_SERIAL` | `1.3.6.1.2.1.43.5.1.1.17.1` | Padrão RFC 3805 | Serial |
| `OID_PAGE_COUNT` | `1.3.6.1.2.1.43.10.2.1.4.1.1` | Padrão RFC 3805 | Contador de páginas |
| `OID_MODEL_STD` | `1.3.6.1.2.1.25.3.2.1.3.1` | RFC (hrDeviceDescr) | Modelo genérico |
| `OID_MODEL_STD2` | `1.3.6.1.2.1.43.5.1.1.16.1` | RFC (prtGeneralPrinterName) | Modelo genérico 2 |
| `OID_HP_MODEL` | `1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.3.0` | HP JetDirect | Modelo HP |
| `OID_HP_TONER` | `1.3.6.1.4.1.11.2.3.9.4.2.1.1.5.28.1` | HP JetDirect | Toner preto (%) |
| `OID_HP_MAINT_KIT` | `1.3.6.1.4.1.11.2.3.9.4.2.1.1.5.28.5` | HP JetDirect | Kit manutenção (%) |
| `OID_SAMSUNG_MODEL` | `1.3.6.1.4.1.236.11.5.1.1.1.1.0` | Samsung CLX/SL MIB | Modelo Samsung |
| `OID_SAMSUNG_TONER` | `1.3.6.1.4.1.236.11.5.11.81.1.1.1.20.1` | Samsung MIB | Toner (%) |
| `OID_SAMSUNG_DRUM` | `1.3.6.1.4.1.236.11.5.11.81.1.1.1.40.1` | Samsung MIB | Unidade de imagem (%) |
| `OID_ZEBRA_SERIAL_1` | `1.3.6.1.4.1.10642.1.9.0` | ZebraNet MIB | Serial Zebra |
| `OID_ZEBRA_SERIAL_2` | `1.3.6.1.4.1.683.6.2.3.2.1.6.1` | Eltron/legado | Serial Zebra legado |
| `OID_ZEBRA_MODEL` | `1.3.6.1.4.1.10642.1.1.7.0` | ZebraNet MIB | Modelo Zebra |
| `OID_ZEBRA_ODOM_ELTRON` | `1.3.6.1.4.1.683.6.2.3.6.1.2.1` | Eltron/legado GK/LP | Odômetro (polegadas) |
| `OID_ZEBRA_ODOM_DOTS` | `1.3.6.1.4.1.10642.1.1.8.0` | ZebraNet ZT/ZD | Odômetro (dots ÷ 203) |
| `OID_HONEYWELL_MODEL` | `1.3.6.1.4.1.1248.1.1.3.1.3.0` | Honeywell/Intermec | Modelo Honeywell |

---

### Modelo de dados — `PrinterInfo`

```python
@dataclass
class PrinterInfo:
    ip:           str          # Endereço IPv4
    fabricante:   str          # HP | Samsung | Zebra | Honeywell | Desconhecido
    modelo:       Optional[str]  # Modelo do equipamento (HTTP ou SNMP)
    serial:       str          # Número de série
    metrica:      Optional[str]  # Páginas impressas (laser) | Polegadas cabeça (Zebra)
    toner:        Optional[str]  # Nível de toner em % (laser HP/Samsung)
    consumivel2:  Optional[str]  # Kit manutenção % (HP) | Unidade de imagem % (Samsung)
    status:       str          # 'Online'
    filial:       str          # Número do CD (ex: '350')
    tipo:         str          # 'laser' | 'termica'
    first_seen:   str          # ISO datetime do primeiro scan
    last_updated: str          # ISO datetime da última atualização de métricas
```

---

### Funções de carregamento e cache

#### `load_network_entries() → list[dict]`
Lê `Endereçamento_Atualizado.csv` e retorna lista de `{network, cd}` para cada rede CIDR válida.
- Detecta colunas `Range 01` … `Range 16` dinamicamente
- Ignora linhas sem coluna `CD` ou com CIDR inválido
- Log de aviso para CIDRs malformados

#### `load_cache() → dict[str, dict]`
Carrega `cache.json` e retorna dicionário `{ip → printer_dict}`.
- Aceita tanto lista quanto dict no JSON (compatibilidade)
- Retorna `{}` se arquivo não existe ou está corrompido

#### `save_cache(printers: list[dict])`
Persiste a lista de impressoras em `cache.json` com indentação de 2 espaços.

---

### Funções SNMP

#### `_snmp_get_raw(ip, oid) → Optional[str]`
Implementação pura-Python de SNMP GET v1 via UDP (BER encoder/decoder manual).
- Não depende de `pysnmp`
- Decodifica OCTET STRING (tag `0x04`) e inteiros (tags `0x02`, `0x41`, `0x42`, `0x46`)
- Timeout configurável por `SNMP_TIMEOUT`

#### `_snmp_get(ip, oid) → Optional[str]`
Wrapper que usa `pysnmp.hlapi.getCmd` quando disponível, senão cai para `_snmp_get_raw`.

#### `get_serial(ip, manufacturer) → str`
Obtém serial via SNMP.
- **Zebra**: tenta `OID_ZEBRA_SERIAL_1` → `OID_ZEBRA_SERIAL_2` → `OID_SERIAL`
- **Outros**: apenas `OID_SERIAL`
- Retorna `'N/A'` se nenhum OID responder

---

### Funções HTTP

#### `_http_get_page(ip, path, use_https=False, timeout=HTTP_TIMEOUT) → Optional[str]`
Helper centralizado para GET HTTP/HTTPS.
- HTTPS desabilita verificação de certificado (SSL auto-assinado das impressoras)
- Retorna body como string UTF-8 ou `None` em caso de erro

#### `_decode_html(s) → str`
Decodifica entidades HTML básicas (`&raquo;`, `&amp;`, `&nbsp;`, etc.).

---

### Funções de detecção por fabricante

#### `_match_manufacturer(text) → Optional[str]`
Detecta fabricante por palavras-chave no texto.

| Fabricante | Palavras-chave |
|-----------|---------------|
| HP | `hp`, `laserjet`, `hewlett`, `hp-http`, `jetdirect` |
| Samsung | `samsung` |
| Zebra | `zebra`, `zpl`, `zebra technologies` |
| Honeywell | `honeywell`, `intermec`, `datamax` |

#### `detect_manufacturer(ip) → Optional[str]`
Identifica o fabricante em 4 etapas (para na primeira que funcionar):
1. **SNMP** — OIDs `OID_MODEL_STD` e `OID_MODEL_STD2` (mais rápido)
2. **HTTP específico por fabricante**:
   - HP: `https://IP/hp/device/DeviceInformation/View`
   - Samsung: `/sws/index.html`, `/default.html`
   - Zebra: `/server/SYSINFO.htm`, `/server/CFGPAGE.htm`, `/config.html`
3. **HTTP/HTTPS genérico** na raiz `/`
4. **Banner TCP porta 9100** (JetDirect / ZPL)

#### `get_model(ip, manufacturer) → Optional[str]`
Detecta o modelo do equipamento.

| Fabricante | Estratégia |
|-----------|-----------|
| HP | Regex `\bHP\s+(LaserJet|PageWide|…)…` no body de `/hp/device/DeviceStatus/Index`, `/DeviceInformation/View`, `/InternalPages?id=ConfigurationPage`; fallback XML `/DevMgmt/ProductConfigDyn.xml` |
| Samsung | Título de `/sws/index.html` ou `/default.html` (exclui labels genéricos) |
| Zebra | Campo `Model:` de `/server/SYSINFO.htm` ou `/config.html` |
| Todos | SNMP fallback pelos OIDs de modelo específicos e padrões |

#### `_is_valid_model(val, serial='') → bool`
Valida se uma string parece um modelo real. Rejeita:
- Strings com entidades HTML (`&raquo;`, `&amp;`, etc.)
- Caracteres não-imprimíveis (menos de 85% ASCII imprimível)
- Serials disfarçados (somente maiúsculas + dígitos sem espaço, ex: `BRBSR8L01H`)
- Labels de navegação (`Device Information`, `Status do dispositivo`, etc.)
- String igual ou contida no serial da impressora

---

### Funções de coleta de métricas

#### `get_page_count(ip) → Optional[str]`
Contador de páginas totais.
1. XML HP EWS — `/DevMgmt/ProductUsageDyn.xml` (campo `TotalImpressions`)
2. SNMP — `OID_PAGE_COUNT` (RFC 3805)

#### `get_zebra_odometer(ip) → Optional[str]`
Odômetro da cabeça de impressão térmica Zebra em polegadas.
1. HTTP — `/server/SYSINFO.htm` → regex `Head Mileage: N in`
2. HTTP — `/server/CFGPAGE.htm` → mesma regex
3. SNMP — `OID_ZEBRA_ODOM_ELTRON` (já em polegadas, modelos GK/LP)
4. SNMP — `OID_ZEBRA_ODOM_DOTS` (dot count ÷ 203 DPI, modelos ZT/ZD)

Retorna string formatada como `"1,234 pol."`. Rejeita valores acima de 5.000.000 (≈ 79.000 km).

#### `get_hp_consumables(ip) → (toner%, kit%)`
Nível de toner e kit de manutenção HP.
1. XML `/DevMgmt/ConsumableConfigDyn.xml` — parse de `ConsumableLabelCode` + `PercentageLevelRemaining`
2. HTML `/hp/device/DeviceStatus/Index` + `/InternalPages?id=SuppliesStatus` — regex PT/EN: `Preto|Black|Toner|Cartridge` e `Kit|Maintenance|Fuser|Document Feeder`
3. SNMP — `OID_HP_TONER` e `OID_HP_MAINT_KIT` (valores negativos descartados)

#### `get_samsung_consumables(ip) → (toner%, drum%)`
Nível de toner e unidade de imagem Samsung.
1. HTML — `/sws/app/information/reportsAndPages/suppliesStatus`, `/sws/index.html`, `/default.html`
2. SNMP — `OID_SAMSUNG_TONER` e `OID_SAMSUNG_DRUM`

---

### Funções de scan de rede

#### `resolve_tipo(manufacturer) → str`
Retorna `'termica'` para Zebra/Honeywell, `'laser'` para todos os outros.

#### `scan_network(entry, known_ips) → list[dict]`
Escaneia uma rede CIDR com nmap e coleta dados de impressoras novas.
- Ignora IPs já presentes em `known_ips` (serão atualizados pela fase A)
- Hosts com porta **9100** ou **631** abertas são adicionados como `Desconhecido` mesmo sem identificação de fabricante
- Executa toda coleta (serial, modelo, consumíveis) em sequência para cada host
- Controlado pelo semáforo `_nmap_sem` (máximo `MAX_CONCURRENT` simultâneos)

#### `update_metrics_from_cache(cached) → dict`
Atualiza campos dinâmicos de uma impressora já conhecida no cache.
- Re-detecta fabricante se estava como `Desconhecido`
- Re-detecta modelo se o valor atual falha em `_is_valid_model` (limpa lixo salvo anteriormente)
- Atualiza `metrica`, `toner`, `consumivel2`, `last_updated`

#### `run_full_scan(update_only=False) → list[dict]`
Orquestrador principal do scan.
- **Fase A** (sempre): atualiza métricas de todos os IPs em cache em paralelo; salva cache ao final
- **Fase B** (apenas se `update_only=False`): descobre novos hosts por rede em paralelo; salva cache incrementalmente a cada rede concluída
- Atualiza `_scan_status` (contadores expostos via `/api/status`)

---

### Funções de geração de inventário

#### `generate_inventory_html(printers, output_path)`
Lê `inventory_template.html`, injeta os dados via `string.Template.safe_substitute` e grava `inventory.html`.

| Variável injetada | Conteúdo |
|------------------|---------|
| `$DATA` | JSON array de todas as impressoras |
| `$CDS` | JSON array de CDs únicos ordenados |
| `$TIMESTAMP` | Data/hora da geração |
| `$PROBE_PORT` | Porta do servidor Flask |
| `$TOTAL` | Total de impressoras |

---

### Diagnóstico de conectividade

#### `_probe_tcp(ip, port) → dict`
Testa abertura de uma porta TCP com timeout de 2 s. Distingue timeout, conexão recusada e erros de rede.

#### `_probe_snmp_oid(ip, oid) → dict`
SNMP GET com diagnóstico detalhado. Distingue: timeout UDP, `noSuchObject`, `noSuchInstance`, `endOfMibView`, erros BER, valores vazios. Implementação BER auto-contida (sem pysnmp).

#### `_probe_http(ip) → dict`
GET HTTP na porta 80 com coleta de status code, header `Server`, snippet do body e identificação de fabricante.

---

### Rotas Flask

| Método | Rota | Descrição |
|--------|------|-----------|
| `GET` | `/results` | Regenera `inventory.html` a partir do cache e serve |
| `GET` | `/api/status` | JSON com status do scan em andamento (`running`, `total`, `networks_done`, `networks_total`) |
| `GET` | `/api/cds` | JSON com lista de CDs disponíveis no cache |
| `GET` | `/api/cd/<cd>` | JSON com impressoras de um CD específico |
| `GET` | `/probe` | Página HTML de diagnóstico individual |
| `GET` | `/api/probe?ip=<ip>` | JSON com resultado completo de diagnóstico (portas TCP, HTTP, 10 OIDs SNMP) |

---

## 🖥️ Páginas Web

### `/results` — Inventário de Impressoras (`inventory_template.html`)

Interface principal servida pelo Flask. Gerada via `string.Template` com os dados do cache.

**Layout:**
- Sidebar fixa de 240 px com lista de CDs e contador de impressoras por CD
- Campo de busca para filtrar CDs na sidebar
- Área principal com tabela do CD selecionado ou de todos os CDs

**Funcionalidades:**
- Clique em um CD na sidebar para ver somente suas impressoras
- Botão "Ver todos os CDs" exibe inventário completo
- Banner de progresso azul enquanto scan está em andamento (polling `/api/status` a cada 5 s)
- Auto-refresh a cada 20 s durante scan; reload automático ao finalizar
- Cards de estatísticas: Total, Laser, Térmica
- Filtros em tempo real: IP, Fabricante, Tipo, Serial/Modelo

**Colunas da tabela:**

| Coluna | Descrição |
|--------|-----------|
| IP | Link clicável para interface web do equipamento (`http://IP/`) + ícone 🔍 de probe |
| Fabricante | Badge colorido (HP=azul, Samsung=ciano, Zebra=âmbar, Honeywell=vermelho) |
| Modelo | Nome do modelo detectado |
| N.º Série | Serial via SNMP |
| Contador / Odôm. | Páginas (laser, verde) ou polegadas da cabeça (térmica, âmbar) |
| Toner | Nível em % — verde ≥30%, âmbar 15-29%, vermelho <15% |
| Kit / Drum | Kit de manutenção HP ou unidade de imagem Samsung |
| Tipo | Badge Laser / Térmica |
| Status | Indicador Online |
| Atualizado | Data/hora da última coleta de métricas |

---

### `/probe` — Diagnóstico de Conectividade (`probe.html`)

Permite testar qualquer IP manualmente antes ou após o scan.

**Seções do resultado:**
1. **Identificação** — IP testado + fabricante detectado
2. **Páginas Web do Equipamento** — links diretos para as páginas EWS do fabricante detectado:
   - **HP**: DeviceInformation, SuppliesStatus, UsagePage, ConfigurationPage, XMLs de API, DeviceStatus, EventLog
   - **Samsung**: SyncThru `/sws/index.html`, `/default.html`, suppliesStatus
   - **Zebra**: `/server/SYSINFO.htm`, `/server/CFGPAGE.htm`, `/config.html`
3. **Portas TCP** — 80, 443, 631, 9100 (aberta/fechada + latência)
4. **HTTP porta 80** — status code, header Server, snippet do body
5. **SNMP** — 10 OIDs testados com diagnóstico individual:
   - Serial padrão, Contador de páginas
   - Zebra Serial (ZebraNet + Eltron), Odômetro (dots + polegadas)
   - HP Toner, HP Kit Manutenção
   - Samsung Toner, Samsung Unidade de Imagem
   - Conversão automática de dot count Zebra para polegadas

---

## 📂 CSV de Endereçamento

**Estrutura:** `CD, Range 01, Range 02, …, Range 16`

```csv
CD,Range 01,Range 02,Range 03,...
350,10.70.82.0/24,10.70.85.0/24,10.70.73.0/24,...
490,10.60.217.0/24,10.60.220.0/24,...
```

- Cada linha representa um CD com até 16 redes CIDR
- Ranges vazios são ignorados automaticamente
- O scanner detecta as colunas `Range XX` dinamicamente

---

## 🔒 Acesso Externo

O Flask escuta em `0.0.0.0:5001`. Para acesso da rede local:

```powershell
# Criar regra no Windows Firewall (executar como Administrador)
New-NetFirewallRule -DisplayName "Impressoras Probe 5001" `
  -Direction Inbound -Protocol TCP -LocalPort 5001 -Action Allow -Profile Any
```

Acesse de qualquer máquina na rede: `http://<IP-do-servidor>:5001/results`

---

## 🛠️ Ambiente

| Item | Detalhe |
|------|---------|
| Python | 3.10+ (testado em 3.14 64-bit) |
| SO | Windows 10/11 |
| nmap | Deve estar no PATH — https://nmap.org/download.html |

```powershell
# Instalar dependências
& "C:\Users\_araujo\AppData\Local\Python\pythoncore-3.14-64\python.exe" -m pip install flask pandas python-nmap pysnmp

# Verificar sintaxe do script
& "C:\Users\_araujo\AppData\Local\Python\pythoncore-3.14-64\python.exe" -m py_compile scan_printers.py
```


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