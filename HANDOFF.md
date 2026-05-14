# HANDOFF — Scanner de Impressoras Magalu

> Documento de transferência de contexto para modelos de IA assistentes de desenvolvimento.
> Criado em: 11/05/2026 · Projeto: `leandroaraujo-max/automacao_impressoras` (branch `main`)

---

## 1. Propósito do Projeto

Ferramenta interna do time de TI da Magazine Luiza para:

- **Descobrir** todas as impressoras nos Centros de Distribuição (CDs) via nmap
- **Catalogar** modelo, serial, contador de páginas, toner, configuração de rede (DNS, gateway, hostname)
- **Monitorar** via inventário HTML gerado localmente
- **Aplicar DNS** remotamente via SNMP SET e/ou HTTP nos painéis web das impressoras
- **Expor** API REST local para probe e administração

Roda em **Windows** num PC na rede interna do Magalu. Não há deploy em cloud.

---

## 2. Stack Técnica

| Componente | Detalhe |
|---|---|
| Runtime | Python 3.14 (64-bit) — `python` no PATH |
| Servidor web | Flask 3.1.3 — lazy-loaded, porta **8080** |
| Scanner de rede | python-nmap 0.7.1 (wrapper de nmap 7.95) |
| SNMP | pysnmp 7.1.26 (leitura) + raw UDP socket (escrita/SET) |
| HTTP | `urllib` nativo (sem `requests`) |
| Planilhas | pandas 3.0.2 |
| Config | python-dotenv + `config.py` lendo `.env` |
| Versionamento | Git → GitHub `leandroaraujo-max/automacao_impressoras`, branch `main` |

---

## 3. Estrutura de Arquivos

```
C:\Projetos\Impressoras\
├── scan_printers.py          ← ARQUIVO PRINCIPAL (~2900 linhas)
├── config.py                 ← Carrega .env e expõe constantes
├── .env                      ← Credenciais e config real (NÃO versionado)
├── .env.example              ← Template versionado
├── .gitignore
├── README.md                 ← Documentação técnica completa
├── HANDOFF.md                ← Este arquivo
├── admin.key                 ← Senha do painel admin (texto simples, NÃO versionado)
├── cache.json                ← Cache incremental de impressoras (NÃO versionado)
├── inventory.html            ← Inventário gerado (NÃO versionado)
├── printer_credentials.json  ← Credenciais por IP (NÃO versionado)
├── automacao.log             ← Log rotativo 5MB×3 (NÃO versionado)
├── Redes Imps CDS/
│   └── Endereçamento_Atualizado.csv  ← CIDRs por CD (NÃO versionado)
└── Templates/
    └── inventory_template.html  ← Template HTML do inventário
```

---

## 4. Como Executar

```powershell
cd C:\Projetos\Impressoras

# Scan completo (nmap + coleta + inventário) + servidor Flask
python scan_printers.py

# Só atualiza contadores/toner do cache sem nmap
python scan_printers.py --update

# Só sobe o servidor Flask (sem escanear nada)
python scan_printers.py --probe-only
```

URLs após iniciar:

| URL | Acesso |
|---|---|
| `http://localhost:8080/home` | Inventário público (sem login) |
| `http://localhost:8080/admin` | Painel administrativo (requer login) |
| `http://localhost:8080/login` | Formulário de autenticação |
| `http://localhost:8080/probe` | Diagnóstico individual de IP |
| `http://localhost:8080/healthcheck` | Status do servidor (JSON) |
| `http://10.70.83.43:8080/home` | Rede interna Magalu |

**Firewall Windows:** regra `Scanner Impressoras — Flask 8080` já criada (TCP 8080, Profile Any, Enabled).

---

## 5. Arquitetura do `scan_printers.py`

### 5.1 Fluxo Principal

```
main()
 ├─ _setup_file_logging()           → automacao.log (RotatingFileHandler 5MB×3)
 ├─ Thread(scan-master)
 │    └─ run_full_scan()
 │         ├─ load_network_entries()      → lê CSV com CIDRs por CD
 │         ├─ load_cache()                → cache.json incremental
 │         ├─ scan_network() × N redes   → nmap + identify_host (paralelo, MAX_CONCURRENT)
 │         ├─ update_metrics_from_cache() → atualiza só contadores dos já conhecidos
 │         └─ save_cache()
 └─ _get_flask_app()                → import lazy do Flask
      └─ flask_app.run(0.0.0.0:8080)
```

### 5.2 Modelo de Dados — `PrinterInfo` (dataclass, linha ~251)

```python
@dataclass
class PrinterInfo:
    ip: str
    fabricante: str          # 'HP' | 'Samsung' | 'Zebra' | 'Honeywell'
    modelo: Optional[str]
    serial: str
    metrica: Optional[str]   # páginas (laser) | polegadas (térmica Zebra)
    toner: Optional[str]     # % restante
    consumivel2: Optional[str]  # kit manutenção HP | unidade de imagem Samsung
    status: str              # 'Online' | 'Offline'
    filial: str              # código do CD
    tipo: str                # 'laser' | 'termica'
    first_seen: str          # ISO datetime
    last_updated: str        # ISO datetime
    hostname: Optional[str]
    dns1: Optional[str]
    dns2: Optional[str]
    gateway: Optional[str]
    ip_mode: Optional[str]   # 'DHCP' | 'Manual' | 'AutoIP'
    dns_apply_status: Optional[str]
    auth_ok: Optional[bool]  # True=login web ok | False=falhou | None=não tentou
    auth_user: Optional[str] # usuário que autenticou com sucesso
```

Cache (`cache.json`): dicionário `{ip: PrinterInfo.to_dict()}`.

### 5.3 Coleta por Fabricante

| Fabricante | SNMP | HTTP | Autenticação |
|---|---|---|---|
| **HP** | JetDirect MIB (modelo, toner, kit manutenção, DNS) | EWS `/DevMgmt/NetworkConfigDyn.json`, `/network_id.htm` | Basic Auth — `HP_EWS_USERS` × `HP_EWS_PASSWORDS` |
| **Samsung** | Samsung CLX MIB (modelo, toner, drum) | SyncThru `/sws/app/information/...` | Sessão por cookie — `SAMSUNG_USER` × `SAMSUNG_PASSWORDS` |
| **Zebra** | ZebraNet MIB (serial, odômetro em dots) | `/server/NWSET.htm` | Basic Auth — `ZEBRA_USER` × `ZEBRA_PASSWORDS` |
| **Honeywell** | RFC3805 padrão | — | — |

### 5.4 Funções Críticas (linhas aproximadas)

| Função | Linha | Descrição |
|---|---|---|
| `_setup_file_logging()` | ~78 | RotatingFileHandler 5MB×3 para automacao.log |
| `_with_retry(fn, attempts, base_delay)` | ~467 | Backoff exponencial ×2, ±20% jitter; não retentar em HTTPError 4xx |
| `_http_get_page(ip, path, use_https, timeout)` | ~488 | GET com retry + `_SSL_CTX` |
| `_http_get_authenticated(ip, path, user, pw, use_https)` | ~713 | GET Basic Auth + `_SSL_CTX` |
| `_http_post_authenticated(ip, path, payload, user, pw, ...)` | ~815 | POST Basic Auth com retry + `_SSL_CTX` |
| `_samsung_syncthru_set_dns(ip, user, pw, dns1, dns2, use_https)` | ~854 | Login por cookie + PUT/POST no SyncThru |
| `_snmp_set_string(ip, oid, value)` | ~735 | SNMP SET raw UDP; BER manual; valida error-status==0 |
| `get_network_config(ip, manufacturer)` | ~517 | Coleta hostname/DNS/gateway/ip_mode |
| `apply_dns_config(ip, manufacturer, dns1, dns2)` | ~940 | Aplica DNS: SNMP SET → fallback HTTP |
| `run_full_scan(update_only)` | ~1862 | Orquestra scan completo ou incremental |
| `generate_inventory_html(printers, path, is_admin)` | ~1965 | Gera HTML a partir do template |
| `_register_routes(flask_app, ...)` | ~2047 | Registra todas as rotas Flask |

### 5.5 Contexto SSL Global — CRÍTICO

```python
# Definido logo após os imports de urllib (linhas ~40-46)
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE
```

Aplicado em **todos** os `urlopen` e `HTTPSHandler`. Resolve o bug de redirect HTTP→HTTPS
invisível: urllib seguia `302 Location: https://...` com o contexto SSL padrão do Python,
que rejeitava certificados autoassinados embutidos no firmware das impressoras.

### 5.6 Status Global do Scan

```python
_scan_status = {
    'running': False,
    'total': 0,
    'networks_done': 0,
    'networks_total': 0,
    'started_at': None,
    'finished_at': None,
}
```

Exposto em `GET /api/status`. Usado pelo painel admin para barra de progresso.

---

## 6. API REST Completa

| Método | Rota | Auth | Descrição |
|---|---|---|---|
| GET | `/home` | pública | Inventário HTML público |
| GET | `/admin` | admin | Inventário HTML com funcionalidades completas |
| GET/POST | `/login` | — | Formulário de autenticação |
| GET | `/logout` | — | Encerra sessão |
| GET | `/probe` | pública | Página de diagnóstico individual de IP |
| GET | `/api/status` | pública | Status do scan em andamento |
| GET | `/healthcheck` | pública | `{ok, version, uptime_s, scan_running, cache_size}` |
| GET | `/api/cds` | pública | Lista de CDs no cache |
| GET | `/api/cd/<cd>` | pública | Impressoras de um CD específico |
| GET | `/api/network-report` | pública | Relatório DNS com diff (`?dns1=`, `?dns2=`) |
| GET | `/api/export-csv` | pública | Download CSV (`?cd=`, `?fabricante=`) |
| GET | `/api/probe` | pública | Diagnóstico técnico completo (`?ip=`) |
| POST | `/api/set-credentials` | **admin** | Salva credenciais por IP e recoleta rede |
| POST | `/api/scan/start` | **admin** | Inicia scan `{"update_only": bool}` |
| POST | `/api/apply-dns` | **admin** | Aplica DNS `{dns1, dns2, ips[] ou all_pending: true}` |

---

## 7. Autenticação Admin

- Senha em `admin.key` (texto simples; excluído do git via `*.key` no `.gitignore`)
- Comparação timing-safe: `hmac.compare_digest()`
- Sessão Flask via cookie: `secret_key = _load_admin_password() + '_session_salt_v1'`
- Sessão expira ao reiniciar o servidor (sem persistência em arquivo)
- Primeira execução sem `admin.key`: cria o arquivo com senha padrão `'admin'` e loga aviso

---

## 8. Configuração via `.env`

```env
PROBE_PORT=8080
SNMP_COMMUNITY=public
HTTP_TIMEOUT=3
SNMP_TIMEOUT=2
MAX_CONCURRENT=10
HP_EWS_USERS=administrador,admin
HP_EWS_PASSWORDS=senha1,senha2,
SAMSUNG_USER=admin
SAMSUNG_PASSWORDS=senha1,senha2,senha3,
ZEBRA_USER=admin
ZEBRA_PASSWORDS=senha1,senha2,
```

Carregado por `config.py` via `python-dotenv` com `override=False`
(variáveis de ambiente do SO têm prioridade). Template versionado em `.env.example`.

---

## 9. OIDs SNMP Relevantes

```python
# Standard (RFC 3805 / RFC 3418)
OID_SERIAL           = '1.3.6.1.2.1.43.5.1.1.17.1'
OID_PAGE_COUNT       = '1.3.6.1.2.1.43.10.2.1.4.1.1'
OID_MODEL_STD        = '1.3.6.1.2.1.25.3.2.1.3.1'

# HP JetDirect MIB
OID_HP_MODEL         = '1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.3.0'
OID_HP_TONER         = '1.3.6.1.4.1.11.2.3.9.4.2.1.1.5.28.1'
OID_HP_MAINT_KIT     = '1.3.6.1.4.1.11.2.3.9.4.2.1.1.5.28.5'
OID_HP_DNS_PRIMARY   = '1.3.6.1.4.1.11.2.4.3.5.29.0'
OID_HP_DNS_SECONDARY = '1.3.6.1.4.1.11.2.4.3.5.30.0'
OID_HP_GATEWAY       = '1.3.6.1.4.1.11.2.4.3.5.20.0'
OID_HP_HOSTNAME      = '1.3.6.1.4.1.11.2.4.3.5.2.0'

# Samsung CLX MIB
OID_SAMSUNG_MODEL    = '1.3.6.1.4.1.236.11.5.1.1.1.1.0'
OID_SAMSUNG_TONER    = '1.3.6.1.4.1.236.11.5.11.81.1.1.1.20.1'
OID_SAMSUNG_DRUM     = '1.3.6.1.4.1.236.11.5.11.81.1.1.1.40.1'

# ZebraNet MIB
OID_ZEBRA_SERIAL_1   = '1.3.6.1.4.1.10642.1.9.0'
OID_ZEBRA_MODEL      = '1.3.6.1.4.1.10642.1.1.7.0'
OID_ZEBRA_ODOM_DOTS  = '1.3.6.1.4.1.10642.1.1.8.0'  # dot count ÷ DPI = polegadas
ZEBRA_DEFAULT_DPI    = 203
```

---

## 10. Histórico de Bugs Críticos Corrigidos

| Commit | Erro Observado | Causa Real | Fix Aplicado |
|---|---|---|---|
| `6d82f36` | `URLError: SSL CERTIFICATE_VERIFY_FAILED` | Redirect HTTP→HTTPS seguido com contexto SSL padrão do Python (verifica cert) | `_SSL_CTX` global `CERT_NONE` em todos os `urlopen` |
| — | DNS reportado como aplicado, nunca alterado | `resp[0]==0x30` (tag SEQUENCE) sempre True — qualquer pacote SNMP passava | Parse BER completo: verifica PDU type `0xa2` + `error-status == 0` |
| — | `apply_dns_config` HP retornava sucesso falso | `if ok1 or ok2` — bastava um SET "funcionar" (falso positivo) | `if ok1 and ok2` — ambos DNS1 e DNS2 devem confirmar noError |
| `26bc1cd` | `NameError: name 're' is not defined` | `import re` era só local dentro de `get_network_config` | `import re` adicionado ao bloco global de imports |
| `738a295` | `SyntaxError: Unexpected token '<'` no JS | Servidor sem rota retornava 404 HTML; JS chamava `.json()` sem checar | `r.ok` antes de `.json()`; detecção de resposta HTML |

---

## 11. Convenções Obrigatórias

### Regra do usuário (standing rule)

> **Em alterações muito grandes: atualizar `README.md` → commit → push**

### Código

- **Nunca** usar `requests` — somente `urllib` nativo do Python
- **Todo** `urlopen` deve usar `context=_SSL_CTX`
- `log.error(..., exc_info=True)` em todo bloco `except` relevante
- `_with_retry()` para funções HTTP com falha transitória de rede
- Após qualquer edição: `python -m py_compile scan_printers.py`

### Commits

- Mensagem em inglês; corpo detalhado: causa + fix
- Padrão: `fix: <descrição curta>\n\nBug: ...\nCausa: ...\nFix: ...`

### O que NÃO versionar (`.gitignore`)

```
*.key                   # admin.key e qualquer outro arquivo de senha
.env                    # config local com credenciais reais
cache.json              # dados operacionais
inventory.html          # gerado em runtime
printer_credentials.json
automacao.log
automacao.log.*
*.csv                   # IPs/CIDRs — infraestrutura sensível
```

---

## 12. Pendências Conhecidas

| Prioridade | Item |
|---|---|
| Alta | Confirmar DNS via HTTP no HP E60165 (`/network_id.htm`) em produção real |
| Alta | Impressoras offline no cache permanecem `status='Online'` — sem re-verificação |
| Média | `SNMP_WRITE_COMMUNITY = 'public'` hardcoded — mover para `.env` |
| Média | Validar Samsung SyncThru pós-fix SSL (redirect `use_https=False → HTTPS`) |
| Baixa | Fallback em `config.py` usa `PROBE_PORT=5001` (deveria ser `8080`) |
| Baixa | Sessão admin sem timeout configurável — expira só ao reiniciar o servidor |

---

## 13. Prompt de Contexto para o Gemini (ou outro modelo)

Cole no início de cada nova sessão de desenvolvimento:

```
Você está assumindo o desenvolvimento do projeto "Scanner de Impressoras Magalu".
O arquivo principal é C:\Projetos\Impressoras\scan_printers.py (~2900 linhas).
Leia o arquivo HANDOFF.md em C:\Projetos\Impressoras\ para contexto completo.

REGRAS OBRIGATÓRIAS:
1. Leia o trecho relevante do código ANTES de editar qualquer coisa.
2. Nunca use `requests` — somente `urllib` nativo do Python.
3. Todo urlopen deve usar `context=_SSL_CTX` (definido globalmente após os imports de urllib).
4. Em alterações grandes: atualize README.md → commit → push.
5. Mensagens de commit em inglês com corpo detalhado: bug + causa + fix.
6. Nunca versionar: .env, *.key, cache.json, *.csv, automacao.log.
7. Porta Flask: 8080 (PROBE_PORT no .env e no .env.example).
8. Autenticação admin: arquivo admin.key (texto simples), comparado com hmac.compare_digest().
9. Cache incremental: dicionário {ip: PrinterInfo.to_dict()} persistido em cache.json.
10. log.error() sempre com exc_info=True dentro de blocos except.
11. Usar _with_retry() em funções HTTP sujeitas a falha transitória de rede.
12. Validar sintaxe após toda edição: python -m py_compile scan_printers.py
13. Implementar diretamente — não só sugerir.

CONTEXTO DE REDE:
- Máquina host: 10.70.83.43 | Porta Flask: 8080
- SNMP community leitura: public (funciona na maioria das impressoras)
- SNMP community escrita: public (geralmente bloqueado — usar HTTP como fallback)
- Impressoras HP: HTTPS com certificado autoassinado (coberto pelo _SSL_CTX global)
- Firewall Windows: regra "Scanner Impressoras — Flask 8080", TCP 8080, Profile Any (já criada)

FLUXO DE TRABALHO ESPERADO:
1. Usuário descreve bug ou feature
2. Modelo lê o código relevante antes de implementar
3. Implementa diretamente (não só sugere)
4. Valida: python -m py_compile scan_printers.py
5. Commit com mensagem descritiva + push
6. Se mudança grande: atualiza README.md antes do commit
```

---

## 14. Repositório e Histórico

```
Repositório : leandroaraujo-max/automacao_impressoras
Branch ativa: main
Remote      : https://github.com/leandroaraujo-max/automacao_impressoras
```

Commits recentes (mais recente → mais antigo):

| Commit | Descrição |
|---|---|
| `6d82f36` | fix: SSL CERTIFICATE_VERIFY_FAILED — _SSL_CTX global em todos os urlopen |
| `3c65628` | docs: firewall 8080 documentado + remoção de regra antiga (5001) |
| `1d1f8e2` | chore: porta padrão 5001→8080 |
| `7c238b3` | docs: .gitignore documentado e reestruturado |
| `738a295` | fix: startScan verifica r.ok antes de .json() |
| `0b052c6` | feat: botão force scan + /api/scan/start no painel admin |
| `26bc1cd` | fix: import re global (NameError em update_metrics_from_cache) |
| `4df1aba` | feat: logging rotativo, retry/backoff, config.py, /healthcheck |
