"""Scanner de Impressoras — Inventário Estático + Cache Incremental + Servidor de Probe

Fluxo principal:
  1. Carrega redes do CSV (CD + Range 01..16)
  2. Lê cache JSON existente — hosts já conhecidos só têm métrica/consumiveis atualizados
  3. Novos hosts passam pelo scan completo (nmap + HTTP + SNMP)
  4. Dados coletados por fabricante:
       HP      (laser)   → modelo, contador, toner, kit de manutenção
       Samsung (laser)   → modelo, contador, toner, unidade de imagem
       Zebra   (térmica) → modelo, odômetro da cabeça (polegadas)
       Honeywell(térmica)→ modelo, contador de páginas
  5. Gera inventory.html e salva cache.json
  6. Flask em :5001 para /probe e /api/cd/<cd>

Uso:
    python scan_printers.py              # scan completo + atualiza cache
    python scan_printers.py --update     # só atualiza contadores (sem nmap)
    python scan_printers.py --probe-only # somente servidor de probe

Requisitos:
    pip install flask pandas python-nmap pysnmp
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
import ssl
import urllib.error
import urllib.request
import webbrowser

# Contexto SSL global — desabilita verificação de certificado.
# Impressoras usam certificados autoassinados embutidos no firmware;
# não há CA confiável para esses dispositivos em rede interna.
# Aplica em TODOS os urlopen (inclusive redirects HTTP→HTTPS invisíveis).
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from string import Template
from typing import Optional

print('[1/3] Carregando dependencias...')
import nmap
import pandas as pd
print('[2/3] Dependencias OK. Servidor de probe sera iniciado apos o scan.')

# ---------------------------------------------------------------------------
# Optional: SNMP support
# ---------------------------------------------------------------------------
try:
    from pysnmp.hlapi import (
        CommunityData, ContextData, ObjectIdentity,
        ObjectType, SnmpEngine, UdpTransportTarget, getCmd,
    )
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(threadName)s — %(message)s',
)
log = logging.getLogger(__name__)

def _setup_file_logging() -> None:
    """Adiciona RotatingFileHandler ao logger raiz.

    Cria automacao.log na pasta do script com rotação em 5 MB, 3 backups.
    Chamado uma única vez no main() após imports — não bloqueia o import do módulo.
    """
    from logging.handlers import RotatingFileHandler
    log_path = BASE_DIR / 'automacao.log'
    handler = RotatingFileHandler(
        log_path,
        maxBytes=5 * 1024 * 1024,   # 5 MB
        backupCount=3,
        encoding='utf-8',
    )
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(threadName)s — %(message)s'
    ))
    logging.getLogger().addHandler(handler)
    log.info(f'Log em arquivo iniciado: {log_path}')

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_DIR       = Path(__file__).parent
CSV_PATH       = BASE_DIR / 'Redes Imps CDS' / 'Endereçamento_Atualizado.csv'
INVENTORY_PATH        = BASE_DIR / 'inventory.html'
CACHE_PATH            = BASE_DIR / 'cache.json'
CREDENTIALS_PATH      = BASE_DIR / 'printer_credentials.json'
ADMIN_KEY_PATH        = BASE_DIR / 'admin.key'
TEMPLATE_PATH         = BASE_DIR / 'Templates' / 'inventory_template.html'

# Carrega configuráveis de config.py (que lê .env)
try:
    from config import (
        PROBE_PORT, SNMP_COMMUNITY, SNMP_TIMEOUT, HTTP_TIMEOUT, MAX_CONCURRENT,
        HP_EWS_USERS, HP_EWS_PASSWORDS, HP_EWS_USER, HP_EWS_PASSWORD,
        SAMSUNG_USER, SAMSUNG_PASSWORDS,
        ZEBRA_USER, ZEBRA_PASSWORDS,
    )
except ImportError:
    # Fallback se config.py não estiver disponível
    PROBE_PORT      = 5001
    SNMP_COMMUNITY  = 'public'
    SNMP_TIMEOUT    = 2
    HTTP_TIMEOUT    = 3
    MAX_CONCURRENT  = 10
    HP_EWS_USERS     = ['administrador', 'admin']
    HP_EWS_PASSWORDS = ['simpress1934@', '12345678', '']
    HP_EWS_USER      = HP_EWS_USERS[0]
    HP_EWS_PASSWORD  = HP_EWS_PASSWORDS[0]
    SAMSUNG_USER      = 'admin'
    SAMSUNG_PASSWORDS = ['sec00000', '1111', 'simpress1934@', '12345678', '3737', '']
    ZEBRA_USER        = 'admin'
    ZEBRA_PASSWORDS   = ['1234', '1934', '3737', '']

NMAP_ARGS       = '-p 80,443,631,9100 --open -T4'

# ---------------------------------------------------------------------------
# Admin auth helpers
# ---------------------------------------------------------------------------
def _load_admin_password() -> str:
    """Carrega a senha do admin de admin.key.
    Se o arquivo não existir, cria com senha padrão 'admin' e avisa."""
    import hashlib
    if ADMIN_KEY_PATH.exists():
        return ADMIN_KEY_PATH.read_text(encoding='utf-8').strip()
    # Primeira execução — cria arquivo com senha padrão
    default = 'admin'
    ADMIN_KEY_PATH.write_text(default, encoding='utf-8')
    log.warning(
        f'Arquivo admin.key criado com senha padrão "{default}". '
        'Altere o conteúdo do arquivo para uma senha segura.'
    )
    return default


def _check_admin_password(password: str) -> bool:
    """Compara a senha fornecida com a do admin.key (timing-safe)."""
    import hmac
    expected = _load_admin_password()
    return hmac.compare_digest(password.encode(), expected.encode())

# ---- OIDs -------------------------------------------------------------------
# RFC 3805 (Standard Printer MIB)
OID_SERIAL        = '1.3.6.1.2.1.43.5.1.1.17.1'
OID_PAGE_COUNT    = '1.3.6.1.2.1.43.10.2.1.4.1.1'
OID_MODEL_STD     = '1.3.6.1.2.1.25.3.2.1.3.1'   # hrDeviceDescr — modelo genérico
OID_MODEL_STD2    = '1.3.6.1.2.1.43.5.1.1.16.1'  # prtGeneralPrinterName

# HP-specific (jetdirect MIB)
OID_HP_MODEL      = '1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.3.0'   # modelo HP
OID_HP_TONER      = '1.3.6.1.4.1.11.2.3.9.4.2.1.1.5.28.1'  # toner HP (% restante)
OID_HP_MAINT_KIT  = '1.3.6.1.4.1.11.2.3.9.4.2.1.1.5.28.5'  # kit manutenção HP

# Samsung-specific (CLX/SL MIB)
OID_SAMSUNG_MODEL = '1.3.6.1.4.1.236.11.5.1.1.1.1.0'        # modelo Samsung
OID_SAMSUNG_TONER = '1.3.6.1.4.1.236.11.5.11.81.1.1.1.20.1' # toner Samsung (% ou pct)
OID_SAMSUNG_DRUM  = '1.3.6.1.4.1.236.11.5.11.81.1.1.1.40.1' # unidade de imagem Samsung

# Zebra serial + odômetro
OID_ZEBRA_SERIAL_1    = '1.3.6.1.4.1.10642.1.9.0'       # ZebraNet MIB
OID_ZEBRA_SERIAL_2    = '1.3.6.1.4.1.683.6.2.3.2.1.6.1' # Eltron/legado
OID_ZEBRA_MODEL       = '1.3.6.1.4.1.10642.1.1.7.0'     # ZebraNet model string
OID_ZEBRA_ODOM_ELTRON = '1.3.6.1.4.1.683.6.2.3.6.1.2.1' # polegadas (legado GK/LP)
OID_ZEBRA_ODOM_DOTS   = '1.3.6.1.4.1.10642.1.1.8.0'     # dot count (ZT/ZD ÷ DPI)
ZEBRA_DEFAULT_DPI     = 203

# Honeywell/Intermec
OID_HONEYWELL_MODEL   = '1.3.6.1.4.1.1248.1.1.3.1.3.0'  # Honeywell model

# ---- OIDs de configuracao de rede (HP JetDirect MIB) ----------------------
OID_HP_HOSTNAME       = '1.3.6.1.4.1.11.2.4.3.5.2.0'    # hostname
OID_HP_DNS_PRIMARY    = '1.3.6.1.4.1.11.2.4.3.5.29.0'   # DNS primario
OID_HP_DNS_SECONDARY  = '1.3.6.1.4.1.11.2.4.3.5.30.0'   # DNS secundario
OID_HP_GATEWAY        = '1.3.6.1.4.1.11.2.4.3.5.20.0'   # gateway padrao
OID_HP_IP_CONFIG      = '1.3.6.1.4.1.11.2.4.3.5.16.0'   # modo IP (1=DHCP, 2=Manual)
OID_STD_HOSTNAME      = '1.3.6.1.2.1.1.5.0'              # RFC 1213 sysName

# ---- Credenciais para aplicacao de DNS ------------------------------------
# HP — SNMP SET (community de escrita)
SNMP_WRITE_COMMUNITY  = 'public'

# ---- Classificação de fabricantes -----------------------------------------
KNOWN_MANUFACTURERS   = frozenset({'HP', 'Samsung', 'Zebra', 'Honeywell'})
LASER_MANUFACTURERS   = frozenset({'HP', 'Samsung'})
THERMAL_MANUFACTURERS = frozenset({'Zebra', 'Honeywell'})

_MFR_KEYWORDS: dict[str, tuple[str, ...]] = {
    'HP':        ('hp', 'laserjet', 'hewlett', 'hp-http', 'jetdirect'),
    'Samsung':   ('samsung',),
    'Zebra':     ('zebra', 'zpl', 'zebra technologies'),
    'Honeywell': ('honeywell', 'intermec', 'datamax'),
}

# Semáforo para limitar scans nmap paralelos
_nmap_sem = threading.Semaphore(MAX_CONCURRENT)

# ---------------------------------------------------------------------------
# Status de conectividade em memória — atualizado pelo healthcheck worker
# Separado do cache em arquivo para evitar I/O a cada ciclo de ping
# ---------------------------------------------------------------------------
_status_cache: dict[str, str] = {}   # ip → 'Online' | 'Offline'
_status_lock  = threading.Lock()

# Status global do scan — exposto via /api/status
_scan_status: dict = {
    'running':         False,
    'total':           0,
    'networks_done':   0,
    'networks_total':  0,
    'started_at':      None,
    'finished_at':     None,
}

# Momento de início do servidor — exposto via /healthcheck
_server_start_time: datetime = datetime.now()

# Flask é carregado apenas quando o servidor de probe precisa subir
_flask_app = None


def _get_flask_app():
    """Import e criação lazy do app Flask — evita lentidão no startup."""
    global _flask_app
    if _flask_app is not None:
        return _flask_app
    from flask import Flask, jsonify, render_template, request as flask_request
    import logging as _pylog, os as _os
    _pylog.getLogger('werkzeug').setLevel(_pylog.WARNING)
    _flask_app = Flask(__name__)
    # secret_key para sessões: usa arquivo admin.key como semente
    _flask_app.secret_key = _load_admin_password() + '_session_salt_v1'
    _register_routes(_flask_app, flask_request, jsonify, render_template)
    return _flask_app

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class PrinterInfo:
    ip:           str
    fabricante:   str
    modelo:       Optional[str]  # modelo do equipamento (HTTP ou SNMP)
    serial:       str
    metrica:      Optional[str]  # páginas (laser) | polegadas (térmica Zebra)
    # Consumiveis laser
    toner:        Optional[str]  # % restante ou descrição
    consumivel2:  Optional[str]  # kit manut. (HP) | unid. imagem (Samsung)
    status:       str
    filial:       str
    tipo:         str            # 'laser' | 'termica' (corrigido pelo fabricante)
    first_seen:   str            # ISO datetime do primeiro scan
    last_updated: str            # ISO datetime da última atualização de métrica
    # Configuração de rede
    hostname:     Optional[str] = None
    dns1:         Optional[str] = None
    dns2:         Optional[str] = None
    gateway:      Optional[str] = None
    ip_mode:      Optional[str] = None   # 'DHCP' | 'Manual' | 'AutoIP'
    dns_apply_status: Optional[str] = None  # resultado da última aplicação de DNS
    auth_ok:          Optional[bool] = None  # True se login HTTP na interface web funcionou
    auth_user:        Optional[str]  = None  # usuário que autenticou na interface web

    def to_dict(self) -> dict:
        return asdict(self)

# ---------------------------------------------------------------------------
# Carregar redes do CSV (somente redes já preenchidas no CSV)
# ---------------------------------------------------------------------------
def load_network_entries() -> list[dict]:
    """Carrega entradas de rede do CSV (estrutura: CD + Range 01..16).

    Todas as redes de um CD são escaneadas sem distinção de tipo —
    o tipo laser/termica é determinado pelo fabricante detectado no host.
    """
    try:
        df = pd.read_csv(CSV_PATH, dtype=str)
    except FileNotFoundError:
        log.error(f'CSV não encontrado: {CSV_PATH}')
        return []
    except Exception as exc:
        log.error(f'Erro ao ler CSV: {exc}', exc_info=True)
        return []

    # Identifica colunas de range dinamicamente (Range 01, Range 02, ...)
    range_cols = [c for c in df.columns if c.strip().lower().startswith('range')]

    entries: list[dict] = []
    seen: set[tuple] = set()

    for _, row in df.iterrows():
        cd = str(row.get('CD', '')).strip()
        if not cd or cd in ('nan', 'NaN'):
            continue

        for col in range_cols:
            raw_net = str(row.get(col, '')).strip()
            if (not raw_net
                    or raw_net in ('nan', 'NaN', '')
                    or '/' not in raw_net):
                continue
            try:
                ipaddress.ip_network(raw_net, strict=False)
            except ValueError:
                log.warning(f'CIDR inválido ignorado: {raw_net!r}')
                continue

            key = (raw_net, cd)
            if key not in seen:
                seen.add(key)
                entries.append({'network': raw_net, 'cd': cd})

    log.info(f'{len(entries)} redes carregadas para {len({e["cd"] for e in entries})} CDs.')
    return entries

# ---------------------------------------------------------------------------
# SNMP — implementação pura Python (fallback sem pysnmp)
# ---------------------------------------------------------------------------
def _snmp_get_raw(ip: str, oid: str) -> Optional[str]:
    def _ber_len(n: int) -> bytes:
        if n < 128:
            return bytes([n])
        if n < 256:
            return b'\x81' + bytes([n])
        return b'\x82' + bytes([(n >> 8) & 0xff, n & 0xff])

    def _tlv(tag: int, val: bytes) -> bytes:
        return bytes([tag]) + _ber_len(len(val)) + val

    def _ber_int(n: int) -> bytes:
        if n == 0:
            return _tlv(0x02, b'\x00')
        buf: list[int] = []
        m = n
        while m:
            buf.append(m & 0xff)
            m >>= 8
        buf.reverse()
        if buf[0] & 0x80:
            buf.insert(0, 0)
        return _tlv(0x02, bytes(buf))

    def _ber_oid(s: str) -> bytes:
        parts = [int(x) for x in s.strip('.').split('.')]
        result: list[int] = [parts[0] * 40 + parts[1]]
        for p in parts[2:]:
            if p == 0:
                result.append(0)
            else:
                buf2: list[int] = []
                v = p
                while v:
                    buf2.append(v & 0x7f)
                    v >>= 7
                buf2.reverse()
                for i in range(len(buf2) - 1):
                    buf2[i] |= 0x80
                result.extend(buf2)
        return _tlv(0x06, bytes(result))

    def _read_tlv(data: bytes, pos: int):
        if pos + 2 > len(data):
            return None, None, pos
        tag = data[pos]; pos += 1
        ln  = data[pos]; pos += 1
        if ln & 0x80:
            nb = ln & 0x7f
            if pos + nb > len(data):
                return None, None, pos
            ln = int.from_bytes(data[pos:pos + nb], 'big')
            pos += nb
        if pos + ln > len(data):
            return None, None, pos
        return tag, data[pos:pos + ln], pos + ln

    vb  = _tlv(0x30, _ber_oid(oid) + _tlv(0x05, b''))
    vbl = _tlv(0x30, vb)
    pdu = _tlv(0xa0, _ber_int(1) + _ber_int(0) + _ber_int(0) + vbl)
    pkt = _tlv(0x30, _ber_int(0) + _tlv(0x04, SNMP_COMMUNITY.encode()) + pdu)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(SNMP_TIMEOUT)
            s.sendto(pkt, (ip, 161))
            resp, _ = s.recvfrom(4096)
    except Exception:
        return None

    tag, inner, _ = _read_tlv(resp, 0)
    if tag != 0x30 or inner is None:
        return None
    p = 0
    for _ in range(2):
        tag, _, p = _read_tlv(inner, p)
    tag, pdu_val, _ = _read_tlv(inner, p)
    if tag != 0xa2 or pdu_val is None:
        return None
    p = 0
    for _ in range(3):
        tag, _, p = _read_tlv(pdu_val, p)
    tag, vbl_val, _ = _read_tlv(pdu_val, p)
    if tag != 0x30 or vbl_val is None:
        return None
    tag, vb_val, _ = _read_tlv(vbl_val, 0)
    if tag != 0x30 or vb_val is None:
        return None
    p = 0
    tag, _, p = _read_tlv(vb_val, p)
    if tag != 0x06:
        return None
    tag, v_val, _ = _read_tlv(vb_val, p)
    if not v_val:
        return None
    if tag == 0x04:
        decoded = v_val.decode('latin-1', errors='ignore').strip().strip('.')
        return decoded if decoded and not decoded.startswith('\x00') else None
    if tag in (0x02, 0x41, 0x42, 0x46):
        return str(int.from_bytes(v_val, 'big', signed=(tag == 0x02)))
    return None


def _snmp_get(ip: str, oid: str) -> Optional[str]:
    if SNMP_AVAILABLE:
        try:
            err_ind, err_st, _, var_binds = next(getCmd(
                SnmpEngine(),
                CommunityData(SNMP_COMMUNITY, mpModel=0),
                UdpTransportTarget((ip, 161), timeout=SNMP_TIMEOUT, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            ))
            if err_ind or err_st:
                return None
            value = str(var_binds[0][1]).strip()
            return value if value else None
        except Exception:
            return None
    return _snmp_get_raw(ip, oid)


def get_serial(ip: str, manufacturer: str) -> str:
    """Obtém serial número; para Zebra tenta OIDs específicos primeiro."""
    if manufacturer == 'Zebra':
        for oid in (OID_ZEBRA_SERIAL_1, OID_ZEBRA_SERIAL_2, OID_SERIAL):
            val = _snmp_get(ip, oid)
            if val and val != 'N/A':
                return val
        return 'N/A'
    return _snmp_get(ip, OID_SERIAL) or 'N/A'


# ---------------------------------------------------------------------------
# Retry com backoff exponencial — apenas para chamadas HTTP
# ---------------------------------------------------------------------------

def _with_retry(fn, *, attempts: int = 3, base_delay: float = 1.0):
    """Executa fn() até `attempts` vezes com backoff exponencial.

    Espera: base_delay * 2^tentativa + jitter ±20 %.
    Retorna o resultado de fn() quando bem-sucedido (não-None).
    Se todos os attempts falharem, retorna None.
    Só retentar em urllib.error.URLError / OSError / TimeoutError.
    Erros 4xx (HTTPError com status 4xx) não são retriados.
    """
    import random
    for attempt in range(attempts):
        try:
            result = fn()
        except Exception:
            result = None
        if result is not None:
            return result
        if attempt < attempts - 1:
            delay = base_delay * (2 ** attempt)
            jitter = delay * 0.2 * (2 * random.random() - 1)  # ±20 %
            time.sleep(max(0.0, delay + jitter))
    return None


def _http_get_page(ip: str, path: str, use_https: bool = False,
                   timeout: int = HTTP_TIMEOUT) -> Optional[str]:
    """GET helper — retorna body (str) ou None em caso de erro.

    Retentar até 3 vezes com backoff exponencial em caso de falha de rede.
    Erros 4xx (recurso não existe) não são retriados.
    """
    scheme = 'https' if use_https else 'http'
    url = f'{scheme}://{ip}{path}'

    def _attempt() -> Optional[str]:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'PrinterScanner/1.0'})
            with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
                return resp.read(65536).decode('utf-8', errors='ignore')
        except urllib.error.HTTPError as e:
            if 400 <= e.code < 500:
                return None   # 4xx: não adianta retentar
            raise             # 5xx ou outro: _with_retry capturará como None
        except Exception:
            return None

    return _with_retry(_attempt)


# ---------------------------------------------------------------------------
# Configuração de rede (DNS, Gateway, Hostname)
# ---------------------------------------------------------------------------

def get_network_config(ip: str, manufacturer: str) -> dict:
    # Coleta hostname, DNS1, DNS2, gateway e modo IP do equipamento.
    # HP      -> SNMP JetDirect MIB  -> EWS JSON  -> SyncThru (/sws/)
    # Samsung -> SyncThru (/sws/)
    # Zebra   -> SNMP ZebraNet MIB + HTTP /server/NWSET.htm
    #
    # auth_ok/auth_user registram se login HTTP foi bem-sucedido.
    # None  = nao tentou HTTP auth / SNMP suficiente
    # False = tentou, falhou em todas as credenciais
    # True  = autenticou via HTTP com sucesso
    import re, json as _json
    result = {'hostname': None, 'dns1': None, 'dns2': None,
              'gateway': None, 'ip_mode': None,
              'auth_ok': None, 'auth_user': None}

    # Credenciais salvas manualmente para este IP tem prioridade
    _saved = load_printer_credentials().get(ip, {})
    _sv_u  = _saved.get('user', '')
    _sv_p  = _saved.get('password', '')

    def _sws_parse(flat):
        # Extrai campos DNS/gateway/hostname/modo de JSON serializado.
        dns1_m = re.search(r'(?:primaryDns|dns1|preferredDns)["\s]+([\.\d]{7,15})', flat, re.I)
        dns2_m = re.search(r'(?:secondaryDns|dns2|alternateDns)["\s]+([\.\d]{7,15})', flat, re.I)
        gw_m   = re.search(r'(?:gateway|defaultGateway)["\s]+([\.\d]{7,15})', flat, re.I)
        hn_m   = re.search(r'(?:hostName|hostname)["\s:]+"([^"]{2,80})"', flat, re.I)
        dhcp_m = re.search(r'(?:dhcp|ipMode|ipMethod)["\s:]+"?([\w]+)"?', flat, re.I)
        if not dns1_m:
            return False
        result['dns1']     = dns1_m.group(1)
        result['dns2']     = dns2_m.group(1) if dns2_m else None
        result['gateway']  = gw_m.group(1)   if gw_m   else result.get('gateway')
        result['hostname'] = hn_m.group(1)   if hn_m   else result.get('hostname')
        if dhcp_m:
            v = dhcp_m.group(1).upper()
            result['ip_mode'] = 'DHCP' if 'DHCP' in v or v == 'TRUE' else 'Manual'
        return True

    def _try_sws(sws_users, sws_pwds):
        # Tenta configuracao de rede via SyncThru. Retorna True se achou DNS.
        _tried_auth = False
        for sws_path in ('/sws/app/information/network/networkSetting.json',
                         '/sws/swsapi/swsconfig?subtype=networkSetting'):
            body = _http_get_page(ip, sws_path)
            if not body:
                _tried_auth = True
                for u in sws_users:
                    for pw in sws_pwds:
                        body = _http_get_authenticated(ip, sws_path, u, pw)
                        if body:
                            result['auth_ok']   = True
                            result['auth_user'] = u
                            break
                    if body:
                        break
            if not body:
                continue
            try:
                if _sws_parse(_json.dumps(_json.loads(body))):
                    return True
            except Exception:
                pass
        if _tried_auth and result.get('auth_ok') is None:
            result['auth_ok'] = False
        return False

    if manufacturer == 'HP':
        # --- SNMP JetDirect (mais confiavel) ---
        hn  = _snmp_get(ip, OID_HP_HOSTNAME) or _snmp_get(ip, OID_STD_HOSTNAME)
        d1  = _snmp_get(ip, OID_HP_DNS_PRIMARY)
        d2  = _snmp_get(ip, OID_HP_DNS_SECONDARY)
        gw  = _snmp_get(ip, OID_HP_GATEWAY)
        raw_mode = _snmp_get(ip, OID_HP_IP_CONFIG)
        mode_map = {'1': 'BOOTP', '2': 'DHCP', '3': 'Manual', '4': 'AutoIP'}
        if raw_mode and raw_mode.isdigit():
            ip_mode = mode_map.get(raw_mode, f'Codigo {raw_mode}')
        else:
            ip_mode = raw_mode
        # Aceita apenas IPs reais do SNMP.
        # 'NOT_SET' indica DNS nao configurado manualmente (DHCP) — nao bloqueia
        # o fallback EWS JSON, que pode retornar o IP DHCP real atribuido.
        _IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        _snmp_notset = bool(d1 and str(d1).strip().upper() in ('NOT_SET', 'NOTSET', 'NOT SET'))
        result.update({
            'hostname': hn,
            'dns1':    d1 if (d1 and _IP_RE.match(d1.strip())) else None,
            'dns2':    d2 if (d2 and _IP_RE.match(d2.strip())) else None,
            'gateway': gw, 'ip_mode': ip_mode,
        })

        # --- Fallback EWS JSON (HP tradicionais) ---
        if not result['dns1']:
            _ews_tried = False
            for use_https in (True, False):
                body = _http_get_page(ip, '/DevMgmt/NetworkConfigDyn.json',
                                      use_https=use_https)
                if not body:
                    _ews_tried = True
                    _ews_users = ([_sv_u] if _sv_u else []) + HP_EWS_USERS
                    _ews_pwds  = ([_sv_p] if _sv_p else []) + HP_EWS_PASSWORDS
                    for u in _ews_users:
                        for pw in _ews_pwds:
                            body = _http_get_authenticated(
                                ip, '/DevMgmt/NetworkConfigDyn.json', u, pw, use_https)
                            if body:
                                result['auth_ok']   = True
                                result['auth_user'] = u
                                break
                        if body:
                            break
                if not body:
                    continue
                try:
                    data = _json.loads(body)
                    def _deep(d, *keys):
                        for k in keys:
                            d = d.get(k) if isinstance(d, dict) else None
                        return d
                    dns_cfg = _deep(data, 'NetworkConfigDyn', 'IPConfiguration', 'DNS')
                    if dns_cfg:
                        result['dns1'] = dns_cfg.get('PreferredServer') or result['dns1']
                        result['dns2'] = dns_cfg.get('AlternateServer')  or result['dns2']
                    gw_cfg = _deep(data, 'NetworkConfigDyn', 'IPConfiguration', 'DefaultGateway')
                    if gw_cfg:
                        result['gateway'] = gw_cfg or result['gateway']
                except Exception:
                    pass
                break
            if _ews_tried and result.get('auth_ok') is None:
                result['auth_ok'] = False

        # --- Fallback SyncThru (HP Laser 408 e similares) ---
        if not result['dns1']:
            _hp_sws_users = ([_sv_u] if _sv_u else []) + HP_EWS_USERS
            _hp_sws_pwds  = ([_sv_p] if _sv_p else []) + HP_EWS_PASSWORDS
            _try_sws(_hp_sws_users, _hp_sws_pwds)

    elif manufacturer == 'Samsung':
        _sam_users = [_sv_u] if _sv_u else [SAMSUNG_USER]
        _sam_pwds  = ([_sv_p] if _sv_p else []) + SAMSUNG_PASSWORDS
        _try_sws(_sam_users, _sam_pwds)

    elif manufacturer == 'Zebra':
        # Hostname via SNMP sysName
        result['hostname'] = _snmp_get(ip, OID_STD_HOSTNAME)
        # Gateway via ZebraNet SNMP MIB
        gw_snmp = _snmp_get(ip, '1.3.6.1.4.1.10642.1.2.3.3.0')
        if gw_snmp and gw_snmp not in ('0.0.0.0', '0', ''):
            result['gateway'] = gw_snmp
        # DNS via HTTP scraping do ZebraNet web (/server/NWSET.htm)
        _z_user = _sv_u or ZEBRA_USER
        _z_pwds = ([_sv_p] if _sv_p else []) + ZEBRA_PASSWORDS
        _z_tried = False
        for use_https in (False, True):
            body = _http_get_page(ip, '/server/NWSET.htm', use_https=use_https)
            if not body:
                _z_tried = True
                for pw in _z_pwds:
                    body = _http_get_authenticated(ip, '/server/NWSET.htm',
                                                   _z_user, pw, use_https=use_https)
                    if body:
                        result['auth_ok']   = True
                        result['auth_user'] = _z_user
                        break
            if body:
                d1 = re.search(r"name=[\"']?(?:dns1|DNS1|primarydns)[\"']?[^>]*?value=[\"']([.\d]{7,15})[\"']", body, re.I)
                d2 = re.search(r"name=[\"']?(?:dns2|DNS2|secondarydns)[\"']?[^>]*?value=[\"']([.\d]{7,15})[\"']", body, re.I)
                gw = re.search(r"name=[\"']?(?:gw|gateway|defaultgateway)[\"']?[^>]*?value=[\"']([.\d]{7,15})[\"']", body, re.I)
                if not d1:
                    d1 = re.search(r"(?i)dns.{0,20}?value=[\"']([.\d]{7,15})[\"']", body)
                if d1:
                    result['dns1'] = d1.group(1)
                    if d2: result['dns2']    = d2.group(1)
                    if gw: result['gateway'] = gw.group(1) or result.get('gateway')
                    break
        if _z_tried and result.get('auth_ok') is None:
            result['auth_ok'] = False
        dhcp_oid = _snmp_get(ip, '1.3.6.1.4.1.10642.1.2.3.4.0')
        if dhcp_oid:
            result['ip_mode'] = 'DHCP' if dhcp_oid in ('1', 'true', 'dhcp') else 'Manual'

    # Limpa strings vazias / zero IPs
    for k in ('dns1', 'dns2', 'gateway'):
        v = result.get(k)
        if v in (None, '', '0.0.0.0', '0'):
            result[k] = None

    # Se HP esgotou todos os fallbacks HTTP e o SNMP havia confirmado 'NOT_SET'
    # (DNS nao configurado manualmente), grava o marcador para evitar re-tentativa
    # desnecessaria em ciclos futuros quando auth_ok ja for False.
    if manufacturer == 'HP' and not result.get('dns1') and _snmp_notset:
        result['dns1'] = 'NOT_SET'

    log.debug(f'[netcfg] {ip} -> {result}')
    return result

def _http_get_authenticated(ip: str, path: str, user: str, password: str,
                            use_https: bool = False) -> Optional[str]:
    """GET HTTP com autenticação Basic Auth."""
    import base64
    scheme = 'https' if use_https else 'http'
    url = f'{scheme}://{ip}{path}'
    creds = base64.b64encode(f'{user}:{password}'.encode()).decode()
    try:
        req = urllib.request.Request(
            url,
            headers={
                'Authorization': f'Basic {creds}',
                'User-Agent': 'PrinterScanner/1.0',
            },
        )
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=_SSL_CTX) as r:
            return r.read(65536).decode('utf-8', errors='ignore')
    except Exception as e:
        log.debug(f'[http_get_auth] {ip}{path} erro: {e}')
        return None


def _snmp_set_string(ip: str, oid: str, value: str) -> bool:
    """SNMP SET OctetString usando community de escrita. Retorna True se OK."""
    # BER helpers
    def _bl(n):
        if n < 128:  return bytes([n])
        if n < 256:  return b'\x81' + bytes([n])
        return b'\x82' + bytes([(n >> 8) & 0xff, n & 0xff])
    def _tlv(t, v):  return bytes([t]) + _bl(len(v)) + v
    def _bi(n):
        if n == 0:  return _tlv(0x02, b'\x00')
        buf = []; m = n
        while m:  buf.append(m & 0xff); m >>= 8
        buf.reverse()
        if buf[0] & 0x80:  buf.insert(0, 0)
        return _tlv(0x02, bytes(buf))
    def _boid(s):
        p = [int(x) for x in s.strip('.').split('.')]
        r = [p[0] * 40 + p[1]]
        for v in p[2:]:
            if v == 0:  r.append(0)
            else:
                b = []; x = v
                while x:  b.append(x & 0x7f); x >>= 7
                b.reverse()
                for i in range(len(b) - 1):  b[i] |= 0x80
                r.extend(b)
        return _tlv(0x06, bytes(r))

    vb  = _tlv(0x30, _boid(oid) + _tlv(0x04, value.encode()))
    pdu = _tlv(0xa3, _bi(2) + _bi(0) + _bi(0) + _tlv(0x30, vb))  # 0xa3 = SetRequest
    pkt = _tlv(0x30, _bi(0) + _tlv(0x04, SNMP_WRITE_COMMUNITY.encode()) + pdu)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(SNMP_TIMEOUT)
            s.sendto(pkt, (ip, 161))
            resp, _ = s.recvfrom(1024)
        # Parseia o SetResponse SNMP corretamente.
        # resp[0] == 0x30 e sempre verdadeiro para QUALQUER pacote SNMP (incluindo erros).
        # Precisa verificar:
        #   1. O PDU type e 0xa2 (SetResponse, nao GetResponse ou error)
        #   2. error-status == 0 (noError)
        if len(resp) < 10 or resp[0] != 0x30:
            return False
        i = 1
        # Skip outer SEQUENCE length (suporta forma longa 0x81/0x82)
        i += (resp[i] & 0x7f) + 1 if (resp[i] & 0x80) else 1
        # Skip version INTEGER (0x02 0x01 0x00)
        if i >= len(resp) or resp[i] != 0x02: return False
        i += 2 + resp[i + 1]
        # Skip community OCTET STRING (0x04 len bytes...)
        if i >= len(resp) or resp[i] != 0x04: return False
        i += 2 + resp[i + 1]
        # PDU type deve ser 0xa2 (SetResponse-PDU)
        # 0xa2 = GetResponse-PDU tag, reutilizado por Set; qualquer outro = erro/rejeicao
        if i >= len(resp) or resp[i] != 0xa2:
            log.debug(f'[snmp_set] {ip} OID={oid} PDU type inesperado: {resp[i] if i < len(resp) else "EOF"}')
            return False
        i += 1
        # Skip PDU length
        i += (resp[i] & 0x7f) + 1 if (resp[i] & 0x80) else 1
        # Skip request-id INTEGER
        if i >= len(resp) or resp[i] != 0x02: return False
        i += 2 + resp[i + 1]
        # Ler error-status INTEGER — deve ser 0 (noError)
        # Codigos comuns: 1=tooBig, 2=noSuchName, 3=badValue, 4=readOnly, 5=genErr
        if i >= len(resp) or resp[i] != 0x02: return False
        i += 1
        elen = resp[i]; i += 1
        err_status = int.from_bytes(resp[i:i + elen], 'big')
        if err_status != 0:
            _err_names = {1:'tooBig',2:'noSuchName',3:'badValue',4:'readOnly',5:'genErr'}
            log.debug(f'[snmp_set] {ip} OID={oid} error-status={err_status} ({_err_names.get(err_status,"?")})')
            return False
        return True
    except Exception as e:
        log.debug(f'[snmp_set] {ip} OID={oid} erro: {e}')
        return False


def _http_post_authenticated(ip: str, path: str, payload: str,
                              user: str, password: str,
                              content_type: str = 'application/x-www-form-urlencoded',
                              use_https: bool = False) -> Optional[str]:
    """POST HTTP com autenticação Basic.

    Retentar até 3 vezes com backoff exponencial em caso de falha de rede.
    Erros 4xx não são retriados (credencial inválida, recurso inexistente).
    """
    import base64
    scheme = 'https' if use_https else 'http'
    url = f'{scheme}://{ip}{path}'
    creds = base64.b64encode(f'{user}:{password}'.encode()).decode()

    def _attempt() -> Optional[str]:
        try:
            req = urllib.request.Request(
                url,
                data=payload.encode(),
                headers={
                    'Authorization': f'Basic {creds}',
                    'Content-Type':  content_type,
                    'User-Agent':    'PrinterScanner/1.0',
                },
                method='POST',
            )
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=_SSL_CTX) as r:
                return r.read(4096).decode('utf-8', errors='ignore')
        except urllib.error.HTTPError as e:
            if 400 <= e.code < 500:
                return None   # 4xx: não adianta retentar
            raise
        except Exception as e:
            log.debug(f'[http_post] {ip}{path} erro: {e}')
            return None

    return _with_retry(_attempt)


def _samsung_syncthru_set_dns(ip: str, user: str, password: str,
                               dns1: str, dns2: str,
                               use_https: bool = False) -> bool:
    """Login no Samsung SyncThru via cookie de sessão e aplica DNS.

    O SyncThru ML/SL series usa autenticação baseada em sessão (cookie), não
    HTTP Basic. O fluxo é:
      1. POST /sws/security/login.json  → obtém cookie de sessão
      2. PUT/POST /sws/swsapi/swsconfig?subtype=networkSetting  → aplica DNS

    Retorna True se o DNS foi aplicado com sucesso.
    """
    import http.cookiejar, json as _json, urllib.parse

    scheme = 'https' if use_https else 'http'
    jar    = http.cookiejar.CookieJar()
    # Sempre inclui HTTPSHandler com _SSL_CTX para cobrir redirects HTTP→HTTPS
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=_SSL_CTX),
    )

    # --- Passo 1: Login ---
    login_url = f'{scheme}://{ip}/sws/security/login.json'
    # Tenta JSON e depois form-encoded (firmwares mais antigos usam form)
    login_attempts = [
        (_json.dumps({"login": {"id": user, "passwd": password,
                                "idleTimeout": "60"}}).encode(),
         'application/json'),
        (urllib.parse.urlencode({"login[id]": user,
                                 "login[passwd]": password}).encode(),
         'application/x-www-form-urlencoded'),
    ]
    login_ok = False
    for body, ctype in login_attempts:
        try:
            req = urllib.request.Request(
                login_url, data=body,
                headers={'Content-Type': ctype, 'User-Agent': 'PrinterScanner/1.0'},
                method='POST',
            )
            with opener.open(req, timeout=HTTP_TIMEOUT) as r:
                resp = r.read(512).decode('utf-8', errors='ignore')
            # Considera login OK se: algum cookie foi setado OU resposta indica sucesso
            has_cookie = any(True for _ in jar)
            resp_ok    = ('"status"' in resp and ('": 1' in resp or '":1' in resp
                                                   or ': true' in resp.lower()))
            if has_cookie or resp_ok:
                login_ok = True
                log.debug(f'[samsung_login] {ip} login OK user={user!r} ctype={ctype}')
                break
        except Exception as e:
            log.debug(f'[samsung_login] {ip} login erro ({ctype}): {e}')

    if not login_ok:
        log.debug(f'[samsung_login] {ip} login falhou user={user!r} https={use_https}')
        return False

    # --- Passo 2: Aplica DNS ---
    dns_payload = _json.dumps({
        'networkSetting': {
            'tcpip': {'dns': {'primaryDns': dns1, 'secondaryDns': dns2}}
        }
    }).encode()
    for method, path in (
        ('PUT',  f'{scheme}://{ip}/sws/swsapi/swsconfig?subtype=networkSetting'),
        ('POST', f'{scheme}://{ip}/sws/swsapi/swsconfig?subtype=networkSetting'),
        ('POST', f'{scheme}://{ip}/sws/app/information/network/networkSetting'),
    ):
        try:
            req = urllib.request.Request(
                path, data=dns_payload,
                headers={'Content-Type': 'application/json',
                         'User-Agent': 'PrinterScanner/1.0'},
                method=method,
            )
            with opener.open(req, timeout=HTTP_TIMEOUT) as r:
                resp = r.read(1024).decode('utf-8', errors='ignore')
            if any(x in resp.lower() for x in ('ok', 'success', 'true', '"status"')):
                log.info(f'[samsung_dns] {ip} {method} ok: {dns1}/{dns2} user={user!r}')
                return True
        except Exception as e:
            log.debug(f'[samsung_dns] {ip} {method} {path} erro: {e}')
    return False


# ---------------------------------------------------------------------------
# Strategy: Adaptadores de DNS por fabricante
# ---------------------------------------------------------------------------

class VendorAdapter:
    """Interface base para aplicar DNS em um fabricante específico."""

    def apply_dns(self, ip: str, dns1: str, dns2: str) -> dict:
        raise NotImplementedError


class _HPAdapter(VendorAdapter):
    def apply_dns(self, ip: str, dns1: str, dns2: str) -> dict:
        import urllib.parse, json as _json

        # Tentativa 1: SNMP SET JetDirect
        ok1 = _snmp_set_string(ip, OID_HP_DNS_PRIMARY,   dns1)
        ok2 = _snmp_set_string(ip, OID_HP_DNS_SECONDARY, dns2)
        if ok1 and ok2:
            log.info(f'[apply_dns] {ip} HP SNMP SET ok: {dns1}/{dns2}')
            return {'ok': True, 'method': 'SNMP SET JetDirect',
                    'detail': f'DNS1={dns1} DNS2={dns2}'}

        # Tentativa 2: EWS HTTP (network_id.htm, SetStaticDNS, SyncThru)
        payload_ews = urllib.parse.urlencode({
            'PreferredDNSServer': dns1, 'AlternateDNSServer': dns2,
        })
        payload_sws = _json.dumps({
            'networkSetting': {'tcpip': {'dns': {'primaryDns': dns1, 'secondaryDns': dns2}}}
        })
        for use_https in (True, False):
            for u in HP_EWS_USERS:
                for pw in HP_EWS_PASSWORDS:
                    # network_id.htm — HP E-series (confirmado E60165)
                    if _hp_network_id_apply_dns(ip, dns1, dns2, u, pw, use_https=use_https):
                        log.info(f'[apply_dns] {ip} HP network_id.htm ok: {dns1}/{dns2}')
                        return {'ok': True,
                                'method': f'network_id.htm HTTP{"S" if use_https else ""}',
                                'detail': f'DNS1={dns1} DNS2={dns2} user={u}'}
                    # EWS SetStaticDNS (LaserJet Pro/Enterprise clássico)
                    resp = _http_post_authenticated(
                        ip, '/hp/device/IPConfiguration/SetStaticDNS',
                        payload_ews, u, pw, use_https=use_https)
                    if resp is not None:
                        verify = _http_get_authenticated(
                            ip, '/network_id.htm', u, pw, use_https=use_https)
                        if verify and dns1 in verify:
                            log.info(f'[apply_dns] {ip} HP EWS SetStaticDNS ok: {dns1}/{dns2}')
                            return {'ok': True,
                                    'method': f'EWS SetStaticDNS HTTP{"S" if use_https else ""}',
                                    'detail': f'DNS1={dns1} DNS2={dns2} user={u}'}
                        log.debug(f'[apply_dns] {ip} SetStaticDNS POST respondeu mas '
                                  f'DNS não mudou (use_https={use_https})')
                    # SyncThru (HP Laser 408 / Samsung-based)
                    for sws_path in ('/sws/swsapi/swsconfig?subtype=networkSetting',
                                     '/sws/app/information/network/networkSetting'):
                        resp2 = _http_post_authenticated(
                            ip, sws_path, payload_sws, u, pw,
                            content_type='application/json', use_https=use_https)
                        if resp2 and any(x in resp2.lower()
                                         for x in ('ok', 'success', 'true')):
                            log.info(f'[apply_dns] {ip} HP SyncThru ok: {dns1}/{dns2}')
                            return {'ok': True,
                                    'method': f'SyncThru HTTP{"S" if use_https else ""}',
                                    'detail': f'DNS1={dns1} DNS2={dns2} user={u}'}

        detail = ('SNMP SET falhou; EWS/network_id.htm: campos DNS não identificados '
                  'ou POST rejeitado — verifique credenciais, HTTPS e versão de firmware')
        log.warning(f'[apply_dns] {ip} HP FALHOU: {detail}')
        return {'ok': False, 'method': '', 'detail': detail}


class _SamsungAdapter(VendorAdapter):
    def apply_dns(self, ip: str, dns1: str, dns2: str) -> dict:
        _saved = load_printer_credentials().get(ip, {})
        _candidates: list = []
        if _saved.get('password'):
            _candidates.append((_saved.get('user', SAMSUNG_USER), _saved['password']))
        for pw in SAMSUNG_PASSWORDS:
            entry = (SAMSUNG_USER, pw)
            if entry not in _candidates:
                _candidates.append(entry)

        for use_https in (False, True):
            for user, password in _candidates:
                if _samsung_syncthru_set_dns(ip, user, password, dns1, dns2,
                                             use_https=use_https):
                    log.info(f'[apply_dns] {ip} Samsung SyncThru ok: {dns1}/{dns2}')
                    return {'ok': True,
                            'method': f'SyncThru {"HTTPS" if use_https else "HTTP"} (sessão)',
                            'detail': f'DNS1={dns1} DNS2={dns2} user={user}'}

        detail = ('SyncThru sem confirmação — verifique se o payload '
                  'foi aceito manualmente em http://' + ip + '/sws')
        log.warning(f'[apply_dns] {ip} Samsung FALHOU: {detail}')
        return {'ok': False, 'method': '', 'detail': detail}


class _ZebraAdapter(VendorAdapter):
    """Aplica DNS na Zebra: SGD setvar (primário) → HTTP /server/NWSET.htm (fallback)."""

    def apply_dns(self, ip: str, dns1: str, dns2: str) -> dict:
        import re as _re, urllib.parse as _up

        # --- Tentativa 1: SGD nativo porta 9100 ---
        ok_sgd = False
        _zebra_sgd(ip, f'! U1 setvar "internal_wired.ip.dns1" "{dns1}"')
        _zebra_sgd(ip, f'! U1 setvar "internal_wired.ip.dns2" "{dns2}"')
        # Verifica resultado relendo os valores
        got1 = _zebra_sgd(ip, '! U1 getvar "internal_wired.ip.dns1"')
        got2 = _zebra_sgd(ip, '! U1 getvar "internal_wired.ip.dns2"')
        if got1 and got1.strip('"') == dns1:
            ok_sgd = True
            log.info(f'[apply_dns] {ip} Zebra SGD ok: {dns1}/{dns2}')
            return {'ok': True, 'method': 'SGD setvar',
                    'detail': f'DNS1={dns1} DNS2={dns2}'}
        log.debug(f'[zebra_dns] {ip} SGD: got1={got1!r} got2={got2!r} — '
                  f'tentando HTTP fallback')

        # --- Tentativa 2: HTTP GET-parse-POST /server/NWSET.htm ---
        _saved = load_printer_credentials().get(ip, {})
        _z_user = _saved.get('user', ZEBRA_USER)
        _z_pwds = ([_saved['password']] if _saved.get('password') else []) + ZEBRA_PASSWORDS

        for use_https in (False, True):
            for pw in _z_pwds:
                import http.cookiejar as _cj, base64 as _b64
                scheme = 'https' if use_https else 'http'
                creds  = _b64.b64encode(f'{_z_user}:{pw}'.encode()).decode()
                hdrs   = {'Authorization': f'Basic {creds}',
                          'User-Agent': 'PrinterScanner/1.0',
                          'Referer': f'{scheme}://{ip}/server/NWSET.htm'}
                cj     = _cj.CookieJar()
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=_SSL_CTX),
                    urllib.request.HTTPCookieProcessor(cj),
                )
                # GET
                try:
                    req = urllib.request.Request(
                        f'{scheme}://{ip}/server/NWSET.htm', headers=hdrs)
                    with opener.open(req, timeout=HTTP_TIMEOUT) as r:
                        html = r.read(32768).decode('utf-8', 'ignore')
                except Exception as e:
                    log.debug(f'[zebra_dns] {ip} GET /server/NWSET.htm falhou '
                              f'(https={use_https}): {e}')
                    continue

                # Extrai campos do formulário
                form_m    = _re.search(r'<form[^>]+action=["\']([^"\']+)["\']',
                                       html, _re.IGNORECASE)
                post_path = form_m.group(1) if form_m else '/server/NWSET.htm'
                fields: dict = {}
                for m in _re.finditer(r'<input([^>]*)>', html, _re.IGNORECASE):
                    a  = m.group(1)
                    nm = _re.search(r"""name=['"]([^'"]+)['"]""", a, _re.IGNORECASE)
                    vl = _re.search(r"""value=['"]([^'"]*?)['"]""", a, _re.IGNORECASE)
                    tp = _re.search(r"""type=['"]([^'"]+?)['"]""", a, _re.IGNORECASE)
                    chk = _re.search(r'\bchecked\b', a, _re.IGNORECASE)
                    if not nm:
                        continue
                    name  = nm.group(1)
                    value = vl.group(1) if vl else ''
                    ftype = (tp.group(1) or '').lower() if tp else 'text'
                    if ftype == 'submit':
                        if name not in fields:
                            fields[name] = value
                        continue
                    if ftype == 'checkbox':
                        if chk:
                            fields[name] = value or 'on'
                        continue
                    if ftype == 'radio':
                        if chk:
                            fields[name] = value
                        elif name not in fields:
                            fields[name] = value
                        continue
                    fields[name] = value

                if not fields:
                    continue

                # Identifica campos DNS por padrão de nome
                _dns1_candidates = ['dns1', 'DNS1', 'primarydns', 'primaryDNS',
                                    'PreferredDNS', 'dns_primary']
                _dns2_candidates = ['dns2', 'DNS2', 'secondarydns', 'secondaryDNS',
                                    'AlternateDNS', 'dns_secondary']
                dns1_field = next(
                    (n for n in _dns1_candidates if n in fields), None)
                dns2_field = next(
                    (n for n in _dns2_candidates if n in fields), None)
                # Fallback: campos com valor IP atual
                if not dns1_field or not dns2_field:
                    _ip_pat = _re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
                    ip_fields = [(k, v) for k, v in fields.items()
                                 if _ip_pat.match(v or '') and 'gateway' not in k.lower()
                                 and 'wins' not in k.lower()]
                    if not dns1_field and len(ip_fields) >= 1:
                        dns1_field = ip_fields[0][0]
                    if not dns2_field and len(ip_fields) >= 2:
                        dns2_field = ip_fields[1][0]

                if not dns1_field:
                    log.debug(f'[zebra_dns] {ip} campos DNS não identificados '
                              f'em /server/NWSET.htm: {list(fields.keys())}')
                    continue

                if dns1_field:
                    fields[dns1_field] = dns1
                if dns2_field:
                    fields[dns2_field] = dns2

                # POST
                post_hdrs = dict(hdrs)
                post_hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
                req2 = urllib.request.Request(
                    f'{scheme}://{ip}{post_path}',
                    data=_up.urlencode(fields).encode(),
                    headers=post_hdrs,
                    method='POST',
                )
                try:
                    with opener.open(req2, timeout=HTTP_TIMEOUT) as r:
                        _ = r.read(4096)
                except Exception as e:
                    log.debug(f'[zebra_dns] {ip} POST {post_path} falhou: {e}')
                    continue

                # Verificação pós-POST via re-GET
                try:
                    req3 = urllib.request.Request(
                        f'{scheme}://{ip}/server/NWSET.htm', headers=hdrs)
                    with opener.open(req3, timeout=HTTP_TIMEOUT) as r:
                        verify = r.read(32768).decode('utf-8', 'ignore')
                    if verify and dns1 in verify:
                        log.info(f'[apply_dns] {ip} Zebra HTTP NWSET.htm ok: {dns1}/{dns2}')
                        return {'ok': True,
                                'method': f'HTTP NWSET.htm {"HTTPS" if use_https else "HTTP"}',
                                'detail': f'DNS1={dns1} DNS2={dns2} user={_z_user}'}
                    log.debug(f'[zebra_dns] {ip} verificação pós-POST falhou: '
                              f'{dns1!r} não encontrado')
                except Exception as e:
                    log.debug(f'[zebra_dns] {ip} GET de verificação falhou: {e}')

        detail = 'SGD setvar falhou; HTTP /server/NWSET.htm: POST rejeitado ou DNS não confirmado'
        log.warning(f'[apply_dns] {ip} Zebra FALHOU: {detail}')
        return {'ok': False, 'method': '', 'detail': detail}


class _GenericAdapter(VendorAdapter):
    def __init__(self, name: str = 'Desconhecido') -> None:
        self._name = name

    def apply_dns(self, ip: str, dns1: str, dns2: str) -> dict:
        detail = f'Fabricante {self._name!r} sem suporte a apply_dns automatizado'
        log.warning(f'[apply_dns] {ip} {detail}')
        return {'ok': False, 'method': '', 'detail': detail}


# Registry: mapeia fabricante → adaptador (instâncias singleton)
VENDOR_ADAPTERS: dict = {
    'HP':        _HPAdapter(),
    'Samsung':   _SamsungAdapter(),
    'Zebra':     _ZebraAdapter(),
    'Honeywell': _GenericAdapter('Honeywell'),
}
_DEFAULT_ADAPTER = _GenericAdapter()


def apply_dns_config(ip: str, manufacturer: str,
                     dns1: str, dns2: str) -> dict:
    """Aplica DNS primário e secundário no equipamento via adaptador do fabricante.

    HP:
      1. SNMP SET JetDirect (OIDs 29/30)
      2. EWS HTTP: network_id.htm → SetStaticDNS → SyncThru
    Samsung:
      SyncThru /sws/ via sessão autenticada
    Zebra:
      1. SGD setvar porta 9100
      2. HTTP GET-parse-POST /server/NWSET.htm (fallback)
    Outros: retorna ok=False sem I/O

    Retorna dict {'ok': bool, 'method': str, 'detail': str}
    """
    adapter = VENDOR_ADAPTERS.get(manufacturer, _DEFAULT_ADAPTER)
    return adapter.apply_dns(ip, dns1, dns2)


# Obtidos por engenharia reversa das páginas network_id.htm em múltiplos firmwares.
# Confirmados em produção:
#   'IPv4_DnsServerId'      — HP LaserJet E60165 / E52645 (E-series)
#   'IPv4_Sec_DnsServerId'  — HP LaserJet E60165 / E52645 (E-series)
_HP_DNS1_FIELD_NAMES = [
    'IPv4_DnsServerId',      # HP E60165 / E52645 — CONFIRMADO em produção
    'IPv4DNSAddress1',       # variante E-series
    'dns1_cfg',              # Pro M series
    'PreferredDNSServer',    # LaserJet clássico (SetStaticDNS)
    'primaryDNS',
    'dnsServer1',
    'DNS1',
    'dns1',
    'iPv4DNS1',
    'pDNS',
]
_HP_DNS2_FIELD_NAMES = [
    'IPv4_Sec_DnsServerId',  # HP E60165 / E52645 — CONFIRMADO em produção
    'IPv4DNSAddress2',
    'dns2_cfg',
    'AlternateDNSServer',    # LaserJet clássico (SetStaticDNS)
    'secondaryDNS',
    'dnsServer2',
    'DNS2',
    'dns2',
    'iPv4DNS2',
    'sDNS',
]


def _hp_network_id_apply_dns(ip: str, dns1: str, dns2: str,
                              user: str, password: str,
                              use_https: bool = False) -> bool:
    """Aplica DNS no HP EWS via GET-parse-POST-verify em /network_id.htm.

    Fluxo:
      1. GET autenticado da página com CookieJar (mantém sessionId do HP EWS)
      2. Extrai <form action=...> para obter o URL correto de POST
      3. Extrai campos do formulário:
         - Inclui hidden, text, radio (selecionado), checkbox (só se checked)
         - Inclui apenas o primeiro botão Apply (descarta Delete/Cancel/etc.)
         - CSRFToken hidden é incluído automaticamente
      4. Substitui os campos de DNS pelos valores alvo
      5. POST para o endpoint do form com session cookie + Basic Auth + Referer
      6. Re-GET para verificar que os novos DNS aparecem na página
    Retorna True somente se a verificação pós-POST confirmar a mudança.
    """
    import re as _re, urllib.parse as _up, http.cookiejar as _cj, base64 as _b64

    scheme = 'https' if use_https else 'http'
    creds  = _b64.b64encode(f'{user}:{password}'.encode()).decode()
    hdrs   = {'Authorization': f'Basic {creds}', 'User-Agent': 'Mozilla/5.0',
              'Referer': f'{scheme}://{ip}/network_id.htm'}

    # Opener com CookieJar para manter o sessionId do HP EWS
    cj     = _cj.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_SSL_CTX),
        urllib.request.HTTPCookieProcessor(cj),
    )

    # 1. GET — obtém o HTML do formulário e o cookie de sessão
    try:
        req = urllib.request.Request(f'{scheme}://{ip}/network_id.htm', headers=hdrs)
        with opener.open(req, timeout=HTTP_TIMEOUT) as r:
            html = r.read(65536).decode('utf-8', 'ignore')
    except Exception as e:
        log.debug(f'[hp_net_id] {ip} GET falhou (use_https={use_https}): {e}')
        return False

    # 2. Extrai a URL de POST do atributo ACTION do <form>
    form_m  = _re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, _re.IGNORECASE)
    post_path = form_m.group(1) if form_m else '/network_id.htm/config'

    # 3. Extrai campos do formulário com tratamento correto de tipos
    _APPLY_NAMES = {'Apply', 'Appli', 'apply', 'submit', 'OK'}
    fields: dict[str, str] = {}
    for m in _re.finditer(r'<input([^>]*)>', html, _re.IGNORECASE):
        a   = m.group(1)
        nm  = _re.search(r"""name=['"]([^'"]+)['"]""", a, _re.IGNORECASE)
        vl  = _re.search(r"""value=['"]([^'"]*?)['"]""", a, _re.IGNORECASE)
        tp  = _re.search(r"""type=['"]([^'"]+?)['"]""", a, _re.IGNORECASE)
        chk = _re.search(r'\bchecked\b', a, _re.IGNORECASE)
        if not nm:
            continue
        name  = nm.group(1)
        value = vl.group(1) if vl else ''
        ftype = (tp.group(1) or '').lower() if tp else 'text'
        if ftype == 'submit':
            if name in _APPLY_NAMES and name not in fields:
                fields[name] = value
            continue
        if ftype == 'checkbox':
            if chk:
                fields[name] = value or 'on'
            # checkbox não marcado: NÃO inclui (causa 400 no HP EWS)
            continue
        if ftype == 'radio':
            if chk:
                fields[name] = value
            elif name not in fields:
                fields[name] = value  # fallback: primeiro radio
            continue
        fields[name] = value

    if not fields:
        log.debug(f'[hp_net_id] {ip} nenhum campo de formulário encontrado (use_https={use_https})')
        return False

    # 4. Identifica campos DNS por nome
    dns1_field = next((n for n in _HP_DNS1_FIELD_NAMES if n in fields), None)
    dns2_field = next((n for n in _HP_DNS2_FIELD_NAMES if n in fields), None)

    # Fallback: procura campos cujo valor atual é um endereço IP
    # (heurística para firmwares com nomes de campo desconhecidos)
    if not dns1_field or not dns2_field:
        _ip_pat = _re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
        # Só considera os primeiros campos IP (evita pegar WINS/gateway)
        ip_fields = [(k, v) for k, v in fields.items()
                     if _ip_pat.match(v or '') and 'wins' not in k.lower()
                     and 'gateway' not in k.lower()]
        log.debug(f'[hp_net_id] {ip} campos com valor IP: {ip_fields}')
        if not dns1_field and len(ip_fields) >= 1:
            dns1_field = ip_fields[0][0]
        if not dns2_field and len(ip_fields) >= 2:
            dns2_field = ip_fields[1][0]

    if not dns1_field and not dns2_field:
        log.debug(f'[hp_net_id] {ip} campos DNS não identificados. '
                  f'Campos: {list(fields.keys())}')
        return False

    log.debug(f'[hp_net_id] {ip} campos DNS: {dns1_field!r}/{dns2_field!r} '
              f'action={post_path!r}')

    if dns1_field:
        fields[dns1_field] = dns1
    if dns2_field:
        fields[dns2_field] = dns2

    # 5. POST com session cookie + Basic Auth + Referer
    payload = _up.urlencode(fields)
    post_hdrs = dict(hdrs)
    post_hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
    req2 = urllib.request.Request(
        f'{scheme}://{ip}{post_path}',
        data=payload.encode(),
        headers=post_hdrs,
        method='POST',
    )
    try:
        with opener.open(req2, timeout=HTTP_TIMEOUT) as r:
            _ = r.read(4096)  # lê body para liberar conexão
    except Exception as e:
        log.debug(f'[hp_net_id] {ip} POST {post_path} falhou: {e}')
        return False

    # 6. Re-GET para verificar que os novos valores de DNS aparecem na página
    try:
        req3 = urllib.request.Request(f'{scheme}://{ip}/network_id.htm', headers=hdrs)
        with opener.open(req3, timeout=HTTP_TIMEOUT) as r:
            verify = r.read(65536).decode('utf-8', 'ignore')
        if verify and dns1 in verify:
            log.info(f'[hp_net_id] {ip} DNS verificado: {dns1}/{dns2} '
                     f'(campo={dns1_field} action={post_path})')
            return True
        log.debug(f'[hp_net_id] {ip} verificação pós-POST falhou: '
                  f'{dns1!r} não encontrado na resposta')
    except Exception as e:
        log.debug(f'[hp_net_id] {ip} GET de verificação falhou: {e}')
    return False


def get_page_count(ip: str) -> Optional[str]:
    """Contador de páginas — tenta HP XML, depois SNMP padrão."""
    import re, xml.etree.ElementTree as ET
    # HP EWS XML — /DevMgmt/ProductUsageDyn.xml
    for use_https in (True, False):
        body = _http_get_page(ip, '/DevMgmt/ProductUsageDyn.xml', use_https=use_https)
        if body:
            try:
                root = ET.fromstring(body)
                # Procura TotalImpressions em qualquer namespace
                for elem in root.iter():
                    if 'TotalImpressions' in elem.tag and elem.text:
                        return elem.text.strip()
            except Exception:
                pass
            # Fallback regex caso XML malformado
            m = re.search(r'<[^>]*TotalImpressions[^>]*>\s*(\d+)', body)
            if m:
                return m.group(1)
    return _snmp_get(ip, OID_PAGE_COUNT)


def get_zebra_odometer(ip: str) -> Optional[str]:
    """Odômetro da cabeça térmica Zebra em polegadas.

    Cascata exclusivamente SNMP/HTTP (porta 9100 bloqueada por firewall nos CDs):
    1. SNMP UDP 161 — OID Eltron (polegadas direto, modelos GK/LP/legado).
    2. SNMP UDP 161 — OID ZebraNet dot count ÷ DPI (firmware ZT/ZD SNMP).
    3. HTTP TCP 80  — /server/SYSINFO.htm  (regex Head Mileage/Odometer).
    4. HTTP TCP 80  — /server/CFGPAGE.htm  (mesmo regex).
    """
    import re

    # --- 1. SNMP Eltron (UDP — mais rápido, sem risco de firewall TCP) ---
    val = _snmp_get(ip, OID_ZEBRA_ODOM_ELTRON)
    if val and val.lstrip('-').isdigit():
        inches = int(val)
        if 0 < inches < 5_000_000:
            return f'{inches:,} pol.'

    # --- 2. SNMP ZebraNet dots ÷ DPI ---
    val = _snmp_get(ip, OID_ZEBRA_ODOM_DOTS)
    if val and val.lstrip('-').isdigit():
        dots = int(val)
        if dots > 0:
            return f'{dots // ZEBRA_DEFAULT_DPI:,} pol.'

    # --- 3-4. HTTP scraping TCP 80 (fallback; sem porta 9100) ---
    for path in ('/server/SYSINFO.htm', '/server/CFGPAGE.htm'):
        body = _http_get_page(ip, path)
        if not body:
            continue
        m = re.search(
            r'Head\s+(?:Mileage|Odometer)\s*[:\-=]?\s*([\d,]+)\s*in',
            body, re.I)
        if m:
            inches = int(m.group(1).replace(',', ''))
            if 0 < inches < 5_000_000:
                return f'{inches:,} pol.'
        m = re.search(
            r'Head\s+(?:Mileage|Odometer)\s*[:\-=]?\s*([\d,]+)\s*dot',
            body, re.I)
        if m:
            dots = int(m.group(1).replace(',', ''))
            if dots > 0:
                return f'{dots // ZEBRA_DEFAULT_DPI:,} pol.'

    return None


def _zebra_sgd(ip: str, command: str, timeout: float = 3.0) -> Optional[str]:
    """Stub inativo: porta 9100 bloqueada por firewall nos CDs.

    Mantido para compatibilidade de assinatura. Retorna sempre None.
    Se o ambiente mudar, remova este stub e restaure a implementação
    com socket TCP porta 9100.
    """
    log.debug(f'[zebra_sgd] {ip} porta 9100 desativada (firewall); cmd ignorado')
    return None


def _decode_html(s: str) -> str:
    """Decodifica entidades HTML básicas."""
    return (s.replace('&raquo;', '\u00bb').replace('&laquo;', '\u00ab')
              .replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
              .replace('&nbsp;', ' ').replace('&bull;', '\u2022')
              .replace('&#x2022;', '\u2022').replace('&middot;', '\u00b7')
              .replace('&ndash;', '\u2013').replace('&mdash;', '\u2014').strip())


def get_model(ip: str, manufacturer: str) -> Optional[str]:
    """Detecta modelo via HTTP (paths específicos por fabricante) + SNMP fallback."""
    import re

    if manufacturer == 'HP':
        # NUNCA usar <title> para HP — é sempre "HP » Device Information"
        # Busca padrão "HP LaserJet..." diretamente no corpo das páginas EWS
        # Exclui caracteres HTML (&, <, >) para nunca capturar entidades
        HP_MODEL_RE = re.compile(
            r'\bHP\s+(?:Color\s+)?'
            r'(?:LaserJet|PageWide|OfficeJet|DeskJet|Smart\s*Tank|Ink\s*Tank)'
            r'(?:[^<>&"\n]{2,60})',
            re.I)
        for use_https in (True, False):
            for path in (
                '/hp/device/DeviceStatus/Index',
                '/hp/device/DeviceInformation/View',
                '/hp/device/InternalPages/Index?id=ConfigurationPage',
            ):
                body = _http_get_page(ip, path, use_https=use_https)
                if not body:
                    continue
                m = HP_MODEL_RE.search(body)
                if m:
                    model = m.group(0).strip().rstrip('.,;: ')
                    if len(model) > 8 and '&' not in model:
                        return model
            if use_https:
                break  # HTTPS tentado, não precisamos repetir com HTTP se HTTPS funcionou

        # Fallback: XML de configuração HP
        for use_https in (True, False):
            body = _http_get_page(ip, '/DevMgmt/ProductConfigDyn.xml', use_https=use_https)
            if body:
                for tag in ('dd:DeviceName', 'DeviceName', 'localization:EnglishString'):
                    m = re.search(rf'<{re.escape(tag)}[^>]*>([^<]{{4,80}})<', body, re.I)
                    if m:
                        val = m.group(1).strip()
                        if 'hp' in val.lower() or len(val) > 6:
                            return _decode_html(val)

    elif manufacturer == 'Samsung':
        for path in ('/sws/index.html', '/default.html'):
            body = _http_get_page(ip, path)
            if body:
                m = re.search(r'<title[^>]*>([^<]{4,80})</title>', body, re.I)
                if m:
                    title = m.group(1).strip()
                    generic = ('syncthru', 'web service', 'home', 'index', 'login')
                    if not any(g in title.lower() for g in generic):
                        return title
                m = re.search(
                    r'(?:Model|Modelo)[^:]*:\s*</[^>]+>\s*<[^>]+>([^<]{4,60})',
                    body, re.I)
                if m:
                    return m.group(1).strip()

    elif manufacturer == 'Zebra':
        for path in ('/server/SYSINFO.htm', '/config.html'):
            body = _http_get_page(ip, path)
            if body:
                m = re.search(
                    r'(?:Model|Modelo|Printer\s+Model)\s*[:\-=]\s*'
                    r'(<[^>]+>)?\s*([A-Za-z0-9][^\n<]{2,50})',
                    body, re.I)
                if m:
                    return m.group(2).strip()
                m = re.search(r'<title[^>]*>([^<]{4,80})</title>', body, re.I)
                if m:
                    title = m.group(1).strip()
                    if 'zebra' in title.lower() or 'zt' in title.lower():
                        return title

    # SNMP fallback para todos os fabricantes
    oid_map = {
        'HP':        (OID_HP_MODEL, OID_MODEL_STD, OID_MODEL_STD2),
        'Samsung':   (OID_SAMSUNG_MODEL, OID_MODEL_STD, OID_MODEL_STD2),
        'Zebra':     (OID_ZEBRA_MODEL, OID_MODEL_STD, OID_MODEL_STD2),
        'Honeywell': (OID_HONEYWELL_MODEL, OID_MODEL_STD, OID_MODEL_STD2),
    }
    for oid in oid_map.get(manufacturer, (OID_MODEL_STD, OID_MODEL_STD2)):
        val = _snmp_get(ip, oid)
        if val and _is_valid_model(val):
            return val.strip()

    return None


def _is_valid_model(val: Optional[str], serial: str = '') -> bool:
    """Retorna True se val parece um modelo real (não lixo, não serial, não HTML)."""
    import re as _re
    if not val or len(val) < 3:
        return False
    # Rejeita se contém entidade HTML (ex: "HP &raquo; Device Information")
    if '&' in val and ';' in val:
        return False
    # Rejeita caracteres não-imprimíveis (ex: ýèBRBSR8L01H)
    printable = sum(1 for c in val if c.isprintable() and ord(c) < 128)
    if printable / len(val) < 0.85:
        return False
    # Rejeita serial-like: só maiúsculas + dígitos, sem espaço (ex: BRBSR8L01H)
    if _re.match(r'^[A-Z0-9]{6,}$', val.strip()):
        return False
    # Rejeita labels genéricos de navegação
    nav_labels = ('device information', 'device status', 'status do dispositivo',
                  'web service', 'configuration', 'configura')
    if any(lbl in val.lower() for lbl in nav_labels):
        return False
    # Rejeita se igual ou contido no serial
    if serial and (val.strip() == serial or val.strip() in serial):
        return False
    return True


def get_hp_consumables(ip: str) -> tuple[Optional[str], Optional[str]]:
    """Retorna (toner%, kit_manutencao%) para impressoras HP.

    1. HP EWS XML — /DevMgmt/ConsumableConfigDyn.xml (mais confiável)
    2. HP EWS HTML — /hp/device/InternalPages/Index?id=SuppliesStatus
    3. SNMP HP MIB fallback
    """
    import re, xml.etree.ElementTree as ET

    def _pct(v: str) -> Optional[str]:
        v = v.strip()
        if v.isdigit():
            return f'{int(v)}%'
        m = re.search(r'(\d+)\s*%', v)
        return f'{m.group(1)}%' if m else None

    # --- HP EWS XML ---------------------------------------------------------
    for use_https in (True, False):
        body = _http_get_page(
            ip, '/DevMgmt/ConsumableConfigDyn.xml', use_https=use_https)
        if not body:
            continue
        try:
            root = ET.fromstring(body)
            toner_pct = kit_pct = None
            for item in root.iter():
                tag = item.tag.split('}')[-1]  # remove namespace
                if tag == 'ConsumableLabelCode':
                    label = (item.text or '').upper()
                    # Próximo sibling com percentual
                    parent = list(root.iter())
                    idx = parent.index(item)
                    for sibling in parent[idx:idx + 8]:
                        stag = sibling.tag.split('}')[-1]
                        if 'PercentageLevelRemaining' in stag and sibling.text:
                            pct = f'{sibling.text.strip()}%'
                            if 'TONER' in label or 'BLACK' in label:
                                toner_pct = pct
                            elif 'MAINT' in label or 'FUSER' in label or 'KIT' in label:
                                kit_pct = pct
                            break
            if toner_pct or kit_pct:
                return toner_pct, kit_pct
        except Exception:
            # Fallback regex no XML
            toner_m = re.search(
                r'TONER[^<]*</[^>]+>[^<]*<[^>]+>\s*(\d+)', body, re.I)
            kit_m   = re.search(
                r'(?:MAINT|FUSER|KIT)[^<]*</[^>]+>[^<]*<[^>]+>\s*(\d+)',
                body, re.I)
            return (
                f'{toner_m.group(1)}%' if toner_m else None,
                f'{kit_m.group(1)}%'   if kit_m   else None,
            )

    # --- HP EWS HTML — DeviceStatus (mais simples, mostra Preto/Kit) --------
    for use_https in (True, False):
        for hp_path in (
            '/hp/device/DeviceStatus/Index',
            '/hp/device/InternalPages/Index?id=SuppliesStatus',
        ):
            body = _http_get_page(ip, hp_path, use_https=use_https)
            if not body:
                continue
            # Labels PT: Preto / EN: Black|Toner|Cartridge
            toner_m = re.search(
                r'(?:Preto|Black|Toner|Cartridge|CARTRIDGE)'
                r'[^%]{0,400}?(\d{1,3})\s*%',
                body, re.I | re.S)
            # Kit manutencao / Kit alimentador / Maintenance / Fuser
            kit_m = re.search(
                r'(?:Kit\b|Maintenance|Fuser|Document\s*Feeder)'
                r'[^%]{0,400}?(\d{1,3})\s*%',
                body, re.I | re.S)
            if toner_m or kit_m:
                return (
                    f'{toner_m.group(1)}%' if toner_m else None,
                    f'{kit_m.group(1)}%'   if kit_m   else None,
                )

    # --- SNMP fallback -------------------------------------------------------
    def _snmp_fmt(v: Optional[str]) -> Optional[str]:
        if not v or not v.lstrip('-').isdigit():
            return None
        pct = int(v)
        return None if pct < 0 else f'{pct}%'

    return _snmp_fmt(_snmp_get(ip, OID_HP_TONER)), _snmp_fmt(_snmp_get(ip, OID_HP_MAINT_KIT))


def get_samsung_consumables(ip: str) -> tuple[Optional[str], Optional[str]]:
    """Retorna (toner%, drum%) para impressoras Samsung.

    1. HTTP SyncThru pages
    2. SNMP Samsung MIB fallback
    """
    import re

    # Samsung SyncThru — tenta obter dados de suprimentos via HTML
    for path in (
        '/sws/app/information/reportsAndPages/suppliesStatus',
        '/sws/index.html',
        '/default.html',
    ):
        body = _http_get_page(ip, path)
        if not body:
            continue
        toner_m = re.search(
            r'(?:Toner|Black|Cartucho)[^\d]{0,80}(\d{1,3})\s*%', body, re.I)
        drum_m  = re.search(
            r'(?:Drum|Tambor|Imaging\s*Unit)[^\d]{0,80}(\d{1,3})\s*%',
            body, re.I)
        if toner_m or drum_m:
            return (
                f'{toner_m.group(1)}%' if toner_m else None,
                f'{drum_m.group(1)}%'  if drum_m  else None,
            )

    # SNMP fallback
    def _fmt(v: Optional[str]) -> Optional[str]:
        if not v or not v.lstrip('-').isdigit():
            return None
        return f'{int(v)}%'
    return _fmt(_snmp_get(ip, OID_SAMSUNG_TONER)), _fmt(_snmp_get(ip, OID_SAMSUNG_DRUM))


def resolve_tipo(manufacturer: str) -> str:
    """Zebra e Honeywell são SEMPRE térmicas."""
    return 'termica' if manufacturer in THERMAL_MANUFACTURERS else 'laser'


# ---------------------------------------------------------------------------
# Cache incremental
# ---------------------------------------------------------------------------
def load_cache() -> dict[str, dict]:
    """Carrega cache.json; retorna dict keyed por IP."""
    if not CACHE_PATH.exists():
        return {}
    try:
        data = json.loads(CACHE_PATH.read_text(encoding='utf-8'))
        if isinstance(data, list):
            return {p['ip']: p for p in data if 'ip' in p}
        return data
    except Exception as exc:
        log.warning(f'Cache corrompido, ignorando: {exc}')
        return {}


def save_cache(printers: list[dict]) -> None:
    """Persiste lista de impressoras em cache.json."""
    try:
        CACHE_PATH.write_text(
            json.dumps(printers, ensure_ascii=False, indent=2),
            encoding='utf-8',
        )
        log.info(f'Cache salvo: {CACHE_PATH} ({len(printers)} entradas)')
    except Exception as exc:
        log.error(f'Erro ao salvar cache: {exc}', exc_info=True)


def load_printer_credentials() -> dict:
    """Carrega credenciais por IP de printer_credentials.json."""
    try:
        return json.loads(CREDENTIALS_PATH.read_text(encoding='utf-8'))
    except Exception:
        return {}


def save_printer_credentials(creds: dict) -> None:
    """Persiste credenciais por IP em printer_credentials.json."""
    try:
        CREDENTIALS_PATH.write_text(
            json.dumps(creds, ensure_ascii=False, indent=2),
            encoding='utf-8',
        )
    except Exception as exc:
        log.error(f'Erro ao salvar credenciais: {exc}', exc_info=True)


def update_metrics_from_cache(cached: dict) -> dict:
    """Atualiza campos dinâmicos; re-detecta modelo/fabricante se inválidos."""
    ip     = cached['ip']
    mfr    = cached.get('fabricante', '')
    serial = cached.get('serial', '')
    updated = dict(cached)
    now = datetime.now().isoformat(timespec='seconds')

    # Short-circuit: se o healthcheck já marcou como Offline, não tenta
    # SNMP/HTTP — evita acumular timeouts de 3 s em máquinas desligadas.
    with _status_lock:
        current_status = _status_cache.get(ip)
    if current_status == 'Offline':
        updated['status']       = 'Offline'
        updated['last_updated'] = now
        return updated

    # Re-detecta fabricante se 'Desconhecido' ou vazio
    if not mfr or mfr == 'Desconhecido':
        detected = detect_manufacturer(ip)
        if detected:
            mfr = detected
            updated['fabricante'] = mfr
            updated['tipo'] = resolve_tipo(mfr)

    # Re-detecta modelo se inválido (lixo SNMP, HTML entity, label de navegação ou ausente)
    modelo_atual = cached.get('modelo') or ''
    if not _is_valid_model(modelo_atual, serial):
        novo_modelo = get_model(ip, mfr)
        if novo_modelo and _is_valid_model(novo_modelo, serial):
            updated['modelo'] = novo_modelo
        else:
            updated['modelo'] = None   # limpa o lixo mesmo se não encontrou novo

    if mfr == 'Zebra':
        updated['metrica'] = get_zebra_odometer(ip)
    elif mfr == 'HP':
        updated['metrica']     = get_page_count(ip)
        t, k = get_hp_consumables(ip)
        updated['toner']       = t
        updated['consumivel2'] = k
    elif mfr == 'Samsung':
        updated['metrica']     = get_page_count(ip)
        t, d = get_samsung_consumables(ip)
        updated['toner']       = t
        updated['consumivel2'] = d
    else:
        updated['metrica'] = get_page_count(ip)

    # Configuração de rede — lógica de retry:
    # - IP real      → pula (já tem)
    # - None         → sempre tenta (nunca coletado)
    # - 'NOT_SET'    → tenta SE auth_ok nao for False (DHCP + HTTP já falhou = esgotado)
    _dns1_now  = str(updated.get('dns1') or '').strip().upper()
    _dns_is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', _dns1_now))
    _dns_notset = _dns1_now in ('NOT_SET', 'NOTSET', 'NOT SET')
    _auth_done  = updated.get('auth_ok') is False
    _retry_dns  = not _dns_is_ip and not (_dns_notset and _auth_done)
    if mfr in ('HP', 'Samsung', 'Zebra') and _retry_dns:
        netcfg = get_network_config(ip, mfr)
        updated['hostname'] = netcfg.get('hostname') or updated.get('hostname')
        updated['dns1']     = netcfg.get('dns1')     or updated.get('dns1')
        updated['dns2']     = netcfg.get('dns2')     or updated.get('dns2')
        updated['gateway']  = netcfg.get('gateway')  or updated.get('gateway')
        updated['ip_mode']  = netcfg.get('ip_mode')  or updated.get('ip_mode')
        if netcfg.get('auth_ok') is not None:
            updated['auth_ok']   = netcfg['auth_ok']
            updated['auth_user'] = netcfg.get('auth_user')

    updated['last_updated'] = now
    return updated


# ---------------------------------------------------------------------------
# Diagnóstico de conectividade — /api/probe
# ---------------------------------------------------------------------------

def _check_is_online(ip: str, timeout: float = 1.5) -> bool:
    """TCP handshake na porta 80 — detecta se a impressora está acessível.
    Porta 9100 (RAW/SGD) não é usada: bloqueada por firewall nos CDs.
    """
    try:
        with socket.create_connection((ip, 80), timeout=timeout):
            return True
    except Exception:
        return False


def _healthcheck_loop() -> None:
    """Worker daemon que atualiza _status_cache a cada 120 s.

    Estratégia:
    - Lê a lista de IPs do cache em arquivo (snapshot, sem lock de arquivo)
    - Testa conectividade via TCP 80 em paralelo (max 30 workers)
    - Atualiza apenas _status_cache (dict em memória, com _status_lock mínimo)
    - Loga APENAS mudanças de estado para não poluir automacao.log
    - Intervalo de 120 s reduz o risco de saturação em redes SD-WAN
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    _HC_INTERVAL   = 120   # segundos entre ciclos
    _HC_MAX_WORKERS = 30   # paralelismo — ~800 IPs ÷ 30 = 27 lotes de ~1.5 s

    log.info('[healthcheck] Worker iniciado. Intervalo: %d s, workers: %d.',
             _HC_INTERVAL, _HC_MAX_WORKERS)

    while True:
        try:
            time.sleep(_HC_INTERVAL)

            # Snapshot dos IPs conhecidos (leitura de arquivo; aceita ser ligeiramente defasado)
            try:
                ip_list = list(load_cache().keys())
            except Exception as _e:
                log.warning('[healthcheck] Erro ao ler cache: %s', _e)
                continue

            if not ip_list:
                continue

            def _ping(ip: str) -> tuple[str, bool]:
                return ip, _check_is_online(ip)

            with ThreadPoolExecutor(max_workers=_HC_MAX_WORKERS,
                                    thread_name_prefix='hc') as ex:
                futures = {ex.submit(_ping, ip): ip for ip in ip_list}
                for fut in as_completed(futures):
                    try:
                        ip, online = fut.result()
                        new_status = 'Online' if online else 'Offline'
                        with _status_lock:
                            old_status = _status_cache.get(ip)
                            if old_status != new_status:
                                log.info('[healthcheck] %s: %s → %s',
                                         ip, old_status or 'Novo', new_status)
                            _status_cache[ip] = new_status
                    except Exception as _fe:
                        log.debug('[healthcheck] Erro em future: %s', _fe)

        except Exception as _exc:
            log.warning('[healthcheck] Falha no ciclo: %s', _exc)


def _probe_tcp(ip: str, port: int) -> dict:
    """Testa abertura de uma porta TCP."""
    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=2.0):
            return {'open': True, 'ms': round((time.monotonic() - t0) * 1000)}
    except socket.timeout:
        return {'open': False, 'error': 'timeout (2s)'}
    except ConnectionRefusedError:
        return {'open': False, 'error': 'recusado (porta fechada)'}
    except OSError as e:
        return {'open': False, 'error': str(e)}


def _probe_snmp_oid(ip: str, oid: str) -> dict:
    """SNMP GET com diagnóstico detalhado — distingue timeout, noSuchObject, etc."""

    # BER helpers (auto-contidos)
    def _bl(n):
        if n < 128:  return bytes([n])
        if n < 256:  return b'\x81' + bytes([n])
        return b'\x82' + bytes([(n >> 8) & 0xff, n & 0xff])

    def _tlv(t, v):  return bytes([t]) + _bl(len(v)) + v

    def _bi(n):
        if n == 0:  return _tlv(0x02, b'\x00')
        buf = []; m = n
        while m:  buf.append(m & 0xff); m >>= 8
        buf.reverse()
        if buf[0] & 0x80:  buf.insert(0, 0)
        return _tlv(0x02, bytes(buf))

    def _boid(s):
        p = [int(x) for x in s.strip('.').split('.')]
        r = [p[0] * 40 + p[1]]
        for v in p[2:]:
            if v == 0:  r.append(0)
            else:
                b = []; x = v
                while x:  b.append(x & 0x7f); x >>= 7
                b.reverse()
                for i in range(len(b) - 1):  b[i] |= 0x80
                r.extend(b)
        return _tlv(0x06, bytes(r))

    def _rt(data, pos):
        if pos + 2 > len(data):  return None, None, pos
        tag = data[pos]; pos += 1
        ln  = data[pos]; pos += 1
        if ln & 0x80:
            nb = ln & 0x7f
            if pos + nb > len(data):  return None, None, pos
            ln = int.from_bytes(data[pos:pos + nb], 'big'); pos += nb
        if pos + ln > len(data):  return None, None, pos
        return tag, data[pos:pos + ln], pos + ln

    vb  = _tlv(0x30, _boid(oid) + _tlv(0x05, b''))
    pdu = _tlv(0xa0, _bi(1) + _bi(0) + _bi(0) + _tlv(0x30, vb))
    pkt = _tlv(0x30, _bi(0) + _tlv(0x04, SNMP_COMMUNITY.encode()) + pdu)

    out = {'oid': oid, 'value': None, 'ok': False, 'error': None, 'ms': None}
    t0  = time.monotonic()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(SNMP_TIMEOUT)
            s.sendto(pkt, (ip, 161))
            resp, _ = s.recvfrom(4096)
        out['ms'] = round((time.monotonic() - t0) * 1000)
    except socket.timeout:
        out['error'] = f'Sem resposta UDP (timeout {SNMP_TIMEOUT}s) — SNMP desabilitado ou porta 161 bloqueada'
        return out
    except ConnectionRefusedError:
        out['error'] = 'Porta 161/UDP recusada (ICMP unreachable)'
        return out
    except OSError as e:
        out['error'] = f'Erro de socket: {e}'
        return out

    _SERRS = {1: 'tooBig', 2: 'noSuchName', 3: 'badValue', 4: 'readOnly', 5: 'genErr'}
    try:
        tag, inner, _ = _rt(resp, 0)
        if tag != 0x30 or inner is None:
            out['error'] = 'Resposta malformada (tag raiz)'; return out
        p = 0
        for _ in range(2):  _, _, p = _rt(inner, p)          # skip version, community
        tag, pdv, _   = _rt(inner, p)
        if tag != 0xa2 or pdv is None:
            out['error'] = f'PDU inesperado 0x{tag:02x} (esperado GetResponse 0xa2)'; return out
        p = 0
        _, _, p        = _rt(pdv, p)                          # request-id
        _, err_b, p    = _rt(pdv, p)                          # error-status
        _, _, p        = _rt(pdv, p)                          # error-index
        err = int.from_bytes(err_b, 'big') if err_b else 0
        if err:
            out['error'] = f'SNMP error-status {err} ({_SERRS.get(err, "desconhecido")})'; return out
        _, vbl, _      = _rt(pdv, p)
        _, vb_v, _     = _rt(vbl or b'', 0)
        pp = 0
        _, _, pp       = _rt(vb_v or b'', pp)                 # skip OID
        vt, vv, _      = _rt(vb_v or b'', pp)
        _exc = {0x80: 'noSuchObject — OID não existe neste equipamento',
                0x81: 'noSuchInstance — instância inexistente',
                0x82: 'endOfMibView'}
        if vt in _exc:    out['error'] = _exc[vt]; return out
        if not vv:        out['error'] = 'Valor vazio na resposta'; return out
        if vt == 0x04:
            d = vv.decode('latin-1', errors='replace').strip().strip('.')
            if d and not d.startswith('\x00'):
                out['value'] = d; out['ok'] = True
            else:
                out['error'] = f'OCTET STRING vazio/nulo (hex: {vv.hex()[:32]})'
        elif vt in (0x02, 0x41, 0x42, 0x46):
            out['value'] = str(int.from_bytes(vv, 'big', signed=(vt == 0x02))); out['ok'] = True
        else:
            out['error'] = f'Tipo desconhecido tag=0x{vt:02x} hex={vv.hex()[:32]}'
    except Exception as e:
        out['error'] = f'Erro ao parsear resposta SNMP: {e}'
    return out


def _probe_http(ip: str) -> dict:
    """HTTP probe na porta 80 com diagnóstico detalhado."""
    out = {'ok': False, 'status': None, 'server': None,
           'manufacturer': None, 'ms': None, 'error': None, 'snippet': None}
    t0  = time.monotonic()
    try:
        req = urllib.request.Request(
            f'http://{ip}/', headers={'User-Agent': 'PrinterProbe/1.0'})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=_SSL_CTX) as resp:
            out['ms']           = round((time.monotonic() - t0) * 1000)
            out['status']       = resp.status
            out['server']       = resp.headers.get('Server', '')
            body                = resp.read(4096).decode('utf-8', errors='ignore')
            out['snippet']      = body[:400].strip()
            out['manufacturer'] = _match_manufacturer(out['server'] + ' ' + body)
            out['ok']           = True
    except urllib.error.HTTPError as e:
        out['ms']     = round((time.monotonic() - t0) * 1000)
        out['status'] = e.code
        out['error']  = f'HTTP {e.code} {e.reason}'
    except urllib.error.URLError as e:
        out['error']  = f'URLError: {e.reason}'
    except socket.timeout:
        out['error']  = f'Timeout ({HTTP_TIMEOUT}s) na porta 80'
    except Exception as e:
        out['error']  = str(e)
    return out

# ---------------------------------------------------------------------------
# Detecção de fabricante
# ---------------------------------------------------------------------------
def _match_manufacturer(text: str) -> Optional[str]:
    t = text.lower()
    for brand, keywords in _MFR_KEYWORDS.items():
        if any(kw in t for kw in keywords):
            return brand
    return None


def detect_manufacturer(ip: str) -> Optional[str]:
    """Identifica o fabricante em 4 etapas:
    1. SNMP OID padrão (RFC 3805 / Host Resources MIB)
    2. Paths específicos por fabricante (HP=/hp/device/, Samsung=/sws/, Zebra=/server/)
    3. HTTP/HTTPS genérico na raiz
    4. Banner raw TCP porta 9100
    """
    # ---- 1. SNMP — mais rápido e universal ---------------------------------
    for oid in (OID_MODEL_STD, OID_MODEL_STD2):
        val = _snmp_get_raw(ip, oid)
        if val:
            brand = _match_manufacturer(val)
            if brand:
                log.debug(f'{ip}: fabricante via SNMP → {brand}')
                return brand

    # ---- 2. Paths específicos por fabricante --------------------------------
    # HP EWS — redireciona para HTTPS, usa path /hp/device/
    for use_https in (True, False):
        body = _http_get_page(ip, '/hp/device/DeviceInformation/View',
                              use_https=use_https)
        if body and ('hp' in body.lower() or 'laserjet' in body.lower()):
            log.debug(f'{ip}: fabricante via HP EWS → HP')
            return 'HP'

    # Samsung SyncThru
    for path in ('/sws/index.html', '/default.html'):
        body = _http_get_page(ip, path)
        if body and 'samsung' in body.lower():
            log.debug(f'{ip}: fabricante via Samsung SyncThru → Samsung')
            return 'Samsung'

    # Zebra ZebraNet
    for path in ('/server/SYSINFO.htm', '/server/CFGPAGE.htm', '/config.html'):
        body = _http_get_page(ip, path)
        if body and ('zebra' in body.lower() or 'zpl' in body.lower()
                     or 'zebranet' in body.lower()):
            log.debug(f'{ip}: fabricante via Zebra Web → Zebra')
            return 'Zebra'

    # ---- 3. HTTP/HTTPS genérico na raiz ------------------------------------
    for use_https in (False, True):
        body = _http_get_page(ip, '/', use_https=use_https)
        if body:
            brand = _match_manufacturer(body)
            if brand:
                log.debug(f'{ip}: fabricante via HTTP(S) raiz → {brand}')
                return brand

    # ---- 4. Banner TCP 9100 (JetDirect / ZPL) ------------------------------
    try:
        with socket.create_connection((ip, 9100), timeout=2.0) as s:
            s.settimeout(2.0)
            try:
                banner = s.recv(512).decode('latin-1', errors='ignore')
            except Exception:
                banner = ''
        if banner:
            brand = _match_manufacturer(banner)
            if brand:
                log.debug(f'{ip}: fabricante via porta 9100 → {brand}')
                return brand
    except Exception:
        pass

    return None

# ---------------------------------------------------------------------------
# Scan por rede
# ---------------------------------------------------------------------------
def scan_network(entry: dict, known_ips: set[str]) -> list[dict]:
    """Escaneia uma rede; ignora IPs já no cache (serão atualizados separadamente).

    Fase 1 (dentro do semáforo nmap): nmap descobre hosts com portas abertas.
    Fase 2 (fora do semáforo, em paralelo): identifica fabricante e coleta dados
            de cada host candidato simultaneamente — reduz de ~8s/host para ~8s/rede.
    """
    network = entry['network']
    cd      = entry['cd']
    found: list[dict] = []
    now = datetime.now().isoformat(timespec='seconds')

    # ---- Fase 1: nmap (serializado pelo semáforo) ---------------------------
    candidates: list[tuple[str, set[int]]] = []
    with _nmap_sem:
        try:
            log.info(f'[CD {cd}] Scan nmap: {network}')
            nm = nmap.PortScanner()
            nm.scan(hosts=network, arguments=NMAP_ARGS)

            all_hosts = nm.all_hosts()
            log.info(f'[CD {cd}] nmap encontrou {len(all_hosts)} host(s) com porta aberta em {network}')

            for host in all_hosts:
                if nm[host].state() != 'up':
                    log.debug(f'[CD {cd}] {host} ignorado — estado nmap: {nm[host].state()}')
                    continue
                if not any(p in nm[host] for p in ('tcp', 'udp')):
                    log.debug(f'[CD {cd}] {host} ignorado — sem portas TCP/UDP registradas')
                    continue
                if host in known_ips:
                    log.debug(f'[CD {cd}] {host} já no cache — será atualizado')
                    continue

                open_ports: set[int] = set()
                for proto in ('tcp', 'udp'):
                    if proto in nm[host]:
                        for p, info in nm[host][proto].items():
                            if info.get('state') == 'open':
                                open_ports.add(p)

                if open_ports & {631, 9100, 80, 443}:
                    candidates.append((host, open_ports))
                else:
                    log.debug(f'[CD {cd}] {host} ignorado — portas: {open_ports}')

        except Exception as exc:
            log.error(f'Erro ao escanear {network}: {exc}', exc_info=True)
            return found

    if not candidates:
        return found

    log.info(f'[CD {cd}] {len(candidates)} candidato(s) para identificação paralela em {network}')

    # ---- Fase 2: identificação paralela (fora do semáforo nmap) -------------
    lock_found = threading.Lock()

    def _identify_host(host: str, open_ports: set[int]) -> None:
        is_printer_port = bool(open_ports & {631, 9100})
        manufacturer = detect_manufacturer(host)
        if manufacturer not in KNOWN_MANUFACTURERS:
            if is_printer_port:
                log.info(f'[CD {cd}] {host} — porta 9100/631 aberta, fabricante nao identificado → adicionado como Desconhecido')
                manufacturer = 'Desconhecido'
            else:
                log.info(f'[CD {cd}] {host} — fabricante nao identificado, sem porta de impressao')
                return

        tipo_real   = resolve_tipo(manufacturer)
        serial      = get_serial(host, manufacturer)
        modelo      = get_model(host, manufacturer)
        toner       = None
        consumivel2 = None

        if manufacturer == 'Zebra':
            metrica = get_zebra_odometer(host)
        elif manufacturer == 'HP':
            metrica = get_page_count(host)
            toner, consumivel2 = get_hp_consumables(host)
        elif manufacturer == 'Samsung':
            metrica = get_page_count(host)
            toner, consumivel2 = get_samsung_consumables(host)
        else:
            metrica = get_page_count(host)

        netcfg = {}
        if manufacturer in ('HP', 'Samsung', 'Zebra'):
            netcfg = get_network_config(host, manufacturer)

        printer = PrinterInfo(
            ip=host,
            fabricante=manufacturer,
            modelo=modelo,
            serial=serial,
            metrica=metrica,
            toner=toner,
            consumivel2=consumivel2,
            status='Online',
            filial=cd,
            tipo=tipo_real,
            first_seen=now,
            last_updated=now,
            hostname=netcfg.get('hostname'),
            dns1=netcfg.get('dns1'),
            dns2=netcfg.get('dns2'),
            gateway=netcfg.get('gateway'),
            ip_mode=netcfg.get('ip_mode'),
            auth_ok=netcfg.get('auth_ok'),
            auth_user=netcfg.get('auth_user'),
        ).to_dict()

        log.info(
            f'[CD {cd}] NOVO {host} ({manufacturer}/{tipo_real}) '
            f'modelo={modelo} serial={serial} metrica={metrica}'
        )
        with lock_found:
            found.append(printer)

    host_threads = [
        threading.Thread(target=_identify_host, args=(h, op), daemon=True)
        for h, op in candidates
    ]
    for t in host_threads:
        t.start()
    for t in host_threads:
        t.join()

    return found


# ---------------------------------------------------------------------------
# Orquestrador do scan completo (com cache incremental)
# ---------------------------------------------------------------------------
def run_full_scan(update_only: bool = False) -> list[dict]:
    """Executa scan completo ou só atualiza métricas do cache.

    update_only=True: sem nmap, só atualiza contadores/consumíveis dos IPs
                      já presentes no cache.json.
    """
    global _scan_status
    _scan_status['running']        = True
    _scan_status['started_at']     = datetime.now().isoformat(timespec='seconds')
    _scan_status['finished_at']    = None
    _scan_status['networks_done']  = 0
    _scan_status['networks_total'] = 0

    cache = load_cache()
    known_ips = set(cache.keys())

    all_printers: dict = {}
    lock = threading.Lock()

    # Pré-carrega cache no dict de trabalho
    for ip, val in cache.items():
        all_printers[ip] = val
    _scan_status['total'] = len(all_printers)

    # ---- Passo 1: atualiza métricas dos hosts já conhecidos -----------------
    # Semáforo para limitar conexões simultâneas no update (evita saturar a rede)
    _update_sem = threading.Semaphore(20)

    if known_ips:
        log.info(f'Atualizando métricas de {len(known_ips)} hosts em cache...')

        def _update_worker(cached: dict) -> None:
            with _update_sem:
                updated = update_metrics_from_cache(cached)
            with lock:
                all_printers[updated['ip']] = updated
                _scan_status['total'] = len(all_printers)

        threads_upd = [
            threading.Thread(target=_update_worker, args=(v,), daemon=True)
            for v in cache.values()
        ]
        for t in threads_upd:
            t.start()
        for t in threads_upd:
            t.join()

        # Salva métricas atualizadas imediatamente
        save_cache(list(all_printers.values()))

    if update_only:
        result = list(all_printers.values())
        _scan_status['running']     = False
        _scan_status['finished_at'] = datetime.now().isoformat(timespec='seconds')
        return result

    # ---- Passo 2: descobre novos hosts via nmap ------------------------------
    entries = load_network_entries()
    if not entries:
        log.warning('Nenhuma entrada de rede carregada. Verifique o CSV.')
        _scan_status['running']     = False
        _scan_status['finished_at'] = datetime.now().isoformat(timespec='seconds')
        return list(all_printers.values())

    _scan_status['networks_total'] = len(entries)
    log.info(f'Scan nmap em {len(entries)} redes ({len(known_ips)} hosts já conhecidos)...')

    def _scan_worker(entry: dict) -> None:
        results = scan_network(entry, known_ips)
        with lock:
            for p in results:
                all_printers[p['ip']] = p
            _scan_status['total']         = len(all_printers)
            _scan_status['networks_done'] += 1
            # Salva cache incrementalmente a cada rede concluída
            if results:
                save_cache(list(all_printers.values()))

    threads_scan = [
        threading.Thread(
            target=_scan_worker, args=(e,), daemon=True,
            name=f"scan-{e['cd']}"
        )
        for e in entries
    ]
    for t in threads_scan:
        t.start()
    for t in threads_scan:
        t.join()

    result = list(all_printers.values())
    log.info(
        f'Scan concluído — {len(result)} impressoras '
        f'({len(result) - len(known_ips)} novas, {len(known_ips)} atualizadas)'
    )
    save_cache(result)
    _scan_status['running']     = False
    _scan_status['finished_at'] = datetime.now().isoformat(timespec='seconds')
    return result

# ---------------------------------------------------------------------------
# Geração do HTML estático de inventário
# ---------------------------------------------------------------------------
def generate_inventory_html(printers: list[dict], output_path: Path,
                            is_admin: bool = False) -> None:
    """Lê o template, injeta os dados e grava o inventory.html."""
    if not TEMPLATE_PATH.exists():
        log.error(f'Template não encontrado: {TEMPLATE_PATH}')
        return

    # Lista de CDs únicos ordenada para o filtro da página
    cds_sorted = sorted({str(p.get('filial', '')) for p in printers if p.get('filial')},
                        key=lambda x: x.zfill(6))

    timestamp  = datetime.now().strftime('%d/%m/%Y %H:%M')
    data_json  = json.dumps(printers, ensure_ascii=False)
    cds_json   = json.dumps(cds_sorted, ensure_ascii=False)
    total      = str(len(printers))

    raw  = TEMPLATE_PATH.read_text(encoding='utf-8')
    html = (
        Template(raw)
        .safe_substitute(
            DATA=data_json,
            CDS=cds_json,
            TIMESTAMP=timestamp,
            PROBE_PORT=str(PROBE_PORT),
            TOTAL=total,
            IS_ADMIN='true' if is_admin else 'false',
        )
    )
    output_path.write_text(html, encoding='utf-8')
    log.info(f'Inventário gerado ({"admin" if is_admin else "público"}): '
             f'{output_path}  ({total} impressoras)')


# ---------------------------------------------------------------------------
# Página de login (HTML inline — sem dependência de arquivo externo)
# ---------------------------------------------------------------------------
_LOGIN_HTML = """<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login — Painel Administrativo</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:"Segoe UI",system-ui,sans-serif;
  background:radial-gradient(ellipse at 60%% 40%%, #1a1d2e 0%%, #0a0c14 100%%);
  color:#e2e8f0;display:flex;align-items:center;justify-content:center;
  min-height:100vh;
}
.card{
  background:rgba(26,29,39,.95);border:1px solid #2d3148;border-radius:18px;
  padding:2.8rem 2.4rem;width:100%%;max-width:380px;
  display:flex;flex-direction:column;align-items:center;gap:1.4rem;
  box-shadow:0 24px 60px rgba(0,0,0,.5);
}
.logo-wrap{display:flex;flex-direction:column;align-items:center;gap:.6rem;}
.logo-img{width:140px;filter:brightness(1.1) drop-shadow(0 2px 8px rgba(0,0,0,.6));}
.card-title{font-size:1.05rem;font-weight:700;color:#f1f5f9;letter-spacing:.3px;}
.divider{width:100%%;height:1px;background:linear-gradient(90deg,transparent,#2d3148 40%%,#2d3148 60%%,transparent);}
.field{width:100%%;display:flex;flex-direction:column;gap:.3rem;}
label{font-size:.72rem;color:#64748b;font-weight:700;text-transform:uppercase;letter-spacing:.6px;}
input{
  width:100%%;background:#0f1117;border:1px solid #2d3148;border-radius:10px;
  color:#e2e8f0;padding:10px 14px;font-size:.9rem;outline:none;transition:border-color .2s;
}
input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.15);}
.btn{
  width:100%%;background:linear-gradient(135deg,#1d4ed8,#2563eb);color:#fff;
  border:none;border-radius:10px;padding:11px;font-size:.9rem;font-weight:700;
  cursor:pointer;transition:opacity .15s,transform .1s;letter-spacing:.3px;
}
.btn:hover{opacity:.9;transform:translateY(-1px);}
.btn:active{transform:translateY(0);}
.err{
  width:100%%;background:#2a0a0a;border:1px solid #7f1d1d;border-radius:10px;
  color:#fca5a5;padding:10px 14px;font-size:.82rem;text-align:center;
}
.pub-link{font-size:.78rem;color:#475569;}
.pub-link a{color:#60a5fa;text-decoration:none;font-weight:600;}
.pub-link a:hover{text-decoration:underline;}
</style>
</head>
<body>
<div class="card">
  <div class="logo-wrap">
    <img src="data:image/png;base64,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" alt="Luiza Labs" class="logo-img">
    <span class="card-title">&#128274;&#160;Painel Administrativo</span>
  </div>
  <div class="divider"></div>
  {{ERROR_BLOCK}}
  <form method="POST" autocomplete="off" style="width:100%%;display:flex;flex-direction:column;gap:1.1rem;">
    <div class="field">
      <label for="password">Senha de acesso</label>
      <input type="password" id="password" name="password" autofocus required placeholder="••••••••">
    </div>
    <button type="submit" class="btn">Entrar</button>
  </form>
  <p class="pub-link">Acesso somente leitura? <a href="/home">Abrir invent&#225;rio p&#250;blico</a></p>
</div>
</body>
</html>"""

# ---------------------------------------------------------------------------
# Rotas Flask — registradas via função para suportar import lazy
# ---------------------------------------------------------------------------
def _register_routes(flask_app, req, jsonify_fn, render_tmpl):
    """Registra todas as rotas no app Flask passado como argumento."""
    from flask import session, redirect, url_for, Response as FlaskResponse

    # ---- Auth helpers ----
    def _is_admin() -> bool:
        return session.get('is_admin') is True

    def _require_admin():
        """Retorna resposta de erro se não for admin; None se OK."""
        if not _is_admin():
            return jsonify_fn({'error': 'Não autorizado. Faça login em /admin'}), 403
        return None

    # ---- /login ----
    @flask_app.route('/login', methods=['GET', 'POST'])
    def login():
        error = ''
        if req.method == 'POST':
            pw = req.form.get('password', '')
            if _check_admin_password(pw):
                session['is_admin'] = True
                session['username'] = 'admin'
                log.info(f'[audit] LOGIN bem-sucedido | ip={req.remote_addr}')
                next_url = req.args.get('next', '/admin')
                return redirect(next_url)
            log.warning(f'[audit] LOGIN falhou — senha errada | ip={req.remote_addr}')
            error = '<div class="err">Senha incorreta. Tente novamente.</div>'
        # Página de login inline (sem template externo)
        return FlaskResponse(_LOGIN_HTML.replace('{{ERROR_BLOCK}}', error),
                             mimetype='text/html; charset=utf-8')

    # ---- /logout ----
    @flask_app.route('/logout')
    def logout():
        session.clear()
        return redirect('/home')

    # ---- /home  (leitura pública) ----
    @flask_app.route('/')
    @flask_app.route('/home')
    def home():
        """Inventário público — somente leitura."""
        cache = load_cache()
        if not cache and not _scan_status['running']:
            return FlaskResponse(
                '<p style="font-family:sans-serif;padding:2rem;color:#ccc">'
                'Cache vazio. Peça ao administrador para executar um scan.</p>',
                status=404, mimetype='text/html'
            )
        printers = list(cache.values())
        generate_inventory_html(printers, INVENTORY_PATH, is_admin=False)
        return INVENTORY_PATH.read_text(encoding='utf-8'), 200, {
            'Content-Type': 'text/html; charset=utf-8'
        }

    # ---- /admin  (requer login) ----
    @flask_app.route('/admin')
    def admin():
        """Inventário administrativo — funcionalidades completas."""
        if not _is_admin():
            return redirect('/login?next=/admin')
        cache = load_cache()
        if not cache and not _scan_status['running']:
            return FlaskResponse(
                '<p style="font-family:sans-serif;padding:2rem;color:#ccc">'
                'Cache vazio. Execute <code>scan_printers.py</code> primeiro.</p>',
                status=404, mimetype='text/html'
            )
        printers = list(cache.values())
        generate_inventory_html(printers, INVENTORY_PATH, is_admin=True)
        return INVENTORY_PATH.read_text(encoding='utf-8'), 200, {
            'Content-Type': 'text/html; charset=utf-8'
        }

    # ---- /results  (redirect legado) ----
    @flask_app.route('/results')
    def results_legacy():
        """Redireciona URLs antigas para /home."""
        return redirect('/home')


    @flask_app.route('/api/status')
    def api_status():
        """Status do scan em andamento."""
        return jsonify_fn(dict(_scan_status))

    @flask_app.route('/api/online-status')
    def api_online_status():
        """Retorna o status de conectividade em memória para todos os IPs.
        O frontend usa este endpoint para atualizar os badges dinamicamente
        sem recarregar a página.
        """
        with _status_lock:
            snapshot = dict(_status_cache)
        return jsonify_fn(snapshot)

    @flask_app.route('/healthcheck')
    def healthcheck():
        """Verifica se o servidor está saudável e retorna métricas básicas."""
        cache = load_cache()
        uptime = int((datetime.now() - _server_start_time).total_seconds())
        return jsonify_fn({
            'ok':           True,
            'version':      '1.0',
            'uptime_s':     uptime,
            'scan_running': bool(_scan_status.get('running')),
            'cache_size':   len(cache),
        })

    @flask_app.route('/api/cds')
    def api_cds():
        """Retorna lista de CDs disponíveis no cache."""
        cache = load_cache()
        cds = sorted({str(p.get('filial', '')) for p in cache.values() if p.get('filial')},
                     key=lambda x: x.zfill(6))
        return jsonify_fn({'cds': cds})

    @flask_app.route('/api/cd/<cd>')
    def api_cd(cd):
        """Retorna impressoras de um CD específico a partir do cache."""
        cache = load_cache()
        printers = [p for p in cache.values() if str(p.get('filial', '')) == cd]
        return jsonify_fn({'cd': cd, 'total': len(printers), 'printers': printers})

    @flask_app.route('/probe')
    def probe_page():
        return render_tmpl('probe.html')

    @flask_app.route('/api/network-report')
    def api_network_report():
        """Relatório de configuração de rede de todas as impressoras do cache.
        Parâmetros opcionais:
          ?dns1=X.X.X.X  — filtra/compara com DNS primário alvo
          ?dns2=X.X.X.X  — filtra/compara com DNS secundário alvo
        """
        target_dns1 = req.args.get('dns1', '').strip() or None
        target_dns2 = req.args.get('dns2', '').strip() or None
        cache = load_cache()
        report = []
        for p in cache.values():
            mfr = p.get('fabricante', '')
            if mfr not in VENDOR_ADAPTERS:
                continue
            dns1_ok = (p.get('dns1') == target_dns1) if target_dns1 else None
            dns2_ok = (p.get('dns2') == target_dns2) if target_dns2 else None
            needs_update = (
                (target_dns1 and not dns1_ok) or
                (target_dns2 and not dns2_ok)
            ) if (target_dns1 or target_dns2) else None
            report.append({
                'ip':           p.get('ip'),
                'fabricante':   mfr,
                'modelo':       p.get('modelo'),
                'filial':       p.get('filial'),
                'hostname':     p.get('hostname'),
                'dns1':         p.get('dns1'),
                'dns2':         p.get('dns2'),
                'gateway':      p.get('gateway'),
                'ip_mode':      p.get('ip_mode'),
                'dns1_ok':      dns1_ok,
                'dns2_ok':      dns2_ok,
                'needs_update': needs_update,
                'last_updated': p.get('last_updated'),
                'dns_apply_status': p.get('dns_apply_status'),
            })
        # Ordena: com problema primeiro, depois por filial
        report.sort(key=lambda r: (
            0 if r['needs_update'] else 1,
            str(r.get('filial', '')).zfill(6),
            r.get('ip', ''),
        ))
        needs_count = sum(1 for r in report if r.get('needs_update'))
        return jsonify_fn({
            'total':        len(report),
            'needs_update': needs_count,
            'target_dns1':  target_dns1,
            'target_dns2':  target_dns2,
            'printers':     report,
        })

    @flask_app.route('/api/export-csv')
    def api_export_csv():
        """Exporta todas as impressoras do cache como CSV.

        Parâmetros opcionais:
          ?cd=350          — filtra por filial
          ?fabricante=HP   — filtra por fabricante
        """
        import csv, io
        cache = load_cache()
        printers = list(cache.values())

        f_cd  = req.args.get('cd', '').strip()
        f_fab = req.args.get('fabricante', '').strip().upper()
        if f_cd:
            printers = [p for p in printers if str(p.get('filial', '')) == f_cd]
        if f_fab:
            printers = [p for p in printers if (p.get('fabricante') or '').upper() == f_fab]

        printers.sort(key=lambda p: (str(p.get('filial', '')).zfill(6), p.get('ip', '')))

        fields = ['ip', 'filial', 'fabricante', 'modelo', 'serial', 'tipo',
                  'metrica', 'toner', 'consumivel2',
                  'hostname', 'dns1', 'dns2', 'gateway', 'ip_mode',
                  'status', 'first_seen', 'last_updated', 'dns_apply_status',
                  'auth_ok', 'auth_user']

        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fields, extrasaction='ignore',
                                lineterminator='\r\n')
        writer.writeheader()
        for p in printers:
            writer.writerow({f: (p.get(f) or '') for f in fields})

        from flask import Response as FlaskResponse
        cd_suffix = f'_CD{f_cd}' if f_cd else ''
        fab_suffix = f'_{f_fab}' if f_fab else ''
        filename = f'impressoras{cd_suffix}{fab_suffix}.csv'
        return FlaskResponse(
            buf.getvalue().encode('utf-8-sig'),   # BOM para Excel
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Type': 'text/csv; charset=utf-8',
            }
        )

    @flask_app.route('/api/set-credentials', methods=['POST'])
    def api_set_credentials():
        """[ADMIN] Salva credenciais por IP e recoleta configuracao de rede."""
        err = _require_admin()
        if err: return err
        import json as _json
        try:
            body = _json.loads(req.get_data(as_text=True) or '{}')
        except Exception:
            return jsonify_fn({'error': 'JSON invalido'}), 400

        ip       = (body.get('ip') or '').strip()
        user     = (body.get('user') or '').strip()
        password = body.get('password', '')

        if not ip:
            return jsonify_fn({'ok': False, 'error': 'ip obrigatorio'}), 400

        creds = load_printer_credentials()
        if user:
            creds[ip] = {'user': user, 'password': password}
        elif ip in creds:
            del creds[ip]
        save_printer_credentials(creds)

        # Recoleta configuracao de rede usando as novas credenciais
        cache = load_cache()
        p = cache.get(ip, {})
        mfr = p.get('fabricante', '')
        netcfg = {}
        if mfr in ('HP', 'Samsung', 'Zebra'):
            netcfg = get_network_config(ip, mfr)
            for k in ('hostname', 'dns1', 'dns2', 'gateway', 'ip_mode', 'auth_ok', 'auth_user'):
                if netcfg.get(k) is not None:
                    p[k] = netcfg[k]
            if p:
                cache[ip] = p
                # save_cache espera lista
                save_cache(list(cache.values()))

        admin_user = session.get('username', 'admin')
        log.info(f'[audit] SET_CREDENTIALS | user={admin_user} | ip_origem={req.remote_addr} | '
                 f'alvo={ip} printer_user={user!r} auth_ok={p.get("auth_ok")}')
        return jsonify_fn({
            'ok':        True,
            'auth_ok':   p.get('auth_ok'),
            'auth_user': p.get('auth_user'),
            'dns1':      p.get('dns1'),
            'dns2':      p.get('dns2'),
            'netcfg':    {k: v for k, v in netcfg.items() if k not in ('auth_ok', 'auth_user')},
        })

    @flask_app.route('/api/scan/start', methods=['POST'])
    def api_scan_start():
        """[ADMIN] Inicia um novo scan completo ou atualização incremental em background."""
        err = _require_admin()
        if err: return err

        if _scan_status.get('running'):
            return jsonify_fn({'error': 'Scan já está em andamento'}), 409

        import json as _json
        try:
            body = _json.loads(req.get_data(as_text=True) or '{}')
        except Exception:
            body = {}

        update_only = bool(body.get('update_only', False))
        mode = 'update' if update_only else 'full'
        scan_user = session.get('username', 'admin')
        log.info(f'[audit] SCAN_START | user={scan_user} | ip_origem={req.remote_addr} | mode={mode}')

        def _bg_scan():
            try:
                printers = run_full_scan(update_only=update_only)
                generate_inventory_html(printers, INVENTORY_PATH, is_admin=False)
                log.info(f'[scan/start] Scan {mode} concluído — {len(printers)} impressoras')
            except Exception as exc:
                log.error(f'[scan/start] Erro no scan {mode}: {exc}', exc_info=True)

        threading.Thread(target=_bg_scan, daemon=True,
                         name=f'scan-api-{mode}').start()

        return jsonify_fn({'started': True, 'mode': mode})

    @flask_app.route('/api/apply-dns', methods=['POST'])
    def api_apply_dns():
        """[ADMIN] Aplica DNS em uma ou mais impressoras."""
        err = _require_admin()
        if err: return err
        import json as _json
        try:
            body = _json.loads(req.get_data(as_text=True) or '{}')
        except Exception:
            return jsonify_fn({'error': 'JSON inválido'}), 400

        dns1 = body.get('dns1', '').strip()
        dns2 = body.get('dns2', '').strip()
        if not dns1:
            return jsonify_fn({'error': 'Campo dns1 obrigatório'}), 400

        cache = load_cache()

        # Determina lista de IPs alvo
        if body.get('all_pending'):
            t1 = body.get('target_dns1', dns1).strip()
            t2 = body.get('target_dns2', dns2).strip()
            target_ips = [
                p['ip'] for p in cache.values()
                if p.get('fabricante') in ('HP', 'Samsung') and (
                    (t1 and p.get('dns1') != t1) or
                    (t2 and p.get('dns2') != t2)
                )
            ]
        else:
            target_ips = [i.strip() for i in body.get('ips', []) if i.strip()]

        if not target_ips:
            return jsonify_fn({'message': 'Nenhum equipamento para atualizar', 'results': []}), 200

        results = []
        lock_apply = threading.Lock()

        def _apply_worker(ip: str) -> None:
            p = cache.get(ip)
            if not p:
                with lock_apply:
                    results.append({'ip': ip, 'ok': False,
                                    'detail': 'IP não encontrado no cache'})
                return
            mfr = p.get('fabricante', '')
            try:
                r = apply_dns_config(ip, mfr, dns1, dns2)
            except Exception as _exc:
                log.error(f'[apply_dns] {ip} exceção não tratada: {_exc}', exc_info=True)
                r = {'ok': False, 'method': 'exception', 'detail': str(_exc)[:100]}
            # Persiste status no cache
            if r['ok']:
                p['dns1'] = dns1
                p['dns2'] = dns2
                p['dns_apply_status'] = f'OK {datetime.now().strftime("%d/%m %H:%M")} — {r["method"]}'
            else:
                p['dns_apply_status'] = f'FALHA {datetime.now().strftime("%d/%m %H:%M")} — {r["detail"][:80]}'
            cache[ip] = p
            with lock_apply:
                results.append({'ip': ip, 'fabricante': mfr,
                                 'ok': r['ok'], 'method': r.get('method', ''),
                                 'detail': r.get('detail', '')})

        threads = [threading.Thread(target=_apply_worker, args=(ip,), daemon=True)
                   for ip in target_ips]
        for t in threads: t.start()
        for t in threads: t.join()

        # Salva cache com status atualizado
        save_cache(list(cache.values()))

        ok_count   = sum(1 for r in results if r['ok'])
        fail_count = len(results) - ok_count
        user = session.get('username', 'admin')
        log.info(f'[audit] APPLY_DNS | user={user} | ip_origem={req.remote_addr} | '
                 f'dns1={dns1} dns2={dns2} | alvos={len(results)} ok={ok_count} fail={fail_count}')
        return jsonify_fn({
            'total':      len(results),
            'ok':         ok_count,
            'failed':     fail_count,
            'dns1':       dns1,
            'dns2':       dns2,
            'results':    results,
        })

    @flask_app.route('/api/probe')
    def api_probe():
        ip = req.args.get('ip', '').strip()
        if not ip:
            return jsonify_fn({'error': 'Parâmetro ?ip= ausente'}), 400
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify_fn({'error': f'IP inválido: {ip!r}'}), 400

        ports = [
            {'label': 'HTTP (80/TCP)',   'result': _probe_tcp(ip, 80)},
            {'label': 'HTTPS (443/TCP)', 'result': _probe_tcp(ip, 443)},
            {'label': 'IPP (631/TCP)',   'result': _probe_tcp(ip, 631)},
            {'label': 'RAW (9100/TCP)',  'result': _probe_tcp(ip, 9100)},
        ]
        snmp = [
            {'label': 'Serial — padrão RFC3805',              'result': _probe_snmp_oid(ip, OID_SERIAL)},
            {'label': 'Contador de páginas (RFC 3805)',        'result': _probe_snmp_oid(ip, OID_PAGE_COUNT)},
            {'label': 'Zebra Serial (ZebraNet)',               'result': _probe_snmp_oid(ip, OID_ZEBRA_SERIAL_1)},
            {'label': 'Zebra Serial (Eltron/legado)',          'result': _probe_snmp_oid(ip, OID_ZEBRA_SERIAL_2)},
            {'label': 'Zebra Odômetro (ZebraNet, dot count)',  'result': _probe_snmp_oid(ip, OID_ZEBRA_ODOM_DOTS)},
            {'label': 'Zebra Odômetro (Eltron, polegadas)',    'result': _probe_snmp_oid(ip, OID_ZEBRA_ODOM_ELTRON)},
            {'label': 'HP Toner (%)',                          'result': _probe_snmp_oid(ip, OID_HP_TONER)},
            {'label': 'HP Kit Manutenção (%)',                 'result': _probe_snmp_oid(ip, OID_HP_MAINT_KIT)},
            {'label': 'Samsung Toner (%)',                     'result': _probe_snmp_oid(ip, OID_SAMSUNG_TONER)},
            {'label': 'Samsung Unidade de Imagem (%)',         'result': _probe_snmp_oid(ip, OID_SAMSUNG_DRUM)},
        ]
        http_result = _probe_http(ip)
        log.info(
            f'[probe] {ip} — fabricante={http_result.get("manufacturer")} '
            f'http={http_result.get("ok")} snmp_serial={snmp[0]["result"].get("ok")}'
        )
        return jsonify_fn({
            'ip':           ip,
            'ports':        ports,
            'snmp':         snmp,
            'http':         http_result,
            'manufacturer': http_result.get('manufacturer') or 'Não identificado',
        })


# ---------------------------------------------------------------------------
# Scan + abertura do inventário (roda em thread de background)
# ---------------------------------------------------------------------------
def _scan_and_open(update_only: bool = False) -> None:
    try:
        mode = 'atualização incremental' if update_only else 'scan completo'
        print(f'[3/3] Iniciando {mode}...')
        printers = run_full_scan(update_only=update_only)
        generate_inventory_html(printers, INVENTORY_PATH, is_admin=False)
        # Abre diretamente o /home no browser se Flask já estiver rodando,
        # senão abre o arquivo local (modo offline)
        local_url = f'http://127.0.0.1:{PROBE_PORT}/home'
        webbrowser.open(local_url)
        log.info(f'Inventário disponível em: {local_url}')
    except Exception as exc:
        log.error(f'Erro no scan: {exc}', exc_info=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    _setup_file_logging()   # ativa log em arquivo (automacao.log)
    parser = argparse.ArgumentParser(
        description='Scanner de impressoras — gera inventário estático HTML'
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '--probe-only', action='store_true',
        help='Inicia somente o servidor de probe (sem scan de rede)',
    )
    group.add_argument(
        '--update', action='store_true',
        help='Atualiza apenas contadores/consumíveis do cache sem rodar nmap',
    )
    args = parser.parse_args()

    if args.probe_only:
        log.info('Modo --probe-only: sem scan de rede ao iniciar.')
        # Se o cache está vazio em modo probe-only, dispara scan completo
        # automaticamente para popular o inventário
        if not load_cache():
            log.info('[probe-only] Cache vazio — iniciando scan completo automático.')
            threading.Thread(
                target=_scan_and_open, args=(False,),
                daemon=True, name='scan-master'
            ).start()
    else:
        update_only = args.update
        threading.Thread(
            target=_scan_and_open, args=(update_only,),
            daemon=True, name='scan-master'
        ).start()

    # --- Background scheduler: atualiza métricas a cada 60 minutos ---
    _SCHEDULER_INTERVAL_S = 3600  # 60 min

    def _bg_scheduler() -> None:
        """Loop daemon que dispara run_full_scan(update_only=True) periodicamente."""
        log.info(f'[scheduler] Iniciado. Intervalo: {_SCHEDULER_INTERVAL_S // 60} min.')
        while True:
            time.sleep(_SCHEDULER_INTERVAL_S)
            log.info('[scheduler] Iniciando atualizacao de metricas (update_only=True)...')
            try:
                # Se o cache está vazio, faz scan completo (com nmap)
                # em vez de update_only para não perder redes
                cache_empty = not bool(load_cache())
                run_full_scan(update_only=(not cache_empty))
                log.info('[scheduler] Atualizacao concluida.')
            except Exception as _exc:
                log.warning(f'[scheduler] Falha na atualizacao: {_exc}')

    threading.Thread(
        target=_bg_scheduler,
        daemon=True,
        name='bg-scheduler',
    ).start()
    log.info('[scheduler] Thread bg-scheduler registrada.')

    # Healthcheck worker — mantém _status_cache atualizado (TCP 80, 120 s)
    threading.Thread(
        target=_healthcheck_loop,
        daemon=True,
        name='hc-worker',
    ).start()
    log.info('[healthcheck] Thread hc-worker registrada.')

    # Importa Flask lazy — só aqui, após o scan já estar rodando em background
    flask_app = _get_flask_app()
    import socket as _sock
    _local_ip = _sock.gethostbyname(_sock.gethostname())
    print('Servidor acessível em:')
    print(f'  Visualização pública : http://127.0.0.1:{PROBE_PORT}/home')
    print(f'  Painel admin         : http://127.0.0.1:{PROBE_PORT}/admin  (requer login)')
    print(f'  Rede local (público) : http://{_local_ip}:{PROBE_PORT}/home')
    print(f'  Rede local (admin)   : http://{_local_ip}:{PROBE_PORT}/admin')
    print(f'  Probe de diagnóstico : http://{_local_ip}:{PROBE_PORT}/probe')
    flask_app.run(host='0.0.0.0', port=PROBE_PORT, debug=False, use_reloader=False)


if __name__ == '__main__':
    main()
