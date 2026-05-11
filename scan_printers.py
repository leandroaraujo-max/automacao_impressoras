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
import socket
import threading
import time
import urllib.error
import urllib.request
import webbrowser
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_DIR       = Path(__file__).parent
CSV_PATH       = BASE_DIR / 'Redes Imps CDS' / 'Endereçamento_Atualizado.csv'
INVENTORY_PATH = BASE_DIR / 'inventory.html'
CACHE_PATH     = BASE_DIR / 'cache.json'
TEMPLATE_PATH  = BASE_DIR / 'Templates' / 'inventory_template.html'
PROBE_PORT     = 5001

SNMP_COMMUNITY  = 'public'
SNMP_TIMEOUT    = 2
HTTP_TIMEOUT    = 3
NMAP_ARGS       = '-p 80,443,631,9100 --open -T4'
MAX_CONCURRENT  = 10

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

# HP — EWS HTTP Basic Auth
HP_EWS_USER     = 'administrador'
HP_EWS_PASSWORD = 'simpress1934@'

# Samsung SyncThru HTTP
SAMSUNG_USER     = 'admin'
SAMSUNG_PASSWORDS = ['sec00000', '1111', 'simpress1934@']

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

# Status global do scan — exposto via /api/status
_scan_status: dict = {
    'running':         False,
    'total':           0,
    'networks_done':   0,
    'networks_total':  0,
    'started_at':      None,
    'finished_at':     None,
}

# Flask é carregado apenas quando o servidor de probe precisa subir
_flask_app = None


def _get_flask_app():
    """Import e criação lazy do app Flask — evita lentidão no startup."""
    global _flask_app
    if _flask_app is not None:
        return _flask_app
    from flask import Flask, jsonify, render_template, request as flask_request
    import logging as _pylog
    _pylog.getLogger('werkzeug').setLevel(_pylog.WARNING)
    _flask_app = Flask(__name__)
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
        log.error(f'Erro ao ler CSV: {exc}')
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


def _http_get_page(ip: str, path: str, use_https: bool = False,
                   timeout: int = HTTP_TIMEOUT) -> Optional[str]:
    """GET helper — retorna body (str) ou None em caso de erro."""
    import ssl
    scheme = 'https' if use_https else 'http'
    url = f'{scheme}://{ip}{path}'
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'PrinterScanner/1.0'})
        if use_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.read(65536).decode('utf-8', errors='ignore')
        else:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(65536).decode('utf-8', errors='ignore')
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Configuração de rede (DNS, Gateway, Hostname)
# ---------------------------------------------------------------------------

def get_network_config(ip: str, manufacturer: str) -> dict:
    """Coleta hostname, DNS1, DNS2, gateway e modo IP do equipamento.

    HP   → HP JetDirect SNMP MIB (OIDs 1.3.6.1.4.1.11.2.4.3.5.*)
         fallback → EWS /DevMgmt/NetworkConfigDyn.json
    Samsung → SyncThru /sws/app/information/network/networkSetting.json
    """
    import re
    result = {'hostname': None, 'dns1': None, 'dns2': None,
              'gateway': None, 'ip_mode': None}

    if manufacturer == 'HP':
        # --- SNMP JetDirect (mais confiável) ---
        hn  = _snmp_get(ip, OID_HP_HOSTNAME) or _snmp_get(ip, OID_STD_HOSTNAME)
        d1  = _snmp_get(ip, OID_HP_DNS_PRIMARY)
        d2  = _snmp_get(ip, OID_HP_DNS_SECONDARY)
        gw  = _snmp_get(ip, OID_HP_GATEWAY)
        raw_mode = _snmp_get(ip, OID_HP_IP_CONFIG)
        mode_map = {'1': 'BOOTP', '2': 'DHCP', '3': 'Manual', '4': 'AutoIP'}
        if raw_mode and raw_mode.isdigit():
            ip_mode = mode_map.get(raw_mode, f'Código {raw_mode}')
        else:
            ip_mode = raw_mode

        result = {'hostname': hn, 'dns1': d1 or None, 'dns2': d2 or None,
                  'gateway': gw, 'ip_mode': ip_mode}

        # --- Fallback HTTP EWS JSON (impressoras modernas sem JetDirect MIB) ---
        if not d1:
            for use_https in (True, False):
                body = _http_get_page(ip, '/DevMgmt/NetworkConfigDyn.json',
                                      use_https=use_https)
                if not body:
                    continue
                try:
                    import json as _json
                    data = _json.loads(body)
                    def _deep(d, *keys):
                        for k in keys:
                            if isinstance(d, dict):
                                d = d.get(k)
                            else:
                                return None
                        return d
                    dns_cfg = _deep(data, 'NetworkConfigDyn', 'IPConfiguration',
                                    'DNS')
                    if dns_cfg:
                        result['dns1']    = dns_cfg.get('PreferredServer') or result['dns1']
                        result['dns2']    = dns_cfg.get('AlternateServer')  or result['dns2']
                    gw_cfg = _deep(data, 'NetworkConfigDyn', 'IPConfiguration', 'DefaultGateway')
                    if gw_cfg:
                        result['gateway'] = gw_cfg or result['gateway']
                    break
                except Exception:
                    pass

    elif manufacturer == 'Samsung':
        # --- SyncThru JSON ---
        for path in (
            '/sws/app/information/network/networkSetting.json',
            '/sws/swsapi/swsconfig?subtype=networkSetting',
        ):
            body = _http_get_page(ip, path)
            if not body:
                continue
            try:
                import json as _json
                data = _json.loads(body)
                # Estrutura varia por firmware; busca recursiva por campos comuns
                flat = json.dumps(data)  # noqa: F821 (json importado no outer scope)
                dns1_m = re.search(r'(?:primaryDns|dns1|preferredDns)["\s:]+([\d.]{7,15})', flat, re.I)
                dns2_m = re.search(r'(?:secondaryDns|dns2|alternateDns)["\s:]+([\d.]{7,15})', flat, re.I)
                gw_m   = re.search(r'(?:gateway|defaultGateway)["\s:]+([\d.]{7,15})', flat, re.I)
                hn_m   = re.search(r'(?:hostName|hostname)["\s:]+"([^"]{2,80})"', flat, re.I)
                dhcp_m = re.search(r'(?:dhcp|ipMode|ipMethod)["\s:]+"?([\w]+)"?', flat, re.I)
                if dns1_m:
                    result['dns1']     = dns1_m.group(1)
                    result['dns2']     = dns2_m.group(1) if dns2_m else None
                    result['gateway']  = gw_m.group(1)   if gw_m   else None
                    result['hostname'] = hn_m.group(1)   if hn_m   else None
                    if dhcp_m:
                        v = dhcp_m.group(1).upper()
                        result['ip_mode'] = 'DHCP' if 'DHCP' in v or v == 'TRUE' else 'Manual'
                    break
            except Exception:
                pass

    # Limpa strings vazias / zero IPs
    for k in ('dns1', 'dns2', 'gateway'):
        v = result.get(k)
        if v in (None, '', '0.0.0.0', '0'):
            result[k] = None

    log.debug(f'[netcfg] {ip} → {result}')
    return result


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
        # Verifica se recebeu SetResponse (0xa2) sem erro
        return len(resp) > 6 and resp[0] == 0x30
    except Exception as e:
        log.debug(f'[snmp_set] {ip} OID={oid} erro: {e}')
        return False


def _http_post_authenticated(ip: str, path: str, payload: str,
                              user: str, password: str,
                              content_type: str = 'application/x-www-form-urlencoded',
                              use_https: bool = False) -> Optional[str]:
    """POST HTTP com autenticação Basic."""
    import base64, ssl
    scheme = 'https' if use_https else 'http'
    url = f'{scheme}://{ip}{path}'
    creds = base64.b64encode(f'{user}:{password}'.encode()).decode()
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
        if use_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx) as r:
                return r.read(4096).decode('utf-8', errors='ignore')
        else:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                return r.read(4096).decode('utf-8', errors='ignore')
    except Exception as e:
        log.debug(f'[http_post] {ip}{path} erro: {e}')
        return None


def apply_dns_config(ip: str, manufacturer: str,
                     dns1: str, dns2: str) -> dict:
    """Aplica DNS primário e secundário no equipamento.

    HP:
      1. SNMP SET JetDirect (OIDs 29/30) — mais universal
      2. Fallback EWS HTTP POST /hp/device/IPConfiguration/SetStaticDNS
    Samsung:
      1. HTTP POST SyncThru /sws/swsapi/swsconfig?subtype=networkSetting
         com credenciais (tenta todas as senhas conhecidas)

    Retorna dict {'ok': bool, 'method': str, 'detail': str}
    """
    result = {'ok': False, 'method': '', 'detail': ''}

    if manufacturer == 'HP':
        # --- Tentativa 1: SNMP SET ---
        ok1 = _snmp_set_string(ip, OID_HP_DNS_PRIMARY,   dns1)
        ok2 = _snmp_set_string(ip, OID_HP_DNS_SECONDARY, dns2)
        if ok1 or ok2:
            result = {'ok': True, 'method': 'SNMP SET JetDirect',
                      'detail': f'DNS1={dns1} DNS2={dns2} (SNMP ok1={ok1} ok2={ok2})'}
            log.info(f'[apply_dns] {ip} HP SNMP SET ok: {dns1}/{dns2}')
            return result

        # --- Tentativa 2: EWS HTTP (com e sem HTTPS) ---
        import urllib.parse
        for use_https in (True, False):
            # Endpoint para impressoras HP modernas
            payload = urllib.parse.urlencode({
                'PreferredDNSServer':  dns1,
                'AlternateDNSServer':  dns2,
            })
            resp = _http_post_authenticated(
                ip, '/hp/device/IPConfiguration/SetStaticDNS',
                payload, HP_EWS_USER, HP_EWS_PASSWORD, use_https=use_https)
            if resp is not None:
                result = {'ok': True, 'method': f'EWS HTTP{"S" if use_https else ""}',
                          'detail': f'DNS1={dns1} DNS2={dns2}'}
                log.info(f'[apply_dns] {ip} HP EWS HTTP ok: {dns1}/{dns2}')
                return result

        result['detail'] = 'SNMP SET sem resposta e EWS HTTP sem resposta — verifique community de escrita e senha EWS'

    elif manufacturer == 'Samsung':
        import json as _json, urllib.parse
        payload_dict = {
            'networkSetting': {
                'tcpip': {'dns': {'primaryDns': dns1, 'secondaryDns': dns2}}
            }
        }
        payload_json = _json.dumps(payload_dict)
        for password in SAMSUNG_PASSWORDS:
            # SyncThru aceita JSON via PUT ou POST dependendo do firmware
            for method_path in (
                '/sws/swsapi/swsconfig?subtype=networkSetting',
                '/sws/app/information/network/networkSetting',
            ):
                resp = _http_post_authenticated(
                    ip, method_path, payload_json,
                    SAMSUNG_USER, password,
                    content_type='application/json')
                if resp is not None and ('ok' in resp.lower() or 'success' in resp.lower()
                                         or 'true' in resp.lower()):
                    result = {'ok': True, 'method': 'SyncThru HTTP POST',
                              'detail': f'DNS1={dns1} DNS2={dns2} senha={password[:3]}***'}
                    log.info(f'[apply_dns] {ip} Samsung SyncThru ok: {dns1}/{dns2}')
                    return result
        result['detail'] = ('SyncThru sem confirmação — verifique se o payload '  
                            'foi aceito manualmente em http://' + ip + '/sws')

    else:
        result['detail'] = f'Fabricante {manufacturer!r} sem suporte a apply_dns automatizado'

    log.warning(f'[apply_dns] {ip} FALHOU: {result["detail"]}')
    return result


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

    1. HTTP /server/SYSINFO.htm — Head Mileage (ZT/ZD series)
    2. HTTP /server/CFGPAGE.htm — Config page
    3. SNMP OID Eltron (polegadas, modelos GK/LP/legado)
    4. SNMP OID ZebraNet dot count ÷ DPI
    """
    import re
    for path in ('/server/SYSINFO.htm', '/server/CFGPAGE.htm'):
        body = _http_get_page(ip, path)
        if not body:
            continue
        # Ex: "Head Mileage: 1,234 in" ou "Head Odometer: 1234in"
        m = re.search(
            r'Head\s+(?:Mileage|Odometer)\s*[:\-=]?\s*([\d,]+)\s*in',
            body, re.I)
        if m:
            inches = int(m.group(1).replace(',', ''))
            if 0 < inches < 5_000_000:
                return f'{inches:,} pol.'
        # Às vezes reporta em dots
        m = re.search(
            r'Head\s+(?:Mileage|Odometer)\s*[:\-=]?\s*([\d,]+)\s*dot',
            body, re.I)
        if m:
            dots = int(m.group(1).replace(',', ''))
            if dots > 0:
                return f'{dots // ZEBRA_DEFAULT_DPI:,} pol.'

    # SNMP fallback
    val = _snmp_get(ip, OID_ZEBRA_ODOM_ELTRON)
    if val and val.lstrip('-').isdigit():
        inches = int(val)
        if 0 < inches < 5_000_000:
            return f'{inches:,} pol.'

    val = _snmp_get(ip, OID_ZEBRA_ODOM_DOTS)
    if val and val.lstrip('-').isdigit():
        dots = int(val)
        if dots > 0:
            return f'{dots // ZEBRA_DEFAULT_DPI:,} pol.'

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
        log.error(f'Erro ao salvar cache: {exc}')


def update_metrics_from_cache(cached: dict) -> dict:
    """Atualiza campos dinâmicos; re-detecta modelo/fabricante se inválidos."""
    ip     = cached['ip']
    mfr    = cached.get('fabricante', '')
    serial = cached.get('serial', '')
    updated = dict(cached)
    now = datetime.now().isoformat(timespec='seconds')

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

    # Atualiza configuração de rede (sempre que for HP ou Samsung)
    if mfr in ('HP', 'Samsung'):
        netcfg = get_network_config(ip, mfr)
        updated['hostname'] = netcfg.get('hostname') or updated.get('hostname')
        updated['dns1']     = netcfg.get('dns1')     or updated.get('dns1')
        updated['dns2']     = netcfg.get('dns2')     or updated.get('dns2')
        updated['gateway']  = netcfg.get('gateway')  or updated.get('gateway')
        updated['ip_mode']  = netcfg.get('ip_mode')  or updated.get('ip_mode')

    updated['last_updated'] = now
    return updated


# ---------------------------------------------------------------------------
# Diagnóstico de conectividade — /api/probe
# ---------------------------------------------------------------------------

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
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
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
    """Escaneia uma rede; ignora IPs já no cache (serão atualizados separadamente)."""
    network = entry['network']
    cd      = entry['cd']
    found: list[dict] = []
    now = datetime.now().isoformat(timespec='seconds')

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
                    continue  # host já no cache — será atualizado pelo updater

                # Portas de impressão abertas = quase certamente uma impressora
                open_ports: set[int] = set()
                for proto in ('tcp', 'udp'):
                    if proto in nm[host]:
                        for p, info in nm[host][proto].items():
                            if info.get('state') == 'open':
                                open_ports.add(p)
                is_printer_port = bool(open_ports & {631, 9100})

                manufacturer = detect_manufacturer(host)
                if manufacturer not in KNOWN_MANUFACTURERS:
                    if is_printer_port:
                        log.info(f'[CD {cd}] {host} — porta 9100/631 aberta, fabricante nao identificado → adicionado como Desconhecido')
                        manufacturer = 'Desconhecido'
                    else:
                        log.info(f'[CD {cd}] {host} — fabricante nao identificado, sem porta de impressao')
                        continue

                tipo_real = resolve_tipo(manufacturer)
                serial    = get_serial(host, manufacturer)
                modelo    = get_model(host, manufacturer)
                toner     = None
                consumivel2 = None

                if manufacturer == 'Zebra':
                    metrica = get_zebra_odometer(host)
                elif manufacturer == 'HP':
                    metrica = get_page_count(host)
                    toner, consumivel2 = get_hp_consumables(host)
                elif manufacturer == 'Samsung':
                    metrica = get_page_count(host)
                    toner, consumivel2 = get_samsung_consumables(host)
                else:  # Honeywell
                    metrica = get_page_count(host)

                # Coleta configuração de rede (DNS, Gateway, Hostname)
                netcfg = {}
                if manufacturer in ('HP', 'Samsung'):
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
                ).to_dict()

                log.info(
                    f'[CD {cd}] NOVO {host} ({manufacturer}/{tipo_real}) '
                    f'modelo={modelo} serial={serial} metrica={metrica}'
                )
                found.append(printer)

        except Exception as exc:
            log.error(f'Erro ao escanear {network}: {exc}')

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
    if known_ips:
        log.info(f'Atualizando métricas de {len(known_ips)} hosts em cache...')

        def _update_worker(cached: dict) -> None:
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
def generate_inventory_html(printers: list[dict], output_path: Path) -> None:
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
        )
    )
    output_path.write_text(html, encoding='utf-8')
    log.info(f'Inventário gerado: {output_path}  ({total} impressoras)')


# ---------------------------------------------------------------------------
# Rotas Flask — registradas via função para suportar import lazy
# ---------------------------------------------------------------------------
def _register_routes(flask_app, req, jsonify_fn, render_tmpl):
    """Registra todas as rotas no app Flask passado como argumento."""

    @flask_app.route('/results')
    def results():
        """Regenera o inventário a partir do cache + template e serve."""
        cache = load_cache()
        if not cache and not _scan_status['running']:
            return (
                '<p style="font-family:sans-serif;padding:2rem;color:#ccc">'
                'Cache vazio. Execute <code>scan_printers.py</code> primeiro.</p>'
            ), 404
        printers = list(cache.values())
        generate_inventory_html(printers, INVENTORY_PATH)
        return INVENTORY_PATH.read_text(encoding='utf-8'), 200, {
            'Content-Type': 'text/html; charset=utf-8'
        }

    @flask_app.route('/api/status')
    def api_status():
        """Status do scan em andamento."""
        return jsonify_fn(dict(_scan_status))

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
            if mfr not in ('HP', 'Samsung'):
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

    @flask_app.route('/api/apply-dns', methods=['POST'])
    def api_apply_dns():
        """Aplica DNS em uma ou mais impressoras.

        Body JSON:
          { "dns1": "X.X.X.X", "dns2": "X.X.X.X",
            "ips": ["X.X.X.X", ...] }   -- lista específica, OU
          { "dns1": "X.X.X.X", "dns2": "X.X.X.X",
            "all_pending": true,
            "target_dns1": "...", "target_dns2": "..." }  -- todos com DNS divergente
        """
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
            if mfr not in ('HP', 'Samsung'):
                with lock_apply:
                    results.append({'ip': ip, 'ok': False,
                                    'detail': f'Fabricante {mfr!r} sem suporte'})
                return
            r = apply_dns_config(ip, mfr, dns1, dns2)
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
        log.info(f'[apply_dns] Aplicado em {ok_count}/{len(results)} equipamentos '
                 f'(dns1={dns1} dns2={dns2})')
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
        generate_inventory_html(printers, INVENTORY_PATH)
        url = INVENTORY_PATH.as_uri()
        webbrowser.open(url)
        log.info(f'Inventário aberto no browser: {url}')
    except Exception as exc:
        log.error(f'Erro no scan: {exc}', exc_info=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
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
        log.info('Modo --probe-only: sem scan de rede.')
    else:
        update_only = args.update
        threading.Thread(
            target=_scan_and_open, args=(update_only,),
            daemon=True, name='scan-master'
        ).start()

    # Importa Flask lazy — só aqui, após o scan já estar rodando em background
    flask_app = _get_flask_app()
    import socket as _sock
    _local_ip = _sock.gethostbyname(_sock.gethostname())
    print('Servidor acessível em:')
    print(f'  Inventário (local) : http://127.0.0.1:{PROBE_PORT}/results')
    print(f'  Inventário (rede)  : http://{_local_ip}:{PROBE_PORT}/results')
    print(f'  Probe              : http://{_local_ip}:{PROBE_PORT}/probe')
    flask_app.run(host='0.0.0.0', port=PROBE_PORT, debug=False, use_reloader=False)


if __name__ == '__main__':
    main()
