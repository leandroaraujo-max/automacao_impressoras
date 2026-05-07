"""Scanner de Impressoras de Rede
Backend Flask — Detecta HP, Samsung, Zebra e Honeywell nas redes dos CDs.

Requisitos:
    pip install flask pandas python-nmap pysnmp
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import os
import socket
import struct
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Optional

import nmap
import pandas as pd
from flask import Flask, jsonify, redirect, render_template, request, url_for

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
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(
    BASE_DIR, 'Redes Imps CDS',
    'Endereçamento de Rede CDS - Rede CDS.csv',
)

SNMP_COMMUNITY  = 'public'
SNMP_TIMEOUT    = 2
HTTP_TIMEOUT    = 3
NMAP_ARGS       = '-p 80,443,631,9100 --open -T4'
MAX_CONCURRENT  = 10

# Standard Printer MIB OIDs (RFC 3805)
OID_SERIAL     = '1.3.6.1.2.1.43.5.1.1.17.1'
OID_PAGE_COUNT = '1.3.6.1.2.1.43.10.2.1.4.1.1'

# Zebra-specific OIDs
OID_ZEBRA_SERIAL_1 = '1.3.6.1.4.1.10642.1.9.0'   # Zebra enterprise serial
OID_ZEBRA_SERIAL_2 = '1.3.6.1.4.1.683.6.2.3.2.1.6.1'  # Zebra alt

KNOWN_MANUFACTURERS = frozenset({'HP', 'Samsung', 'Zebra', 'Honeywell'})
LASER_MANUFACTURERS = frozenset({'HP', 'Samsung'})

_MFR_KEYWORDS: dict[str, tuple[str, ...]] = {
    'HP':        ('hp', 'laserjet', 'hewlett', 'hp-http', 'jetdirect'),
    'Samsung':   ('samsung',),
    'Zebra':     ('zebra', 'zpl', 'zt', 'zd'),
    'Honeywell': ('honeywell', 'intermec', 'datamax'),
}

# ---------------------------------------------------------------------------
# Flask App + estado global thread-safe
# ---------------------------------------------------------------------------
app = Flask(__name__)

_scan_cache:   list[dict] = []
_scan_running: bool       = False
_stop_flag:    bool       = False
_scan_threads: list[threading.Thread] = []
_cache_lock                = threading.Lock()
_nmap_sem                  = threading.Semaphore(MAX_CONCURRENT)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class PrinterInfo:
    ip:         str
    fabricante: str
    serial:     str
    contador:   Optional[str]
    status:     str
    filial:     str
    tipo:       str

    def to_dict(self) -> dict:
        return asdict(self)

# ---------------------------------------------------------------------------
# Carregar redes do CSV (somente redes já preenchidas no CSV)
# ---------------------------------------------------------------------------
def load_network_entries() -> list[dict]:
    """Carrega entradas de rede do CSV fonte.
    Usa apenas colunas de rede já preenchidas — sem tentativa de resolver DNS.
    """
    COLUMN_TRIPLETS = [
        ('Rede Imps Lasers',        'laser'),
        ('Rede imps Térmicas Mesa', 'termica'),
        ('Rede ImpsTérmicas WIFI',  'termica'),
    ]

    try:
        df = pd.read_csv(CSV_PATH)
    except FileNotFoundError:
        log.error(f'CSV não encontrado: {CSV_PATH}')
        return []
    except Exception as exc:
        log.error(f'Erro ao ler CSV: {exc}')
        return []

    entries: list[dict] = []
    seen: set[tuple] = set()

    for _, row in df.iterrows():
        cd = str(row.get('CD', '')).strip()

        for net_col, tipo in COLUMN_TRIPLETS:
            raw_net = str(row.get(net_col, '')).strip()

            if (not raw_net
                    or raw_net in ('nan', 'NaN', 'DNS_NAO_ENCONTRADO')
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
                entries.append({'network': raw_net, 'cd': cd, 'tipo': tipo})

    log.info(f'{len(entries)} entradas de rede carregadas.')
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


def get_page_count(ip: str) -> Optional[str]:
    return _snmp_get(ip, OID_PAGE_COUNT)

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
    """Identifica o fabricante via HTTP (header Server + body porta 80)."""
    try:
        req = urllib.request.Request(
            f'http://{ip}/',
            headers={'User-Agent': 'PrinterScanner/1.0'},
        )
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            combined = (
                resp.headers.get('Server', '')
                + ' '
                + resp.read(4096).decode('utf-8', errors='ignore')
            )
        brand = _match_manufacturer(combined)
        if brand:
            return brand
    except Exception:
        pass
    return None

# ---------------------------------------------------------------------------
# Scan por rede
# ---------------------------------------------------------------------------
def scan_network(entry: dict) -> list[dict]:
    global _stop_flag
    network = entry['network']
    cd      = entry['cd']
    tipo    = entry['tipo']
    found: list[dict] = []

    with _nmap_sem:
        if _stop_flag:
            return found
        try:
            log.info(f'[CD {cd}] Iniciando scan: {network} ({tipo})')
            nm = nmap.PortScanner()
            nm.scan(hosts=network, arguments=NMAP_ARGS)

            for host in nm.all_hosts():
                if _stop_flag:
                    break
                if nm[host].state() != 'up':
                    continue
                if not any(p in nm[host] for p in ('tcp', 'udp')):
                    continue

                manufacturer = detect_manufacturer(host)

                if manufacturer not in KNOWN_MANUFACTURERS:
                    log.debug(f'[CD {cd}] {host} ignorado — fabricante não identificado')
                    continue

                serial   = get_serial(host, manufacturer)
                contador = None
                if manufacturer in LASER_MANUFACTURERS and tipo == 'laser':
                    contador = get_page_count(host)

                printer = PrinterInfo(
                    ip=host,
                    fabricante=manufacturer,
                    serial=serial,
                    contador=contador,
                    status='Online',
                    filial=cd,
                    tipo=tipo,
                ).to_dict()

                log.info(f'[CD {cd}] ok {host} ({manufacturer}) serial={serial}')
                found.append(printer)

        except Exception as exc:
            log.error(f'Erro ao escanear {network}: {exc}')

    return found

# ---------------------------------------------------------------------------
# Orquestrador do scan completo
# ---------------------------------------------------------------------------
def run_full_scan() -> None:
    global _scan_cache, _scan_running, _stop_flag, _scan_threads
    _scan_running = True
    _stop_flag    = False
    with _cache_lock:
        _scan_cache = []

    try:
        entries = load_network_entries()
        if not entries:
            log.warning('Nenhuma entrada de rede carregada. Verifique o CSV.')
            return

        log.info(f'Disparando scan para {len(entries)} redes...')

        threads: list[threading.Thread] = []

        def _worker(entry: dict) -> None:
            results = scan_network(entry)
            if results and not _stop_flag:
                with _cache_lock:
                    _scan_cache.extend(results)

        for e in entries:
            t = threading.Thread(
                target=_worker,
                args=(e,),
                daemon=True,
                name=f"scan-{e['cd']}-{e['tipo']}"
            )
            threads.append(t)

        with _cache_lock:
            _scan_threads = threads

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        if _stop_flag:
            log.info('Scan interrompido pelo usuário.')
        else:
            log.info(f'Scan concluído — {len(_scan_cache)} impressoras encontradas.')

    except Exception as exc:
        log.error(f'Erro crítico no scan: {exc}')
    finally:
        _scan_running = False
        # _stop_flag é preservado para que o último poll do frontend
        # ainda leia o estado 'interrompido'. Só é resetado em start_scan.

# ---------------------------------------------------------------------------
# Rotas Flask
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def start_scan():
    global _stop_flag
    if _scan_running:
        log.warning('Scan já em andamento — requisição ignorada.')
        return redirect(url_for('results'))
    _stop_flag = False
    threading.Thread(target=run_full_scan, daemon=True, name='scan-master').start()
    return redirect(url_for('results'))


@app.route('/scan/stop', methods=['POST'])
def stop_scan():
    global _stop_flag
    _stop_flag = True
    log.info('Sinal de parada enviado pelo usuário.')
    return jsonify({'status': 'stopping'})


@app.route('/api/results')
def api_results():
    with _cache_lock:
        snapshot = list(_scan_cache)
    return jsonify({
        'scan_running': _scan_running,
        'stop_requested': _stop_flag,
        'total':        len(snapshot),
        'printers':     snapshot,
    })


@app.route('/results')
def results():
    return render_template('results.html')


@app.route('/probe')
def probe_page():
    return render_template('probe.html')


@app.route('/api/probe')
def api_probe():
    ip = request.args.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'Parâmetro ?ip= ausente'}), 400
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({'error': f'IP inválido: {ip!r}'}), 400

    ports = [
        {'label': 'HTTP (80/TCP)',   'result': _probe_tcp(ip, 80)},
        {'label': 'HTTPS (443/TCP)', 'result': _probe_tcp(ip, 443)},
        {'label': 'IPP (631/TCP)',   'result': _probe_tcp(ip, 631)},
        {'label': 'RAW (9100/TCP)',  'result': _probe_tcp(ip, 9100)},
    ]
    snmp = [
        {'label': 'Serial — padrão RFC3805',  'result': _probe_snmp_oid(ip, OID_SERIAL)},
        {'label': 'Contador de páginas',      'result': _probe_snmp_oid(ip, OID_PAGE_COUNT)},
        {'label': 'Zebra Serial (OID 1)',      'result': _probe_snmp_oid(ip, OID_ZEBRA_SERIAL_1)},
        {'label': 'Zebra Serial (OID 2)',      'result': _probe_snmp_oid(ip, OID_ZEBRA_SERIAL_2)},
    ]
    http_result = _probe_http(ip)
    log.info(f'[probe] {ip} — fabricante={http_result.get("manufacturer")} '
             f'http={http_result.get("ok")} '
             f'snmp_serial={snmp[0]["result"].get("ok")}')
    return jsonify({
        'ip':           ip,
        'ports':        ports,
        'snmp':         snmp,
        'http':         http_result,
        'manufacturer': http_result.get('manufacturer') or 'Não identificado',
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)
