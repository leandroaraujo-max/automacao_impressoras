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
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Optional

import nmap
import pandas as pd
from flask import Flask, jsonify, redirect, render_template, url_for

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
        _stop_flag    = False

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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)
