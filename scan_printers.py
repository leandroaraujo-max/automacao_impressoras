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

if not SNMP_AVAILABLE:
    log.warning(
        "pysnmp não instalado — número de série e contador indisponíveis. "
        "Para habilitar: pip install pysnmp"
    )

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(
    BASE_DIR, 'Redes Imps CDS',
    'Endereçamento de Rede CDS - Rede CDS.csv',
)

DNS_SUFFIX      = '.magazineluiza.intranet'
SNMP_COMMUNITY  = 'public'
SNMP_TIMEOUT    = 2    # segundos por consulta OID
HTTP_TIMEOUT    = 3    # segundos por requisição HTTP
NMAP_ARGS       = '-p 80,443,631,9100 --open -T4'
MAX_CONCURRENT  = 10   # máximo de processos nmap simultâneos

# Standard Printer MIB OIDs (RFC 3805)
OID_SERIAL     = '1.3.6.1.2.1.43.5.1.1.17.1'   # prtGeneralSerialNumber
OID_PAGE_COUNT = '1.3.6.1.2.1.43.10.2.1.4.1.1'  # prtMarkerLifeCount

KNOWN_MANUFACTURERS = frozenset({'HP', 'Samsung', 'Zebra', 'Honeywell'})
LASER_MANUFACTURERS = frozenset({'HP', 'Samsung'})

# Mapeamento de keywords para identificação de fabricante
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
_cache_lock                = threading.Lock()
_nmap_sem                  = threading.Semaphore(MAX_CONCURRENT)
_dns_pool                  = concurrent.futures.ThreadPoolExecutor(max_workers=30, thread_name_prefix='rdns')

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class PrinterInfo:
    ip:         str
    fila:       str            # PTR reverso (nslookup do IP)
    fabricante: str
    serial:     str
    contador:   Optional[str]  # somente laser HP/Samsung
    status:     str
    filial:     str            # número do CD
    tipo:       str            # 'laser' | 'termica'

    def to_dict(self) -> dict:
        return asdict(self)

# ---------------------------------------------------------------------------
# Resolução de rede — espelha lógica do Atualizar-Redes.ps1
# ---------------------------------------------------------------------------
def _resolve_dns(name: str) -> Optional[str]:
    """Resolve hostname para IPv4; tenta nome curto e depois FQDN."""
    for candidate in (name, f'{name}{DNS_SUFFIX}'):
        try:
            ip = socket.gethostbyname(candidate)
            log.info(f'DNS: {candidate!r} → {ip}')
            return ip
        except socket.gaierror:
            continue
    log.warning(f'DNS: não resolvido — {name!r}')
    return None


def _ip_to_cidr24(ip: str) -> str:
    """Converte IP para rede /24 correspondente."""
    octets = ip.split('.')
    return f'{octets[0]}.{octets[1]}.{octets[2]}.0/24'


def load_network_entries() -> list[dict]:
    """Carrega entradas de rede do CSV fonte.

    Para cada CD (filial), extrai as três faixas de rede:
      - Rede Imps Lasers       (laser)
      - Rede imps Térmicas Mesa (térmica)
      - Rede ImpsTérmicas WIFI  (térmica)

    Quando a coluna de rede está vazia, resolve o hostname da coluna DNS
    correspondente — mesma lógica do Atualizar-Redes.ps1.

    Retorna lista de: {'network': '10.x.x.0/24', 'cd': '50', 'tipo': 'laser'}
    """
    COLUMN_TRIPLETS = [
        ('DNS Imps Lasers',          'Rede Imps Lasers',        'laser'),
        ('DNS imps Térmicas Mesa',   'Rede imps Térmicas Mesa', 'termica'),
        ('DNS imps Térmicas Mesa.1', 'Rede ImpsTérmicas WIFI',  'termica'),
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

        for dns_col, net_col, tipo in COLUMN_TRIPLETS:
            raw_net = str(row.get(net_col, '')).strip()

            has_network = (
                raw_net
                and raw_net not in ('nan', 'NaN', 'DNS_NAO_ENCONTRADO')
                and '/' in raw_net
            )

            if has_network:
                network = raw_net
            else:
                dns_name = str(row.get(dns_col, '')).strip()
                if not dns_name or dns_name == 'nan':
                    continue
                resolved_ip = _resolve_dns(dns_name)
                if not resolved_ip:
                    continue
                network = _ip_to_cidr24(resolved_ip)

            # Valida CIDR
            try:
                ipaddress.ip_network(network, strict=False)
            except ValueError:
                log.warning(f'CIDR inválido ignorado: {network!r}')
                continue

            key = (network, cd)
            if key not in seen:
                seen.add(key)
                entries.append({'network': network, 'cd': cd, 'tipo': tipo})

    log.info(f'{len(entries)} entradas de rede carregadas.')
    return entries

# ---------------------------------------------------------------------------
# SNMP — implementação pura Python (fallback sem pysnmp)
# ---------------------------------------------------------------------------
def _snmp_get_raw(ip: str, oid: str) -> Optional[str]:
    """SNMP v1 GET via UDP puro — sem dependências externas."""

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

    # Monta pacote GET
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

    # Navega: Sequence > versão > comunidade > GetResponse PDU
    tag, inner, _ = _read_tlv(resp, 0)
    if tag != 0x30 or inner is None:
        return None
    p = 0
    for _ in range(2):          # pula versão e comunidade
        tag, _, p = _read_tlv(inner, p)
    tag, pdu_val, _ = _read_tlv(inner, p)
    if tag != 0xa2 or pdu_val is None:
        return None
    p = 0
    for _ in range(3):          # pula reqid, error-status, error-index
        tag, _, p = _read_tlv(pdu_val, p)
    tag, vbl_val, _ = _read_tlv(pdu_val, p)
    if tag != 0x30 or vbl_val is None:
        return None
    tag, vb_val, _ = _read_tlv(vbl_val, 0)
    if tag != 0x30 or vb_val is None:
        return None
    p = 0
    tag, _, p = _read_tlv(vb_val, p)   # pula OID
    if tag != 0x06:
        return None
    tag, v_val, _ = _read_tlv(vb_val, p)
    if not v_val:
        return None
    if tag == 0x04:                     # OctetString (serial)
        decoded = v_val.decode('latin-1', errors='ignore').strip().strip('.')
        return decoded if decoded and not decoded.startswith('\x00') else None
    if tag in (0x02, 0x41, 0x42, 0x46):  # Integer / Counter32 / Gauge32 / TimeTicks
        return str(int.from_bytes(v_val, 'big', signed=(tag == 0x02)))
    return None


def _snmp_get(ip: str, oid: str) -> Optional[str]:
    """Consulta OID via SNMP v1. Usa pysnmp se disponível, senão raw UDP."""
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
    # Fallback: implementação raw sem dependências
    return _snmp_get_raw(ip, oid)


def get_serial(ip: str) -> str:
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


def detect_manufacturer(ip: str, fila: str) -> Optional[str]:
    """Identifica o fabricante. Retorna None para dispositivos desconhecidos.

    Estratégia:
      1. Nome DNS reverso (fila)
      2. Header Server + body da porta 80
    """
    if fila and fila != 'N/A':
        brand = _match_manufacturer(fila)
        if brand:
            return brand

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
# DNS reverso (coluna "Fila")
# ---------------------------------------------------------------------------
def resolve_fila(ip: str) -> str:
    """Faz nslookup reverso do IP para obter o nome da fila/impressora.
    Timeout de 3 s para não bloquear o scan em IPs sem PTR record.
    """
    try:
        future = _dns_pool.submit(socket.gethostbyaddr, ip)
        return future.result(timeout=3.0)[0]
    except Exception:
        return 'N/A'

# ---------------------------------------------------------------------------
# Scan por rede
# ---------------------------------------------------------------------------
def scan_network(entry: dict) -> list[dict]:
    """Varre uma rede e retorna apenas impressoras de fabricantes conhecidos."""
    network = entry['network']
    cd      = entry['cd']
    tipo    = entry['tipo']
    found: list[dict] = []

    with _nmap_sem:
        try:
            log.info(f'[CD {cd}] Iniciando scan: {network} ({tipo})')
            nm = nmap.PortScanner()
            nm.scan(hosts=network, arguments=NMAP_ARGS)

            for host in nm.all_hosts():
                if nm[host].state() != 'up':
                    continue
                if not any(p in nm[host] for p in ('tcp', 'udp')):
                    continue

                fila         = resolve_fila(host)
                manufacturer = detect_manufacturer(host, fila)

                # Ignora dispositivos que não são impressoras conhecidas
                if manufacturer not in KNOWN_MANUFACTURERS:
                    log.debug(f'[CD {cd}] {host} ignorado — fabricante não identificado')
                    continue

                serial   = get_serial(host)
                contador = None
                if manufacturer in LASER_MANUFACTURERS and tipo == 'laser':
                    contador = get_page_count(host)

                printer = PrinterInfo(
                    ip=host,
                    fila=fila,
                    fabricante=manufacturer,
                    serial=serial,
                    contador=contador,
                    status='Online',
                    filial=cd,
                    tipo=tipo,
                ).to_dict()

                log.info(f'[CD {cd}] ✓ {host} ({manufacturer}) — {fila}')
                found.append(printer)

        except Exception as exc:
            log.error(f'Erro ao escanear {network}: {exc}')

    return found

# ---------------------------------------------------------------------------
# Orquestrador do scan completo
# ---------------------------------------------------------------------------
def run_full_scan() -> None:
    global _scan_cache, _scan_running
    _scan_running = True
    with _cache_lock:
        _scan_cache = []

    try:
        entries = load_network_entries()
        if not entries:
            log.warning('Nenhuma entrada de rede carregada. Verifique o CSV.')
            return

        log.info(f'Disparando scan para {len(entries)} redes...')

        def _worker(entry: dict) -> None:
            results = scan_network(entry)
            if results:
                with _cache_lock:
                    _scan_cache.extend(results)

        threads = [
            threading.Thread(target=_worker, args=(e,), daemon=True, name=f"scan-{e['cd']}-{e['tipo']}")
            for e in entries
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        log.info(f'Scan concluído — {len(_scan_cache)} impressoras encontradas.')

    except Exception as exc:
        log.error(f'Erro crítico no scan: {exc}')
    finally:
        _scan_running = False

# ---------------------------------------------------------------------------
# Rotas Flask
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def start_scan():
    if _scan_running:
        log.warning('Scan já em andamento — requisição ignorada.')
        return redirect(url_for('results'))
    threading.Thread(target=run_full_scan, daemon=True, name='scan-master').start()
    return redirect(url_for('results'))


@app.route('/api/results')
def api_results():
    with _cache_lock:
        snapshot = list(_scan_cache)
    return jsonify({
        'scan_running': _scan_running,
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
    # use_reloader=False é obrigatório: o reloader cria dois processos e
    # as threads de scan perdem acesso ao _scan_cache do processo principal.
    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)
import pandas as pd
import nmap
import threading
import urllib.request
import urllib.error
from flask import Flask, render_template, request, redirect, url_for, jsonify
import logging

# Configuração básica de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Cache dos resultados do último scan e flag de estado
scan_results_cache = []
scan_is_running = False
results_lock = threading.Lock()

def detect_manufacturer_http(ip, timeout=3):
    """Tenta identificar o fabricante pela resposta HTTP da porta 80."""
    try:
        req = urllib.request.Request(
            f'http://{ip}/',
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            server = resp.headers.get('Server', '')
            content = resp.read(4096).decode('utf-8', errors='ignore')
            combined = (server + ' ' + content).lower()
            if any(k in combined for k in ('hp ', 'hewlett', 'laserjet', 'hp-http')):
                return 'HP'
            if 'samsung' in combined:
                return 'Samsung'
            if 'zebra' in combined:
                return 'Zebra'
            if 'honeywell' in combined:
                return 'Honeywell'
    except Exception:
        pass
    return None


def get_printer_info(host, port_info):
    """Extrai informações relevantes da impressora a partir do resultado do nmap."""
    # .hostname() é o método correto do objeto PortScannerHostDict do python-nmap
    hostname = port_info.hostname() or 'N/A'

    # 1ª tentativa: identificar pelo hostname DNS reverso
    combined = hostname.lower()
    if any(k in combined for k in ('hp', 'laserjet', 'hewlett')):
        manufacturer = 'HP'
    elif 'samsung' in combined:
        manufacturer = 'Samsung'
    elif 'zebra' in combined:
        manufacturer = 'Zebra'
    elif 'honeywell' in combined:
        manufacturer = 'Honeywell'
    else:
        # 2ª tentativa: banner HTTP na porta 80
        manufacturer = detect_manufacturer_http(host) or 'Outros'

    return {
        'ip': host,
        'hostname': hostname,
        'manufacturer': manufacturer,
        'status': 'Ativo'
    }

def scan_network(network_range):
    """Executa o scan em uma faixa de rede e retorna as impressoras encontradas."""
    found_printers = []
    try:
        logging.info(f"Iniciando scan na rede: {network_range}")
        nm = nmap.PortScanner()
        # Scan em portas comuns de impressoras: HTTP, IPP, JetDirect
        # -R força resolução DNS reversa para todos os hosts (necessário para identificar fabricante pelo hostname)
        nm.scan(hosts=network_range, arguments='-p 80,443,631,9100 --open -T4 -R')
        
        for host in nm.all_hosts():
            # Considera um host como impressora se tiver alguma das portas abertas
            if nm[host].state() == 'up' and any(proto in nm[host] for proto in ['tcp', 'udp']):
                printer_info = get_printer_info(host, nm[host])
                found_printers.append(printer_info)
                logging.info(f"Impressora encontrada: {printer_info}")

    except Exception as e:
        logging.error(f"Erro ao escanear a rede {network_range}: {e}")
        
    return found_printers

def run_full_scan():
    """
    Lê o arquivo CSV com estrutura complexa, extrai todas as faixas de rede
    das colunas 'Rede Interna' e dispara o scan para todas elas.
    """
    global scan_results_cache, scan_is_running
    scan_is_running = True
    scan_results_cache = []
    printers_found = []
    try:
        logging.info("Iniciando leitura do arquivo redes.csv.")
        # Lê o CSV, pulando a primeira linha e tratando a segunda como cabeçalho.
        # Os nomes das colunas são definidos manualmente para evitar problemas com duplicatas.
        # skiprows=2 pula a linha inicial irrelevante E a linha de cabeçalho do CSV
        df = pd.read_csv('redes.csv', skiprows=2, header=None)
        # Pega apenas as colunas que precisamos (índices 3 e 8 = 'Rede Interna' de cada bloco)
        df = df.iloc[:, [3, 8]]
        df.columns = ['rede_interna_1', 'rede_interna_2']

        # Concatena as duas colunas de redes em uma só
        redes_series = pd.concat([df['rede_interna_1'], df['rede_interna_2']], ignore_index=True)

        # Limpa os dados: remove valores vazios e espaços extras
        redes_series = redes_series.dropna().str.strip()

        # Processa células que podem ter múltiplas redes separadas por espaço.
        # Normaliza o formato "10.0.0.0 /24" (espaço antes da barra) para "10.0.0.0/24"
        # antes de dividir, para não separar o IP da máscara.
        all_networks = []
        for item in redes_series:
            normalized = item.replace(' /', '/')
            sub_nets = [net.strip() for net in normalized.split() if '/' in net]
            all_networks.extend(sub_nets)

        # Remove duplicatas, ordena e valida que a máscara CIDR é numérica
        networks = sorted([
            n for n in set(all_networks)
            if n.split('/')[1].strip().isdigit()
        ])

        if not networks:
            logging.warning("Nenhuma faixa de rede válida foi encontrada no arquivo redes.csv.")
            scan_results_cache = []
            return

        logging.info(f"Redes encontradas para scan: {networks}")

        threads = []
        thread_results = []

        def thread_target(net):
            result = scan_network(net)
            with results_lock:
                thread_results.extend(result)
                # Publica imediatamente no cache global para o polling JS ver
                scan_results_cache.extend(result)

        for network in networks:
            if '/' in network:
                thread = threading.Thread(target=thread_target, args=(network,))
                threads.append(thread)
                thread.start()
            else:
                logging.warning(f"Formato de rede inválido ignorado: {network}. Use o formato CIDR (ex: 10.70.82.0/24).")

        for thread in threads:
            thread.join()

        scan_results_cache = thread_results
        logging.info(f"Scan completo. Total de impressoras encontradas: {len(scan_results_cache)}")

    except FileNotFoundError:
        logging.error("Arquivo 'redes.csv' não encontrado. Verifique se ele está no mesmo diretório do script.")
        scan_results_cache = []
    except Exception as e:
        logging.error(f"Um erro inesperado ocorreu durante o processamento do arquivo ou scan: {e}")
        scan_results_cache = []
    finally:
        scan_is_running = False


@app.route('/')
def index():
    """Página inicial que permite iniciar o scan."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    """Endpoint para iniciar o processo de scan em background."""
    if scan_is_running:
        logging.warning("Scan já em andamento. Ignorando nova solicitação.")
        return redirect(url_for('results'))
    logging.info("Recebida solicitação de scan.")
    scan_thread = threading.Thread(target=run_full_scan, daemon=True)
    scan_thread.start()
    # Redireciona para /results (GET), evitando 405 no auto-refresh
    return redirect(url_for('results'))


@app.route('/api/results')
def api_results():
    """Endpoint JSON para polling em tempo real pelo frontend."""
    return jsonify({
        'scan_running': scan_is_running,
        'total': len(scan_results_cache),
        'printers': scan_results_cache
    })


@app.route('/results')
def results():
    """Exibe os resultados do scan, separados por fabricante."""
    printers_hp_samsung = [p for p in scan_results_cache if p['manufacturer'] in ['HP', 'Samsung']]
    printers_zebra_other = [p for p in scan_results_cache if p['manufacturer'] in ['Zebra', 'Honeywell', 'Outros']]

    return render_template('results.html',
                           printers_hp_samsung=printers_hp_samsung,
                           printers_zebra_other=printers_zebra_other,
                           scan_running=scan_is_running)

if __name__ == '__main__':
    # use_reloader=False é obrigatório para que threads em background
    # compartilhem o mesmo espaço de memória (global scan_results_cache)
    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)

