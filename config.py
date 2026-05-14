"""Configuração centralizada — carrega variáveis de .env com python-dotenv.

Todas as constantes configuráveis do scan_printers.py são definidas aqui.
O arquivo .env (não versionado) contém os valores reais.
O arquivo .env.example (versionado) documenta as variáveis disponíveis.

Uso:
    from config import PROBE_PORT, SNMP_COMMUNITY, HTTP_TIMEOUT, ...
"""
from __future__ import annotations

import os
from pathlib import Path

# Carrega .env se existir (silencioso se não existir)
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / '.env', override=False)
except ImportError:
    pass  # python-dotenv não instalado — usa apenas variáveis de ambiente do SO

# ---------------------------------------------------------------------------
# Servidor
# ---------------------------------------------------------------------------
PROBE_PORT: int = int(os.getenv('PROBE_PORT', '5001'))

# ---------------------------------------------------------------------------
# SNMP
# ---------------------------------------------------------------------------
SNMP_COMMUNITY: str = os.getenv('SNMP_COMMUNITY', 'public')
SNMP_TIMEOUT: int   = int(os.getenv('SNMP_TIMEOUT', '2'))

# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
HTTP_TIMEOUT: int = int(os.getenv('HTTP_TIMEOUT', '3'))

# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------
MAX_CONCURRENT: int = int(os.getenv('MAX_CONCURRENT', '10'))

# ---------------------------------------------------------------------------
# Credenciais HP EWS (múltiplos usuários e senhas separados por vírgula)
# ---------------------------------------------------------------------------
_hp_users_raw:     str = os.getenv('HP_EWS_USERS',     'administrador,admin')
_hp_passwords_raw: str = os.getenv('HP_EWS_PASSWORDS', 'simpress1934@,12345678,')

HP_EWS_USERS:     list[str] = [u for u in _hp_users_raw.split(',')]
HP_EWS_PASSWORDS: list[str] = [p for p in _hp_passwords_raw.split(',')]

# Compat legado
HP_EWS_USER:     str = HP_EWS_USERS[0]
HP_EWS_PASSWORD: str = HP_EWS_PASSWORDS[0]

# ---------------------------------------------------------------------------
# Credenciais Samsung SyncThru
# ---------------------------------------------------------------------------
SAMSUNG_USER: str = os.getenv('SAMSUNG_USER', 'admin')
_samsung_pwd_raw: str = os.getenv('SAMSUNG_PASSWORDS', 'sec00000,1111,simpress1934@,12345678,3737,')
SAMSUNG_PASSWORDS: list[str] = [p for p in _samsung_pwd_raw.split(',')]

# ---------------------------------------------------------------------------
# Credenciais Zebra ZebraNet
# ---------------------------------------------------------------------------
ZEBRA_USER: str = os.getenv('ZEBRA_USER', 'admin')
_zebra_pwd_raw: str = os.getenv('ZEBRA_PASSWORDS', '1234,1934,3737,')
ZEBRA_PASSWORDS: list[str] = [p for p in _zebra_pwd_raw.split(',')]

# ---------------------------------------------------------------------------
# Autenticação LDAP / Active Directory
# ---------------------------------------------------------------------------
# DCs descobertos automaticamente via DNS SRV:
#   _ldap._tcp.dc._msdcs.<AD_DOMAIN>
# Defina apenas AD_DOMAIN para ativar. AD_SERVER não é necessário.
# Deixe AD_DOMAIN em branco para usar somente o admin.key local.
AD_DOMAIN:      str = os.getenv('AD_DOMAIN', '')           # ex: magazineluiza.intranet
AD_BASE_DN:     str = os.getenv('AD_BASE_DN', '')           # ex: DC=magazineluiza,DC=intranet
AD_ADMIN_GROUP: str = os.getenv('AD_ADMIN_GROUP', '')       # ex: CN=TI-Impressoras,OU=Grupos,DC=magazineluiza,DC=intranet
AD_USE_SSL:     bool = os.getenv('AD_USE_SSL', 'false').lower() in ('1', 'true', 'yes')
AD_TIMEOUT:     int  = int(os.getenv('AD_TIMEOUT', '5'))
