import sys
import os
import json
import base64
import binascii
import subprocess
import time
import threading
import traceback
import uuid
import html
import socket
import ctypes
import signal
import io
import urllib.request
import urllib.error
import queue
import shutil
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote, quote, urlencode
import qrcode

from PySide6.QtWidgets import *
from PySide6.QtCore import *
from PySide6.QtGui import QKeySequence, QShortcut, QPainter, QPen, QColor, QIcon, QPixmap, QCursor
import winreg as reg

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
XRAY_CORE_DIR = os.path.join(BASE_DIR, "xraycore")
DATA_DIR = os.path.join(BASE_DIR, "profilesx")
XRAY_PATH = os.path.join(XRAY_CORE_DIR, "xray.exe")
WINTUN_PATH = os.path.join(XRAY_CORE_DIR, "wintun.dll")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
PROFILE_PATH = os.path.join(DATA_DIR, "profiles.json")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
APP_ICON_PATH = os.path.join(BASE_DIR, "icon.ico")
APP_VERSION = "0.1.0"

os.makedirs(DATA_DIR, exist_ok=True)

PROXY_ADDR = "127.0.0.1"
PROXY_PORT = "10808"

xray_process = None
NO_WINDOW_FLAG = getattr(subprocess, "CREATE_NO_WINDOW", 0)
XRAY_LOCK = threading.RLock()



# ===============================
# PROFILE STORAGE
# ===============================

def load_profiles():
    if not os.path.exists(PROFILE_PATH):
        return []
    try:
        with open(PROFILE_PATH, "r", encoding="utf8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
    except Exception as e:
        print(f"[Profiles] Failed to load {PROFILE_PATH}: {e}", file=sys.stderr)
    return []

def save_profiles(data):
    with open(PROFILE_PATH, "w", encoding="utf8") as f:
        json.dump(data, f, indent=2)


def default_settings():
    return {
        "core": {
            "autostart_core": True,
            "restart_on_select": True,
        },
        "proxy": {
            "auto_set_system_proxy_on_connect": False,
            "set_proxy_on_app_launch": False,
        },
        "routing": {
            "mode": "bypass_ir_cn",  # proxy_all | bypass_ir_cn | direct_all
            "bypass_lan": True,
            "direct_domains": "",
            "proxy_domains": "",
            "direct_ips": "",
        },
        "dns": {
            "enabled": True,
            "servers": "https://1.1.1.1/dns-query\nhttps://dns.google/dns-query\nlocalhost",
            "query_strategy": "UseIP",
        },
        "advanced": {
            "allow_insecure_tls": True,
            "ping_max_time": 15,
            "speed_max_time": 20,
            "log_limit": 1200,
            "suppress_noisy_core_logs": True,
        },
        "tunnel": {
            "enabled": False,
            "name": "xray0",
            "mtu": 1500,
            "stack": "mixed",
            "strict_route": True,
        },
        "subscriptions": [],
    }


def merge_dict(base, override):
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge_dict(result[key], value)
        else:
            result[key] = value
    return result


def load_settings():
    defaults = default_settings()
    if not os.path.exists(SETTINGS_PATH):
        return defaults
    try:
        with open(SETTINGS_PATH, "r", encoding="utf8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return merge_dict(defaults, data)
    except Exception as e:
        print(f"[Settings] Failed to load {SETTINGS_PATH}: {e}", file=sys.stderr)
    return defaults


def save_settings(data):
    with open(SETTINGS_PATH, "w", encoding="utf8") as f:
        json.dump(data, f, indent=2)


def is_valid_uuid(value):
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, TypeError, AttributeError):
        return False


def validate_port(value):
    port = int(value)
    if port < 1 or port > 65535:
        raise ValueError("Invalid port range")
    return port


# ===============================
# PROXY CONTROL
# ===============================

def set_system_proxy():
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
    reg.SetValueEx(key, "ProxyEnable", 0, reg.REG_DWORD, 1)
    reg.SetValueEx(key, "ProxyServer", 0, reg.REG_SZ, f"{PROXY_ADDR}:{PROXY_PORT}")
    reg.CloseKey(key)

def clear_system_proxy():
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
    reg.SetValueEx(key, "ProxyEnable", 0, reg.REG_DWORD, 0)
    reg.CloseKey(key)


def get_system_proxy_status():
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_READ)
    try:
        enabled, _ = reg.QueryValueEx(key, "ProxyEnable")
        server, _ = reg.QueryValueEx(key, "ProxyServer")
    except FileNotFoundError:
        enabled = 0
        server = ""
    finally:
        reg.CloseKey(key)

    is_enabled = bool(enabled)
    expected = f"{PROXY_ADDR}:{PROXY_PORT}"
    is_expected = server.strip() == expected
    return is_enabled, server.strip(), is_expected


def is_running_as_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ===============================
# LINK PARSERS
# ===============================

def _query_value(q, key, default=""):
    return q.get(key, [default])[0]


def _safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return int(default)


def find_free_local_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _normalize_network(value):
    v = (value or "tcp").strip().lower()
    mapping = {
        "raw": "tcp",
        "h2": "http",
        "http2": "http",
        "gun": "grpc",
        "splithttp": "xhttp",
        "chttp": "xhttp",
    }
    return mapping.get(v, v)


def _normalize_security(value):
    v = (value or "none").strip().lower()
    if v in {"tls", "xtls", "reality"}:
        return v
    return "none"


def parse_vmess(link):
    raw = link.replace("vmess://", "", 1)
    padded = raw + ("=" * (-len(raw) % 4))
    decoded = base64.b64decode(padded).decode("utf-8")
    data = json.loads(decoded)

    network = _normalize_network(data.get("net", "tcp"))
    security = _normalize_security(data.get("security") or data.get("tls"))
    path = str(data.get("path", "/"))
    host = str(data.get("host", ""))
    service_name = str(data.get("serviceName", data.get("path", ""))) if network == "grpc" else ""

    return {
        "protocol": "vmess",
        "name": unquote(str(data.get("ps", "VMESS"))).strip() or "VMESS",
        "address": str(data.get("add", "")).strip(),
        "port": data.get("port"),
        "uuid": data.get("id"),
        "alter_id": int(data.get("aid", 0) or 0),
        "encryption": str(data.get("scy", "auto")).strip() or "auto",
        "network": network,
        "security": security,
        "path": path if path else "/",
        "host": host,
        "sni": str(data.get("sni", host)).strip(),
        "alpn": str(data.get("alpn", "")).strip(),
        "fp": str(data.get("fp", "")).strip(),
        "pbk": str(data.get("pbk", "")).strip(),
        "sid": str(data.get("sid", "")).strip(),
        "spx": str(data.get("spx", "")).strip(),
        "flow": str(data.get("flow", "")).strip(),
        "service_name": service_name,
        "authority": str(data.get("authority", "")).strip(),
        "header_type": str(data.get("type", "none")).strip() or "none",
        "kcp_seed": str(data.get("seed", "")).strip(),
        "quic_security": str(data.get("quicSecurity", "none")).strip() or "none",
        "quic_key": str(data.get("key", "")).strip(),
        "xhttp_mode": str(data.get("mode", "auto")).strip() or "auto",
        "xhttp_extra": str(data.get("extra", "")).strip(),
        # compatibility aliases
        "add": str(data.get("add", "")).strip(),
        "id": data.get("id"),
        "aid": int(data.get("aid", 0) or 0),
        "net": network,
        "tls": security,
    }


def parse_vless(link):
    u = urlparse(link)
    q = parse_qs(u.query)
    network = _normalize_network(_query_value(q, "type", "tcp"))
    security = _normalize_security(_query_value(q, "security", "none"))
    path = _query_value(q, "path", "/")
    host = _query_value(q, "host", "")
    return {
        "protocol": "vless",
        "name": unquote(u.fragment).strip() if u.fragment else "VLESS",
        "address": u.hostname,
        "port": u.port,
        "uuid": u.username,
        "encryption": _query_value(q, "encryption", "none"),
        "network": network,
        "security": security,
        "path": path if path else "/",
        "host": host,
        "sni": _query_value(q, "sni", host),
        "alpn": _query_value(q, "alpn", ""),
        "fp": _query_value(q, "fp", ""),
        "pbk": _query_value(q, "pbk", ""),
        "sid": _query_value(q, "sid", ""),
        "spx": _query_value(q, "spx", ""),
        "flow": _query_value(q, "flow", ""),
        "service_name": _query_value(q, "serviceName", ""),
        "authority": _query_value(q, "authority", ""),
        "header_type": _query_value(q, "headerType", "none"),
        "kcp_seed": _query_value(q, "seed", ""),
        "quic_security": _query_value(q, "quicSecurity", "none"),
        "quic_key": _query_value(q, "key", ""),
        "xhttp_mode": _query_value(q, "mode", "auto"),
        "xhttp_extra": _query_value(q, "extra", ""),
    }


def parse_trojan(link):
    u = urlparse(link)
    q = parse_qs(u.query)
    network = _normalize_network(_query_value(q, "type", "tcp"))
    security = _normalize_security(_query_value(q, "security", "tls"))
    path = _query_value(q, "path", "/")
    host = _query_value(q, "host", "")
    return {
        "protocol": "trojan",
        "name": unquote(u.fragment).strip() if u.fragment else "TROJAN",
        "address": u.hostname,
        "port": u.port,
        "password": u.username,
        "network": network,
        "security": security,
        "path": path if path else "/",
        "host": host,
        "sni": _query_value(q, "sni", host),
        "alpn": _query_value(q, "alpn", ""),
        "fp": _query_value(q, "fp", ""),
        "pbk": _query_value(q, "pbk", ""),
        "sid": _query_value(q, "sid", ""),
        "spx": _query_value(q, "spx", ""),
        "flow": _query_value(q, "flow", ""),
        "service_name": _query_value(q, "serviceName", ""),
        "authority": _query_value(q, "authority", ""),
        "header_type": _query_value(q, "headerType", "none"),
        "kcp_seed": _query_value(q, "seed", ""),
        "quic_security": _query_value(q, "quicSecurity", "none"),
        "quic_key": _query_value(q, "key", ""),
        "xhttp_mode": _query_value(q, "mode", "auto"),
        "xhttp_extra": _query_value(q, "extra", ""),
    }


def parse_shadowsocks(link):
    raw = link.replace("ss://", "", 1)
    name = "SHADOWSOCKS"
    if "#" in raw:
        raw, frag = raw.split("#", 1)
        name = unquote(frag).strip() or name
    if "?" in raw:
        raw = raw.split("?", 1)[0]

    method = ""
    password = ""
    address = ""
    port = None

    # Form 1: ss://base64(method:password@host:port)
    try:
        decoded = base64.urlsafe_b64decode(raw + ("=" * (-len(raw) % 4))).decode("utf-8", errors="ignore")
        if "@" in decoded:
            creds, hostport = decoded.rsplit("@", 1)
            if ":" in creds:
                method, password = creds.split(":", 1)
            if ":" in hostport:
                address, port_text = hostport.rsplit(":", 1)
                port = _safe_int(port_text, 0)
    except Exception:
        pass

    # Form 2: ss://base64(method:password)@host:port
    if not address:
        if "@" not in raw:
            raise ValueError("Invalid shadowsocks link format")
        enc_creds, hostport = raw.rsplit("@", 1)
        decoded_creds = base64.urlsafe_b64decode(enc_creds + ("=" * (-len(enc_creds) % 4))).decode("utf-8", errors="ignore")
        if ":" in decoded_creds:
            method, password = decoded_creds.split(":", 1)
        if ":" in hostport:
            address, port_text = hostport.rsplit(":", 1)
            port = _safe_int(port_text, 0)

    return {
        "protocol": "shadowsocks",
        "name": name,
        "address": address.strip(),
        "port": port,
        "method": method.strip(),
        "password": password,
    }


def parse_hysteria2(link):
    scheme = "hysteria2://" if link.startswith("hysteria2://") else "hy2://"
    u = urlparse(link.replace("hy2://", "hysteria2://", 1) if link.startswith("hy2://") else link)
    q = parse_qs(u.query)
    up_mbps = _safe_int(_query_value(q, "upmbps", _query_value(q, "up", "0")), 0)
    down_mbps = _safe_int(_query_value(q, "downmbps", _query_value(q, "down", "0")), 0)
    return {
        "protocol": "hysteria2",
        "name": unquote(u.fragment).strip() if u.fragment else "HYSTERIA2",
        "address": u.hostname,
        "port": u.port,
        "password": u.username or _query_value(q, "password", ""),
        "sni": _query_value(q, "sni", ""),
        "alpn": _query_value(q, "alpn", ""),
        "fp": _query_value(q, "fp", ""),
        "allow_insecure": _query_value(q, "insecure", "0") in {"1", "true", "True"},
        "up_mbps": up_mbps,
        "down_mbps": down_mbps,
        "obfs": _query_value(q, "obfs", ""),
        "obfs_password": _query_value(q, "obfs-password", _query_value(q, "obfs_password", "")),
        "_raw_scheme": scheme,
    }


def parse_tuic(link):
    u = urlparse(link)
    q = parse_qs(u.query)
    return {
        "protocol": "tuic",
        "name": unquote(u.fragment).strip() if u.fragment else "TUIC",
        "address": u.hostname,
        "port": u.port,
        "uuid": u.username,
        "password": u.password or _query_value(q, "password", ""),
        "sni": _query_value(q, "sni", ""),
        "alpn": _query_value(q, "alpn", ""),
        "fp": _query_value(q, "fp", ""),
        "congestion_control": _query_value(q, "congestion_control", _query_value(q, "congestion", "bbr")),
        "udp_relay_mode": _query_value(q, "udp_relay_mode", "native"),
        "zero_rtt_handshake": _query_value(q, "zero_rtt_handshake", "0") in {"1", "true", "True"},
    }


def parse_socks(link):
    u = urlparse(link)
    q = parse_qs(u.query)
    return {
        "protocol": "socks",
        "name": unquote(u.fragment).strip() if u.fragment else "SOCKS",
        "address": u.hostname,
        "port": u.port,
        "username": unquote(u.username).strip() if u.username else "",
        "password": unquote(u.password) if u.password else "",
        "version": _safe_int(_query_value(q, "version", "5"), 5),
    }


def parse_http_outbound(link):
    u = urlparse(link)
    q = parse_qs(u.query)
    marker = _query_value(q, "xray", "") == "1" or _query_value(q, "outbound", "").lower() == "http"
    if not marker:
        raise ValueError("HTTP profile link requires xray=1 or outbound=http marker")
    security = "tls" if u.scheme.lower() == "https" else "none"
    host = u.hostname or ""
    return {
        "protocol": "http",
        "name": unquote(u.fragment).strip() if u.fragment else "HTTP",
        "address": host,
        "port": u.port,
        "username": unquote(u.username).strip() if u.username else "",
        "password": unquote(u.password) if u.password else "",
        "network": "tcp",
        "security": _normalize_security(_query_value(q, "security", security)),
        "sni": _query_value(q, "sni", host),
        "alpn": _query_value(q, "alpn", ""),
        "fp": _query_value(q, "fp", ""),
    }


def parse_wireguard(link):
    u = urlparse(link)
    q = parse_qs(u.query)
    local_address = _query_value(q, "address", _query_value(q, "local", "")).strip()
    if not local_address:
        local_address = "172.16.0.2/32"
    allowed = _query_value(q, "allowed", "0.0.0.0/0,::/0")
    allowed_ips = [x.strip() for x in allowed.split(",") if x.strip()]
    reserved_raw = _query_value(q, "reserved", "").strip()
    reserved = None
    if reserved_raw:
        parts = [p.strip() for p in reserved_raw.split(",")]
        if len(parts) == 3 and all(x.isdigit() for x in parts):
            reserved = [int(parts[0]), int(parts[1]), int(parts[2])]
    return {
        "protocol": "wireguard",
        "name": unquote(u.fragment).strip() if u.fragment else "WIREGUARD",
        "address": u.hostname,
        "port": u.port,
        "secret_key": _query_value(q, "secretKey", _query_value(q, "privateKey", "")),
        "public_key": _query_value(q, "publicKey", ""),
        "pre_shared_key": _query_value(q, "preSharedKey", _query_value(q, "presharedKey", "")),
        "local_address": local_address,
        "allowed_ips": allowed_ips,
        "mtu": _safe_int(_query_value(q, "mtu", "0"), 0),
        "keep_alive": _safe_int(_query_value(q, "keepAlive", "0"), 0),
        "reserved": reserved,
    }


def parse_shadowtls(link):
    u = urlparse(link)
    q = parse_qs(u.query)
    return {
        "protocol": "shadowtls",
        "name": unquote(u.fragment).strip() if u.fragment else "SHADOWTLS",
        "address": u.hostname,
        "port": u.port,
        "password": u.username or _query_value(q, "password", ""),
        "version": _safe_int(_query_value(q, "version", "3"), 3),
        "sni": _query_value(q, "sni", ""),
        "alpn": _query_value(q, "alpn", ""),
        "fp": _query_value(q, "fp", ""),
    }


def parse_internal_outbound(link):
    u = urlparse(link)
    scheme = u.scheme.lower()
    mapping = {
        "freedom": "freedom",
        "direct": "freedom",
        "blackhole": "blackhole",
        "block": "blackhole",
        "dns": "dns",
    }
    proto = mapping.get(scheme)
    if not proto:
        raise ValueError("Unsupported internal outbound scheme")
    default_name = proto.upper()
    return {
        "protocol": proto,
        "name": unquote(u.fragment).strip() if u.fragment else default_name,
    }


def is_profile_link_candidate(link):
    item = str(link or "").strip().lower()
    if item.startswith(("vmess://", "vless://", "trojan://", "ss://", "hy2://", "hysteria2://", "tuic://", "socks://", "socks5://", "wg://", "wireguard://", "shadowtls://", "freedom://", "direct://", "blackhole://", "block://", "dns://")):
        return True
    if item.startswith(("http://", "https://")) and ("xray=1" in item or "outbound=http" in item):
        return True
    return False


def parse_any_link(link):
    item = str(link or "").strip()
    if not item:
        raise ValueError("Unsupported protocol")

    parsed = urlparse(item)
    scheme = parsed.scheme.lower()

    if "://" in item:
        rest = item.split("://", 1)[1]
        normalized = f"{scheme}://{rest}"
    else:
        normalized = item

    if scheme == "vmess":
        return parse_vmess(normalized)
    if scheme == "vless":
        return parse_vless(normalized)
    if scheme == "trojan":
        return parse_trojan(normalized)
    if scheme == "ss":
        return parse_shadowsocks(normalized)
    if scheme in {"hy2", "hysteria2"}:
        return parse_hysteria2(normalized)
    if scheme == "tuic":
        return parse_tuic(normalized)
    if scheme in {"socks", "socks5"}:
        return parse_socks(normalized)
    if scheme in {"wg", "wireguard"}:
        return parse_wireguard(normalized)
    if scheme == "shadowtls":
        return parse_shadowtls(normalized)
    if scheme in {"freedom", "direct", "blackhole", "block", "dns"}:
        return parse_internal_outbound(normalized)
    if scheme in {"http", "https"}:
        return parse_http_outbound(normalized)
    raise ValueError("Unsupported protocol")


def decode_subscription_payload(payload):
    text = (payload or "").strip()
    if not text:
        return []

    def extract_links(raw_text):
        links = []
        for line in raw_text.replace("\r", "\n").split("\n"):
            item = line.strip()
            if is_profile_link_candidate(item):
                links.append(item)
        return links

    direct_links = extract_links(text)
    if direct_links:
        return direct_links

    compact = "".join(text.split())
    padded = compact + ("=" * (-len(compact) % 4))
    decode_attempts = [
        ("utf-8", base64.b64decode),
        ("utf-8", base64.urlsafe_b64decode),
    ]
    for encoding, decoder in decode_attempts:
        try:
            decoded = decoder(padded.encode("ascii")).decode(encoding, errors="ignore")
            links = extract_links(decoded)
            if links:
                return links
        except Exception:
            continue
    return []


def fetch_subscription_links(url, timeout=12):
    parsed = urlparse(str(url or "").strip())
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Subscription URL must start with http:// or https://")

    req = urllib.request.Request(
        parsed.geturl(),
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) XrayClient/1.0"
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=float(timeout)) as resp:
            status = getattr(resp, "status", 200)
            if int(status) < 200 or int(status) >= 300:
                raise ValueError(f"Subscription HTTP status: {status}")
            # Prevent unexpectedly large payloads from stalling the app.
            max_bytes = 4 * 1024 * 1024
            payload = resp.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise ValueError("Subscription payload is too large (>4MB)")
            body = payload.decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        raise ValueError(f"Subscription HTTP error: {e.code}") from e
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        raise ValueError(f"Subscription network error: {reason}") from e
    except socket.timeout as e:
        raise ValueError("Subscription request timed out") from e

    return decode_subscription_payload(body)


def parse_profile_link(link):
    link = link.strip()
    if not link:
        raise ValueError("Empty link")

    try:
        d = parse_any_link(link)
    except (json.JSONDecodeError, binascii.Error, UnicodeDecodeError, ValueError) as e:
        raise ValueError(f"Invalid link payload: {e}") from e

    proto = d.get("protocol")
    if proto not in {"freedom", "blackhole", "dns"}:
        if not d.get("address"):
            raise ValueError("Server address is missing")
        validate_port(d.get("port"))

    if proto in {"vless", "vmess", "tuic"} and not is_valid_uuid(d.get("uuid")):
        raise ValueError(f"{proto.upper()} UUID is invalid")
    if proto == "trojan" and not str(d.get("password", "")).strip():
        raise ValueError("TROJAN password is missing")
    if proto == "shadowsocks":
        if not str(d.get("method", "")).strip():
            raise ValueError("SHADOWSOCKS method is missing")
        if not str(d.get("password", "")).strip():
            raise ValueError("SHADOWSOCKS password is missing")
    if proto == "hysteria2" and not str(d.get("password", "")).strip():
        raise ValueError("HYSTERIA2 password is missing")
    if proto == "tuic" and not str(d.get("password", "")).strip():
        raise ValueError("TUIC password is missing")
    if proto == "socks" and d.get("version") not in {4, 5}:
        raise ValueError("SOCKS version must be 4 or 5")
    if proto == "wireguard":
        if not str(d.get("secret_key", "")).strip():
            raise ValueError("WIREGUARD secretKey/privateKey is missing")
        if not str(d.get("public_key", "")).strip():
            raise ValueError("WIREGUARD publicKey is missing")
    if proto == "shadowtls":
        if not str(d.get("password", "")).strip():
            raise ValueError("SHADOWTLS password is missing")
        if not str(d.get("sni", "")).strip():
            raise ValueError("SHADOWTLS sni is missing")

    name = str(d.get("name", proto.upper())).strip() or proto.upper()
    return {"name": name, "link": link}


def _bool_from_text(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _clean_str(value):
    return str(value or "").strip()


def _encode_fragment(name, default_name):
    final_name = _clean_str(name) or default_name
    return quote(final_name, safe="")


def _build_query_pairs(d, keys):
    pairs = []
    for key in keys:
        val = d.get(key)
        if val is None:
            continue
        text = _clean_str(val)
        if text == "":
            continue
        pairs.append((key, text))
    return pairs


def build_profile_link_from_dict(d):
    proto = _clean_str(d.get("protocol")).lower()
    name = _clean_str(d.get("name"))
    address = _clean_str(d.get("address"))
    port = _safe_int(d.get("port"), 0)

    if proto in {"vless", "trojan", "hysteria2", "tuic", "socks", "http", "wireguard", "shadowtls", "shadowsocks"}:
        if not address:
            raise ValueError("Server address is missing")
        validate_port(port)

    if proto == "vmess":
        payload = {
            "v": "2",
            "ps": name or "VMESS",
            "add": address,
            "port": str(port),
            "id": _clean_str(d.get("uuid")),
            "aid": str(_safe_int(d.get("alter_id"), 0)),
            "scy": _clean_str(d.get("encryption")) or "auto",
            "net": _normalize_network(d.get("network") or "tcp"),
            "type": _clean_str(d.get("header_type")) or "none",
            "host": _clean_str(d.get("host")),
            "path": _clean_str(d.get("path")) or "/",
            "tls": _normalize_security(d.get("security") or "none"),
            "sni": _clean_str(d.get("sni")),
            "alpn": _clean_str(d.get("alpn")),
            "fp": _clean_str(d.get("fp")),
            "pbk": _clean_str(d.get("pbk")),
            "sid": _clean_str(d.get("sid")),
            "spx": _clean_str(d.get("spx")),
            "flow": _clean_str(d.get("flow")),
            "serviceName": _clean_str(d.get("service_name")),
            "authority": _clean_str(d.get("authority")),
            "seed": _clean_str(d.get("kcp_seed")),
            "quicSecurity": _clean_str(d.get("quic_security")) or "none",
            "key": _clean_str(d.get("quic_key")),
            "mode": _clean_str(d.get("xhttp_mode")) or "auto",
            "extra": _clean_str(d.get("xhttp_extra")),
        }
        encoded = base64.b64encode(json.dumps(payload, ensure_ascii=False).encode("utf-8")).decode("utf-8")
        return f"vmess://{encoded}"

    if proto == "vless":
        uid = _clean_str(d.get("uuid"))
        if not is_valid_uuid(uid):
            raise ValueError("VLESS UUID is invalid")
        query_map = {
            "encryption": _clean_str(d.get("encryption")) or "none",
            "flow": _clean_str(d.get("flow")),
            "security": _normalize_security(d.get("security") or "none"),
            "type": _normalize_network(d.get("network") or "tcp"),
            "host": _clean_str(d.get("host")),
            "path": _clean_str(d.get("path")) or "/",
            "sni": _clean_str(d.get("sni")),
            "alpn": _clean_str(d.get("alpn")),
            "fp": _clean_str(d.get("fp")),
            "pbk": _clean_str(d.get("pbk")),
            "sid": _clean_str(d.get("sid")),
            "spx": _clean_str(d.get("spx")),
            "serviceName": _clean_str(d.get("service_name")),
            "authority": _clean_str(d.get("authority")),
            "headerType": _clean_str(d.get("header_type")) or "none",
            "seed": _clean_str(d.get("kcp_seed")),
            "quicSecurity": _clean_str(d.get("quic_security")) or "none",
            "key": _clean_str(d.get("quic_key")),
            "mode": _clean_str(d.get("xhttp_mode")) or "auto",
            "extra": _clean_str(d.get("xhttp_extra")),
        }
        q = urlencode(query_map)
        return f"vless://{uid}@{address}:{port}?{q}#{_encode_fragment(name, 'VLESS')}"

    if proto == "trojan":
        password = _clean_str(d.get("password"))
        if not password:
            raise ValueError("TROJAN password is missing")
        query_map = {
            "security": _normalize_security(d.get("security") or "tls"),
            "type": _normalize_network(d.get("network") or "tcp"),
            "host": _clean_str(d.get("host")),
            "path": _clean_str(d.get("path")) or "/",
            "sni": _clean_str(d.get("sni")),
            "alpn": _clean_str(d.get("alpn")),
            "fp": _clean_str(d.get("fp")),
            "pbk": _clean_str(d.get("pbk")),
            "sid": _clean_str(d.get("sid")),
            "spx": _clean_str(d.get("spx")),
            "flow": _clean_str(d.get("flow")),
            "serviceName": _clean_str(d.get("service_name")),
            "authority": _clean_str(d.get("authority")),
            "headerType": _clean_str(d.get("header_type")) or "none",
            "seed": _clean_str(d.get("kcp_seed")),
            "quicSecurity": _clean_str(d.get("quic_security")) or "none",
            "key": _clean_str(d.get("quic_key")),
            "mode": _clean_str(d.get("xhttp_mode")) or "auto",
            "extra": _clean_str(d.get("xhttp_extra")),
        }
        q = urlencode({k: v for k, v in query_map.items() if _clean_str(v) != ""})
        return f"trojan://{quote(password, safe='')}@{address}:{port}?{q}#{_encode_fragment(name, 'TROJAN')}"

    if proto == "shadowsocks":
        method = _clean_str(d.get("method"))
        password = _clean_str(d.get("password"))
        if not method or not password:
            raise ValueError("Shadowsocks method/password is required")
        creds = f"{method}:{password}@{address}:{port}"
        encoded = base64.urlsafe_b64encode(creds.encode("utf-8")).decode("utf-8").rstrip("=")
        return f"ss://{encoded}#{_encode_fragment(name, 'SHADOWSOCKS')}"

    if proto == "hysteria2":
        password = _clean_str(d.get("password"))
        if not password:
            raise ValueError("Hysteria2 password is missing")
        query_map = {
            "sni": _clean_str(d.get("sni")),
            "alpn": _clean_str(d.get("alpn")),
            "fp": _clean_str(d.get("fp")),
            "insecure": "1" if _bool_from_text(d.get("allow_insecure")) else "0",
            "upmbps": str(_safe_int(d.get("up_mbps"), 0)),
            "downmbps": str(_safe_int(d.get("down_mbps"), 0)),
            "obfs": _clean_str(d.get("obfs")),
            "obfs-password": _clean_str(d.get("obfs_password")),
        }
        q = urlencode({k: v for k, v in query_map.items() if _clean_str(v) != ""})
        return f"hy2://{quote(password, safe='')}@{address}:{port}?{q}#{_encode_fragment(name, 'HYSTERIA2')}"

    if proto == "tuic":
        uid = _clean_str(d.get("uuid"))
        if not is_valid_uuid(uid):
            raise ValueError("TUIC UUID is invalid")
        password = _clean_str(d.get("password"))
        query_map = {
            "password": password,
            "sni": _clean_str(d.get("sni")),
            "alpn": _clean_str(d.get("alpn")),
            "fp": _clean_str(d.get("fp")),
            "congestion_control": _clean_str(d.get("congestion_control")) or "bbr",
            "udp_relay_mode": _clean_str(d.get("udp_relay_mode")) or "native",
            "zero_rtt_handshake": "1" if _bool_from_text(d.get("zero_rtt_handshake")) else "0",
        }
        q = urlencode({k: v for k, v in query_map.items() if _clean_str(v) != ""})
        return f"tuic://{uid}@{address}:{port}?{q}#{_encode_fragment(name, 'TUIC')}"

    if proto == "socks":
        username = _clean_str(d.get("username"))
        password = _clean_str(d.get("password"))
        auth = ""
        if username:
            auth = quote(username, safe="")
            if password:
                auth += f":{quote(password, safe='')}"
            auth += "@"
        query_map = {"version": str(_safe_int(d.get("version"), 5))}
        q = urlencode(query_map)
        return f"socks://{auth}{address}:{port}?{q}#{_encode_fragment(name, 'SOCKS')}"

    if proto == "http":
        username = _clean_str(d.get("username"))
        password = _clean_str(d.get("password"))
        auth = ""
        if username:
            auth = quote(username, safe="")
            if password:
                auth += f":{quote(password, safe='')}"
            auth += "@"
        security = _normalize_security(d.get("security") or "none")
        scheme = "https" if security == "tls" else "http"
        query_map = {
            "xray": "1",
            "security": security,
            "sni": _clean_str(d.get("sni")),
            "alpn": _clean_str(d.get("alpn")),
            "fp": _clean_str(d.get("fp")),
        }
        q = urlencode({k: v for k, v in query_map.items() if _clean_str(v) != ""})
        return f"{scheme}://{auth}{address}:{port}?{q}#{_encode_fragment(name, 'HTTP')}"

    if proto == "wireguard":
        allowed = _clean_str(d.get("allowed_ips")) or "0.0.0.0/0,::/0"
        query_map = {
            "secretKey": _clean_str(d.get("secret_key")),
            "publicKey": _clean_str(d.get("public_key")),
            "preSharedKey": _clean_str(d.get("pre_shared_key")),
            "address": _clean_str(d.get("local_address")) or "172.16.0.2/32",
            "allowed": allowed,
            "mtu": str(_safe_int(d.get("mtu"), 0)),
            "keepAlive": str(_safe_int(d.get("keep_alive"), 0)),
            "reserved": _clean_str(d.get("reserved")),
        }
        q = urlencode({k: v for k, v in query_map.items() if _clean_str(v) != "" and v != "0"})
        return f"wireguard://{address}:{port}?{q}#{_encode_fragment(name, 'WIREGUARD')}"

    if proto == "shadowtls":
        password = _clean_str(d.get("password"))
        if not password:
            raise ValueError("ShadowTLS password is missing")
        query_map = {
            "version": str(_safe_int(d.get("version"), 3)),
            "sni": _clean_str(d.get("sni")),
            "alpn": _clean_str(d.get("alpn")),
            "fp": _clean_str(d.get("fp")),
        }
        q = urlencode({k: v for k, v in query_map.items() if _clean_str(v) != ""})
        return f"shadowtls://{quote(password, safe='')}@{address}:{port}?{q}#{_encode_fragment(name, 'SHADOWTLS')}"

    if proto in {"freedom", "blackhole", "dns"}:
        scheme = "direct" if proto == "freedom" else ("block" if proto == "blackhole" else "dns")
        return f"{scheme}://#{_encode_fragment(name, proto.upper())}"

    raise ValueError(f"Unsupported protocol for link build: {proto}")


# ===============================
# STREAM BUILDER
# ===============================

def build_stream(d, allow_insecure_tls=True):
    network = _normalize_network(d.get("network", "tcp"))
    security = _normalize_security(d.get("security", "none"))
    host = d.get("host", "")
    path = d.get("path", "/") or "/"
    service_name = d.get("service_name", "")
    authority = d.get("authority", "")
    header_type = d.get("header_type", "none") or "none"

    stream = {"network": network, "security": security}

    if network == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host}}
    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": service_name or path.lstrip("/"),
            "authority": authority,
            "multiMode": str(d.get("xhttp_mode", "")).lower() == "multi",
        }
    elif network == "kcp":
        stream["kcpSettings"] = {
            "header": {"type": header_type},
            "seed": d.get("kcp_seed", ""),
        }
    elif network == "quic":
        stream["quicSettings"] = {
            "security": d.get("quic_security", "none") or "none",
            "key": d.get("quic_key", ""),
            "header": {"type": header_type},
        }
    elif network == "http":
        stream["httpSettings"] = {
            "host": [h.strip() for h in host.split(",") if h.strip()] if host else [],
            "path": path,
        }
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path, "host": host}
    elif network == "xhttp":
        xhttp_settings = {
            "path": path,
            "host": host,
            "mode": d.get("xhttp_mode", "auto") or "auto",
        }
        raw_extra = str(d.get("xhttp_extra", "")).strip()
        if raw_extra:
            try:
                parsed_extra = json.loads(raw_extra)
                if isinstance(parsed_extra, dict):
                    xhttp_settings.update(parsed_extra)
            except Exception:
                pass
        stream["xhttpSettings"] = xhttp_settings
    elif network == "tcp" and header_type != "none":
        stream["tcpSettings"] = {"header": {"type": header_type}}

    alpn_list = [x.strip() for x in str(d.get("alpn", "")).split(",") if x.strip()]
    fingerprint = d.get("fp", "")
    server_name = d.get("sni", host)

    if security == "tls":
        tls = {"serverName": server_name, "allowInsecure": bool(allow_insecure_tls)}
        if alpn_list:
            tls["alpn"] = alpn_list
        if fingerprint:
            tls["fingerprint"] = fingerprint
        stream["tlsSettings"] = tls
    elif security == "xtls":
        xtls = {"serverName": server_name, "allowInsecure": bool(allow_insecure_tls)}
        if alpn_list:
            xtls["alpn"] = alpn_list
        if fingerprint:
            xtls["fingerprint"] = fingerprint
        stream["xtlsSettings"] = xtls
    elif security == "reality":
        stream["realitySettings"] = {
            "show": False,
            "serverName": server_name,
            "fingerprint": fingerprint or "chrome",
            "publicKey": d.get("pbk", ""),
            "shortId": d.get("sid", ""),
            "spiderX": d.get("spx", ""),
        }

    return stream


# ===============================
# CONFIG BUILDERS
# ===============================

def build_vless_config(d, inbound_port=10808, allow_insecure_tls=True):
    user = {
        "id": d["uuid"],
        "encryption": d.get("encryption", "none") or "none",
    }
    if d.get("flow"):
        user["flow"] = d["flow"]

    return {
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": int(inbound_port),
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [{
            "protocol": "vless",
            "tag": "proxy",
            "settings": {
                "vnext": [{
                    "address": d["address"],
                    "port": int(d["port"]),
                    "users": [user]
                }]
            },
            "streamSettings": build_stream(d, allow_insecure_tls=allow_insecure_tls)
        }]
    }

def build_vmess_config(d, inbound_port=10808, allow_insecure_tls=True):
    vmess_type = d.get("network", d.get("net", "tcp"))
    vmess_security = _normalize_security(d.get("security", d.get("tls", "none")))
    vmess_stream_input = {
        "type": vmess_type,
        "security": vmess_security,
        "network": vmess_type,
        "path": d.get("path", "/"),
        "host": d.get("host", ""),
        "sni": d.get("sni", d.get("host", "")),
        "alpn": d.get("alpn", ""),
        "fp": d.get("fp", ""),
        "pbk": d.get("pbk", ""),
        "sid": d.get("sid", ""),
        "spx": d.get("spx", ""),
        "service_name": d.get("service_name", ""),
        "authority": d.get("authority", ""),
        "header_type": d.get("header_type", "none"),
        "kcp_seed": d.get("kcp_seed", ""),
        "quic_security": d.get("quic_security", "none"),
        "quic_key": d.get("quic_key", ""),
        "xhttp_mode": d.get("xhttp_mode", "auto"),
    }

    return {
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": int(inbound_port),
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [{
            "protocol": "vmess",
            "tag": "proxy",
            "settings": {
                "vnext": [{
                    "address": d.get("address", d.get("add", "")),
                    "port": int(d["port"]),
                    "users": [{
                        "id": d.get("uuid", d.get("id")),
                        "alterId": int(d.get("alter_id", d.get("aid", 0))),
                        "security": d.get("encryption", "auto") or "auto"
                    }]
                }]
            },
            "streamSettings": build_stream(vmess_stream_input, allow_insecure_tls=allow_insecure_tls)
        }]
    }


def build_trojan_config(d, inbound_port=10808, allow_insecure_tls=True):
    server = {
        "address": d["address"],
        "port": int(d["port"]),
        "password": d["password"],
    }
    if d.get("flow"):
        server["flow"] = d["flow"]

    return {
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": int(inbound_port),
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [{
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {"servers": [server]},
            "streamSettings": build_stream(d, allow_insecure_tls=allow_insecure_tls)
        }]
    }


def build_shadowsocks_config(d, inbound_port=10808):
    return {
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": int(inbound_port),
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [{
            "protocol": "shadowsocks",
            "tag": "proxy",
            "settings": {
                "servers": [{
                    "address": d["address"],
                    "port": int(d["port"]),
                    "method": d["method"],
                    "password": d["password"],
                }]
            }
        }]
    }


def build_hysteria2_config(d, inbound_port=10808, allow_insecure_tls=True):
    server = {
        "address": d["address"],
        "port": int(d["port"]),
        "password": d["password"],
    }
    if d.get("up_mbps", 0) > 0:
        server["upMbps"] = int(d["up_mbps"])
    if d.get("down_mbps", 0) > 0:
        server["downMbps"] = int(d["down_mbps"])

    outbound = {
        "protocol": "hysteria2",
        "tag": "proxy",
        "settings": {"servers": [server]},
    }

    stream_input = {
        "network": "udp",
        "security": "tls",
        "sni": d.get("sni", ""),
        "alpn": d.get("alpn", ""),
        "fp": d.get("fp", ""),
    }
    outbound["streamSettings"] = build_stream(stream_input, allow_insecure_tls=allow_insecure_tls or d.get("allow_insecure", False))

    return {
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": int(inbound_port),
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [outbound]
    }


def build_tuic_config(d, inbound_port=10808, allow_insecure_tls=True):
    server = {
        "address": d["address"],
        "port": int(d["port"]),
        "uuid": d["uuid"],
        "password": d["password"],
    }
    cc = str(d.get("congestion_control", "")).strip()
    if cc:
        server["congestionControl"] = cc
    urm = str(d.get("udp_relay_mode", "")).strip()
    if urm:
        server["udpRelayMode"] = urm
    if d.get("zero_rtt_handshake"):
        server["zeroRTTHandshake"] = True

    outbound = {
        "protocol": "tuic",
        "tag": "proxy",
        "settings": {"servers": [server]},
    }

    stream_input = {
        "network": "udp",
        "security": "tls",
        "sni": d.get("sni", ""),
        "alpn": d.get("alpn", ""),
        "fp": d.get("fp", ""),
    }
    outbound["streamSettings"] = build_stream(stream_input, allow_insecure_tls=allow_insecure_tls)

    return {
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": int(inbound_port),
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [outbound]
    }


def build_socks_config(d, inbound_port=10808):
    server = {
        "address": d["address"],
        "port": int(d["port"]),
    }
    user = str(d.get("username", "")).strip()
    password = str(d.get("password", ""))
    if user:
        server["users"] = [{"user": user, "pass": password}]
    return {
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": int(inbound_port),
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [{
            "protocol": "socks",
            "tag": "proxy",
            "settings": {
                "servers": [server]
            }
        }]
    }


def build_http_config(d, inbound_port=10808, allow_insecure_tls=True):
    server = {
        "address": d["address"],
        "port": int(d["port"]),
    }
    user = str(d.get("username", "")).strip()
    password = str(d.get("password", ""))
    if user:
        server["users"] = [{"user": user, "pass": password}]

    outbound = {
        "protocol": "http",
        "tag": "proxy",
        "settings": {
            "servers": [server]
        }
    }
    if _normalize_security(d.get("security", "none")) in {"tls", "xtls", "reality"}:
        outbound["streamSettings"] = build_stream(
            {
                "network": "tcp",
                "security": d.get("security", "tls"),
                "host": d.get("address", ""),
                "sni": d.get("sni", d.get("address", "")),
                "alpn": d.get("alpn", ""),
                "fp": d.get("fp", ""),
            },
            allow_insecure_tls=allow_insecure_tls
        )
    return {
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": int(inbound_port),
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [outbound]
    }


def build_wireguard_config(d, inbound_port=10808):
    peer = {
        "publicKey": d["public_key"],
        "endpoint": f"{d['address']}:{int(d['port'])}",
        "allowedIPs": d.get("allowed_ips", ["0.0.0.0/0", "::/0"]),
    }
    pre_shared_key = str(d.get("pre_shared_key", "")).strip()
    if pre_shared_key:
        peer["preSharedKey"] = pre_shared_key
    keep_alive = int(d.get("keep_alive", 0) or 0)
    if keep_alive > 0:
        peer["keepAlive"] = keep_alive

    settings = {
        "secretKey": d["secret_key"],
        "address": [d.get("local_address", "172.16.0.2/32")],
        "peers": [peer],
    }
    mtu = int(d.get("mtu", 0) or 0)
    if mtu > 0:
        settings["mtu"] = mtu
    reserved = d.get("reserved")
    if isinstance(reserved, list) and len(reserved) == 3:
        settings["reserved"] = reserved

    return {
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": int(inbound_port),
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [{
            "protocol": "wireguard",
            "tag": "proxy",
            "settings": settings
        }]
    }


def build_shadowtls_config(d, inbound_port=10808, allow_insecure_tls=True):
    outbound = {
        "protocol": "shadowtls",
        "tag": "proxy",
        "settings": {
            "servers": [{
                "address": d["address"],
                "port": int(d["port"]),
                "password": d["password"],
            }]
        },
        "streamSettings": build_stream(
            {
                "network": "tcp",
                "security": "tls",
                "sni": d.get("sni", ""),
                "alpn": d.get("alpn", ""),
                "fp": d.get("fp", ""),
            },
            allow_insecure_tls=allow_insecure_tls
        )
    }
    version = int(d.get("version", 3) or 3)
    outbound["settings"]["servers"][0]["version"] = version
    return {
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": int(inbound_port),
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [outbound]
    }


def build_internal_outbound_config(protocol_name, inbound_port=10808):
    return {
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": int(inbound_port),
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [{
            "protocol": protocol_name,
            "tag": "proxy",
            "settings": {}
        }]
    }


def parse_multiline(value):
    return [x.strip() for x in str(value).splitlines() if x.strip()]


def apply_settings_to_config(config, settings):
    cfg = json.loads(json.dumps(config))

    inbounds = cfg.setdefault("inbounds", [])
    outbounds = cfg.setdefault("outbounds", [])
    if not inbounds or not outbounds:
        return cfg

    if not inbounds[0].get("tag"):
        inbounds[0]["tag"] = "socks-in"
    inbound_tag = inbounds[0]["tag"]

    if not outbounds[0].get("tag"):
        outbounds[0]["tag"] = "proxy"
    proxy_tag = outbounds[0]["tag"]

    has_direct = any(x.get("tag") == "direct" for x in outbounds)
    if not has_direct:
        outbounds.append({
            "tag": "direct",
            "protocol": "freedom",
            "settings": {}
        })

    mode = settings["routing"]["mode"]
    bypass_lan = settings["routing"]["bypass_lan"]

    rules = []
    if bypass_lan:
        rules.append({
            "type": "field",
            "ip": ["geoip:private"],
            "outboundTag": "direct"
        })

    if mode == "bypass_ir_cn":
        rules.append({
            "type": "field",
            "ip": ["geoip:cn"] if bypass_lan else ["geoip:private", "geoip:cn"],
            "outboundTag": "direct"
        })
        rules.append({
            "type": "field",
            "domain": ["geosite:private", "geosite:cn"],
            "outboundTag": "direct"
        })
    elif mode == "direct_all":
        rules.append({
            "type": "field",
            "inboundTag": [inbound_tag],
            "outboundTag": "direct"
        })
        cfg["routing"] = {"domainStrategy": "IPIfNonMatch", "rules": rules}
        return cfg

    direct_domains = parse_multiline(settings["routing"]["direct_domains"])
    if direct_domains:
        rules.append({
            "type": "field",
            "domain": direct_domains,
            "outboundTag": "direct"
        })

    direct_ips = parse_multiline(settings["routing"]["direct_ips"])
    if direct_ips:
        rules.append({
            "type": "field",
            "ip": direct_ips,
            "outboundTag": "direct"
        })

    proxy_domains = parse_multiline(settings["routing"]["proxy_domains"])
    if proxy_domains:
        rules.append({
            "type": "field",
            "domain": proxy_domains,
            "outboundTag": proxy_tag
        })

    rules.append({
        "type": "field",
        "inboundTag": [inbound_tag],
        "outboundTag": proxy_tag if mode != "direct_all" else "direct"
    })

    cfg["routing"] = {
        "domainStrategy": "IPIfNonMatch",
        "rules": rules
    }

    if settings["dns"]["enabled"]:
        servers = parse_multiline(settings["dns"]["servers"])
        if servers:
            cfg["dns"] = {
                "servers": servers,
                "queryStrategy": settings["dns"]["query_strategy"]
            }

    return cfg


def apply_tunnel_to_config(config, settings):
    cfg = json.loads(json.dumps(config))
    inbounds = cfg.setdefault("inbounds", [])
    outbounds = cfg.setdefault("outbounds", [])
    if not outbounds:
        return cfg

    if not outbounds[0].get("tag"):
        outbounds[0]["tag"] = "proxy"
    proxy_tag = outbounds[0]["tag"]

    tun_settings = settings.get("tunnel", {})
    tun_name = str(tun_settings.get("name", "xray0") or "xray0").strip() or "xray0"
    tun_mtu = _safe_int(tun_settings.get("mtu", 1500), 1500)

    tun_inbound = {
        "tag": "tun-in",
        "protocol": "tun",
        "settings": {
            "name": tun_name,
            "MTU": tun_mtu,
            "UserLevel": 0,
        },
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
        },
    }

    replaced = False
    for idx, inbound in enumerate(inbounds):
        if inbound.get("tag") == "tun-in" or inbound.get("protocol") == "tun":
            inbounds[idx] = tun_inbound
            replaced = True
            break
    if not replaced:
        inbounds.append(tun_inbound)

    routing = cfg.setdefault("routing", {"domainStrategy": "IPIfNonMatch", "rules": []})
    rules = routing.setdefault("rules", [])
    has_tun_rule = any(
        isinstance(rule.get("inboundTag"), list) and "tun-in" in rule.get("inboundTag", [])
        for rule in rules
    )
    if not has_tun_rule:
        rules.append({
            "type": "field",
            "inboundTag": ["tun-in"],
            "outboundTag": proxy_tag,
        })

    uplink_interface = str(tun_settings.get("uplink_interface", "")).strip()
    if uplink_interface:
        primary = outbounds[0]
        stream_settings = primary.setdefault("streamSettings", {})
        sockopt = stream_settings.setdefault("sockopt", {})
        sockopt["interface"] = uplink_interface

    return cfg


# ===============================
# XRAY RUNNER (LOG SUPPORT ADDED)
# ===============================

def config_signature(config):
    return json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def write_config(config):
    with open(CONFIG_PATH, "w", encoding="utf8") as f:
        json.dump(config, f, indent=2)


def build_bootstrap_config():
    return {
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": 10808,
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [{
            "protocol": "freedom",
            "settings": {}
        }]
    }


def start_xray(log_callback=None, verify_start=False, verify_seconds=2.0):
    global xray_process

    with XRAY_LOCK:
        if not os.path.exists(XRAY_PATH):
            raise FileNotFoundError(f"xray core not found: {XRAY_PATH}")

        # Kill any existing Xray process before starting a new one
        stop_xray_process(log_callback)

        # Start the new Xray process
        proc = subprocess.Popen(
            [XRAY_PATH, "run", "-config", CONFIG_PATH],
            cwd=XRAY_CORE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            creationflags=NO_WINDOW_FLAG
        )
        xray_process = proc

        if log_callback:
            def reader():
                if not proc.stdout:
                    return
                for line in proc.stdout:
                    log_callback(line.strip())
            threading.Thread(target=reader, daemon=True).start()

        if verify_start:
            time.sleep(max(0.2, float(verify_seconds)))
            if proc.poll() is not None:
                if log_callback:
                    log_callback(f"[Xray] process exited early with code {proc.returncode}")
                return False
        return True


def stop_xray_process(log_callback=None, terminate_timeout=3.0, kill_timeout=3.0):
    global xray_process

    with XRAY_LOCK:
        if not xray_process:
            return

        try:
            if xray_process.poll() is None:
                xray_process.terminate()
                try:
                    xray_process.wait(timeout=max(0.2, float(terminate_timeout)))
                except subprocess.TimeoutExpired:
                    xray_process.kill()
                    xray_process.wait(timeout=max(0.2, float(kill_timeout)))
        except Exception as e:
            if log_callback:
                log_callback(f"[Xray] stop failed: {e}")
        finally:
            xray_process = None


# ===============================
# GUI
# ===============================

def set_smart_columns(table, ratios=(0.5, 0.2, 0.3), min_widths=(150, 60, 80), max_widths=(1000, 200, 300)):
    """
    table: QTableWidget
    ratios: نسبت ستون‌ها نسبت به عرض جدول (جمع تقریبی 1)
    min_widths: حداقل عرض هر ستون
    max_widths: حداکثر عرض هر ستون
    """
    def resize_columns(event=None):
        total_width = table.viewport().width()
        for i, ratio in enumerate(ratios):
            w = int(total_width * ratio)
            w = max(w, min_widths[i])
            w = min(w, max_widths[i])
            table.setColumnWidth(i, w)

    # وصل کردن به رویداد تغییر اندازه جدول
    original_resize_event = table.resizeEvent
    table.resizeEvent = lambda event: (resize_columns(), original_resize_event(event))

    # اجرای اولیه
    resize_columns()


def build_app_stylesheet(mode, accent):
    is_dark = mode == "dark"
    bg = "#0f172a" if is_dark else "#f6f8fb"
    panel = "#111827" if is_dark else "#ffffff"
    panel_alt = "#1f2937" if is_dark else "#eef2ff"
    text = "#e5e7eb" if is_dark else "#111827"
    muted = "#94a3b8" if is_dark else "#6b7280"
    border = "#334155" if is_dark else "#dbe2ea"
    table_alt = "#0b1222" if is_dark else "#f8fafc"

    dropdown_bg = "#0b1220" if is_dark else "#ffffff"
    dropdown_hover = "#1e293b" if is_dark else "#e8eef9"
    dropdown_text = "#e5e7eb" if is_dark else "#111827"

    return f"""
    QMainWindow {{
        background: {bg};
        color: {text};
    }}
    QWidget {{
        color: {text};
        font-family: "Segoe UI Variable", "Segoe UI", "Vazirmatn", sans-serif;
        font-size: 12px;
    }}
    QFrame#Sidebar {{
        background: {panel};
        border: 1px solid {border};
        border-radius: 14px;
    }}
    QFrame#Card {{
        background: {panel};
        border: 1px solid {border};
        border-radius: 12px;
    }}
    QLabel#CardTitle {{
        color: {muted};
        font-size: 11px;
    }}
    QLabel#CardValue {{
        color: {text};
        font-size: 15px;
        font-weight: 700;
    }}
    QPushButton {{
        background: {panel_alt};
        border: 1px solid {border};
        border-radius: 10px;
        padding: 8px 12px;
    }}
    QPushButton:hover {{
        border-color: {accent};
    }}
    QPushButton#Primary {{
        background: {accent};
        color: #ffffff;
        border: none;
        font-weight: 700;
    }}
    QPushButton#NavBtn {{
        text-align: left;
        padding: 10px 12px;
    }}
    QPushButton#NavBtn:checked {{
        background: {accent};
        color: #ffffff;
        border: none;
    }}
    QTableWidget {{
        background: {panel};
        alternate-background-color: {table_alt};
        border: 1px solid {border};
        border-radius: 10px;
        gridline-color: {border};
        selection-background-color: {accent};
        selection-color: #ffffff;
    }}
    QHeaderView::section {{
        background: {panel_alt};
        color: {text};
        border: none;
        border-bottom: 1px solid {border};
        padding: 8px;
        font-weight: 600;
    }}
    QComboBox, QLineEdit, QTextEdit, QPlainTextEdit {{
        background: {panel};
        border: 1px solid {border};
        border-radius: 10px;
        padding: 6px 8px;
    }}
    QComboBox {{
        color: {text};
    }}
    QComboBox::drop-down {{
        border: none;
        width: 22px;
    }}
    QComboBox QAbstractItemView {{
        background: {dropdown_bg};
        color: {dropdown_text};
        selection-background-color: {accent};
        selection-color: #ffffff;
        border: 1px solid {border};
        outline: 0;
    }}
    QComboBox QAbstractItemView::item {{
        min-height: 24px;
        padding: 4px 8px;
    }}
    QComboBox QAbstractItemView::item:hover {{
        background: {dropdown_hover};
    }}
    QTabWidget::pane {{
        border: 1px solid {border};
        border-radius: 10px;
        background: {panel};
    }}
    QTabBar::tab {{
        background: {panel_alt};
        color: {text};
        border: 1px solid {border};
        border-bottom: none;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
        padding: 8px 12px;
        margin-right: 4px;
    }}
    QTabBar::tab:selected {{
        background: {accent};
        color: #ffffff;
        border-color: {accent};
    }}
    QDialog {{
        background: {bg};
        color: {text};
    }}
    QMenu {{
        background: {panel};
        color: {text};
        border: 1px solid {border};
        padding: 6px;
    }}
    QMenu::item {{
        padding: 6px 14px;
        border-radius: 6px;
    }}
    QMenu::item:selected {{
        background: {accent};
        color: #ffffff;
    }}
    QCheckBox {{
        spacing: 8px;
    }}
    """

class ToggleSwitch(QWidget):
    toggled = Signal(bool)
    stateChanged = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._checked = False
        self._offset = 4.0
        self._margin = 4.0
        self._knob_d = 18.0
        self._on_bg = QColor("#22c55e")
        self._off_bg = QColor("#94a3b8")
        self._on_border = QColor("#16a34a")
        self._off_border = QColor("#64748b")
        self._knob = QColor("#ffffff")
        self._disabled_bg = QColor("#9ca3af")
        self._disabled_border = QColor("#6b7280")
        self.setFixedSize(52, 26)
        self.setCursor(Qt.PointingHandCursor)
        self._anim = QPropertyAnimation(self, b"offset", self)
        self._anim.setDuration(140)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

    def sizeHint(self):
        return QSize(52, 26)

    def isChecked(self):
        return self._checked

    def setChecked(self, checked):
        checked = bool(checked)
        if self._checked == checked:
            return
        self._checked = checked
        self._animate_knob()
        self.toggled.emit(self._checked)
        self.stateChanged.emit(2 if self._checked else 0)
        self.update()

    def toggle(self):
        self.setChecked(not self._checked)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton and self.isEnabled():
            self.toggle()
        super().mouseReleaseEvent(event)

    def _left_pos(self):
        return self._margin

    def _right_pos(self):
        return self.width() - self._margin - self._knob_d

    def set_colors(
        self,
        on_bg,
        off_bg,
        on_border,
        off_border,
        knob="#ffffff",
        disabled_bg="#9ca3af",
        disabled_border="#6b7280",
    ):
        self._on_bg = QColor(on_bg)
        self._off_bg = QColor(off_bg)
        self._on_border = QColor(on_border)
        self._off_border = QColor(off_border)
        self._knob = QColor(knob)
        self._disabled_bg = QColor(disabled_bg)
        self._disabled_border = QColor(disabled_border)
        self.update()

    def _animate_knob(self):
        self._anim.stop()
        self._anim.setStartValue(self._offset)
        self._anim.setEndValue(self._right_pos() if self._checked else self._left_pos())
        self._anim.start()

    def getOffset(self):
        return self._offset

    def setOffset(self, value):
        self._offset = float(value)
        self.update()

    offset = Property(float, getOffset, setOffset)

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(1, 1, -1, -1)

        if self.isEnabled():
            bg = self._on_bg if self._checked else self._off_bg
            border = self._on_border if self._checked else self._off_border
        else:
            bg = self._disabled_bg
            border = self._disabled_border

        p.setPen(QPen(border, 1))
        p.setBrush(bg)
        p.drawRoundedRect(rect, rect.height() / 2, rect.height() / 2)

        knob_rect = QRectF(self._offset, self._margin, self._knob_d, self._knob_d)
        p.setPen(QPen(self._knob, 1))
        p.setBrush(self._knob)
        p.drawEllipse(knob_rect)

class MainWindow(QMainWindow):

    log_signal = Signal(str)
    table_update_signal = Signal(int, int, str)
    testing_state_signal = Signal(int, int, bool)
    ui_call_signal = Signal(object)

    COL_REMARKS = 0
    COL_ADDRESS = 1
    COL_PORT = 2
    COL_CONFIG = 3
    COL_TRANSPORT = 4
    COL_TLS = 5
    COL_PING = 6
    COL_SPEED = 7

    def __init__(self):
        super().__init__()

        self.setWindowTitle(f"V2rayX v{APP_VERSION}")
        self.resize(1260, 760)
        self.setAcceptDrops(True)
        if os.path.exists(APP_ICON_PATH):
            self.setWindowIcon(QIcon(APP_ICON_PATH))

        self.profiles = load_profiles()
        self.settings = load_settings()
        self.subscriptions = list(self.settings.get("subscriptions", []))
        self.tunnel_enabled = bool(self.settings.get("tunnel", {}).get("enabled", False))
        self.tunnel_transition = False
        self.tunnel_route_ifindex = None
        self.tunnel_uplink_interface = ""
        self.tunnel_probe_running = False
        self.tunnel_heal_running = False
        self._tunnel_last_log_ts = {}
        self._tunnel_last_heal_try_ts = 0.0
        self._profile_lock_tip_ts = 0.0
        self.active_config_signature = None
        self.base_config = None
        self.theme_mode = "light"
        self.accent_color = "#3b82f6"
        self.log_entries = []
        self.max_log_entries = int(self.settings["advanced"]["log_limit"])
        self.max_rendered_logs = 320
        self.log_render_pending = False
        self._last_log_render_ts = 0.0
        self._log_render_min_interval = 0.35
        self._last_log_html = ""
        self._exit_requested = False
        self._tray_minimize_notice_shown = False
        self._log_repeat_key = ""
        self._log_repeat_sample = ""
        self._log_repeat_count = 0
        self._log_repeat_last_ts = 0.0
        self._tunnel_log_gate = {}
        self._xray_task_queue = queue.Queue()
        self._xray_worker = threading.Thread(target=self._xray_worker_loop, daemon=True)
        self._xray_worker.start()
        self.log_signal.connect(self.append_log)
        self.table_update_signal.connect(self.update_table_cell)
        self.testing_state_signal.connect(self.set_testing_state)
        self.ui_call_signal.connect(self._invoke_ui_callable)

        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(12, 12, 12, 12)
        root_layout.setSpacing(12)

        # Sidebar
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(220)
        sb = QVBoxLayout(sidebar)
        sb.setContentsMargins(12, 12, 12, 12)
        sb.setSpacing(8)

        brand = QLabel("XRAY HUB")
        brand.setStyleSheet("font-size:20px;font-weight:800;letter-spacing:1px;")
        sb.addWidget(brand)
        caption = QLabel("Desktop Control Panel")
        caption.setStyleSheet("color:#94a3b8;")
        sb.addWidget(caption)

        self.navProfiles = QPushButton("Profiles")
        self.navProfiles.setObjectName("NavBtn")
        self.navProfiles.setCheckable(True)
        self.navProfiles.setChecked(True)
        self.navSettings = QPushButton("Settings")
        self.navSettings.setObjectName("NavBtn")
        self.navSettings.setCheckable(True)
        self.navSubs = QPushButton("Subscriptions")
        self.navSubs.setObjectName("NavBtn")
        self.navSubs.setCheckable(True)
        self.navProfiles.clicked.connect(lambda: self.switch_sidebar_tab("profiles"))
        self.navSettings.clicked.connect(lambda: self.switch_sidebar_tab("settings"))
        self.navSubs.clicked.connect(lambda: self.switch_sidebar_tab("subscriptions"))
        sb.addWidget(self.navProfiles)
        sb.addWidget(self.navSettings)
        sb.addWidget(self.navSubs)
        sb.addStretch(1)

        self.themeBtn = QPushButton("Switch Theme")
        self.themeBtn.clicked.connect(self.toggle_theme)
        sb.addWidget(self.themeBtn)
        self.aboutBtn = QPushButton("About")
        self.aboutBtn.clicked.connect(self.show_about_dialog)
        sb.addWidget(self.aboutBtn)
        self.exitBtn = QPushButton("Exit")
        self.exitBtn.clicked.connect(self.exit_from_tray)
        sb.addWidget(self.exitBtn)

        root_layout.addWidget(sidebar)

        # Main content
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(10)
        content_layout.setContentsMargins(0, 0, 0, 0)

        top_card = QFrame()
        top_card.setObjectName("Card")
        top = QHBoxLayout(top_card)
        top.setContentsMargins(12, 10, 12, 10)
        top.setSpacing(8)

        self.pingBtn = QPushButton("Ping")
        self.pingBtn.clicked.connect(self.ping_selected)

        self.speedBtn = QPushButton("Speed")
        self.speedBtn.clicked.connect(self.speed_selected)

        self.systemProxyLabel = QLabel("System Proxy")
        top.addWidget(self.systemProxyLabel)
        self.systemProxyToggle = ToggleSwitch()
        self.systemProxyToggle.toggled.connect(self.on_system_proxy_toggled)
        top.addWidget(self.systemProxyToggle)

        self.systemTunnelLabel = QLabel("System Tunnel")
        top.addWidget(self.systemTunnelLabel)
        self.systemTunnelToggle = ToggleSwitch()
        self.systemTunnelToggle.toggled.connect(self.on_system_tunnel_toggled)
        top.addWidget(self.systemTunnelToggle)

        self.startCoreBtn = QPushButton("Start Xray Core")
        self.startCoreBtn.clicked.connect(self.start_core_manual)
        top.addWidget(self.startCoreBtn)

        self.stopCoreBtn = QPushButton("Stop Xray Core")
        self.stopCoreBtn.clicked.connect(self.stop_core_manual)
        top.addWidget(self.stopCoreBtn)

        self.reloadCoreBtn = QPushButton("Reload")
        self.reloadCoreBtn.clicked.connect(self.reload_core_manual)
        top.addWidget(self.reloadCoreBtn)

        self.accentCombo = QComboBox()
        self.accentCombo.addItems(["Blue", "Emerald", "Rose", "Amber"])
        self.accentCombo.currentIndexChanged.connect(self.change_accent)
        top.addWidget(self.accentCombo)
        top.addStretch(1)
        content_layout.addWidget(top_card)

        status_row = QHBoxLayout()
        status_row.setSpacing(10)
        self.coreCard, self.coreStatusValue = self.create_status_card("Core Status", "Unknown")
        self.proxyCard, self.proxyStatusValue = self.create_status_card("System Proxy", "Unknown")
        self.tunnelCard, self.tunnelStatusValue = self.create_status_card("System Tunnel", "Disabled")
        self.activeCard, self.activeProfileValue = self.create_status_card("Active Profile", "-")
        self.netCard, self.netQualityValue = self.create_status_card("Network Health", "-")
        status_row.addWidget(self.coreCard)
        status_row.addWidget(self.proxyCard)
        status_row.addWidget(self.tunnelCard)
        status_row.addWidget(self.activeCard)
        status_row.addWidget(self.netCard)
        content_layout.addLayout(status_row)

        table_card = QFrame()
        table_card.setObjectName("Card")
        table_layout = QVBoxLayout(table_card)
        table_layout.setContentsMargins(10, 10, 10, 10)
        table_layout.setSpacing(8)

        self.table = QTableWidget()
        self.table.installEventFilter(self)
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "📝 Remarks",
            "🌐 Address",
            "🔌 Port",
            "🧩 Config Type",
            "🚚 Transport",
            "🔒 TLS Type",
            "📶 Ping",
            "🚀 Speed",
        ])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self.on_table_selection_changed)
        self.table.cellDoubleClicked.connect(self.on_table_double_clicked)
        self.table.viewport().installEventFilter(self)

        set_smart_columns(
            self.table,
            ratios=(0.24, 0.16, 0.08, 0.11, 0.10, 0.10, 0.11, 0.10),
            min_widths=(170, 140, 70, 90, 90, 90, 90, 100),
            max_widths=(900, 420, 150, 220, 220, 220, 220, 260),
        )
        table_layout.addWidget(self.table)

        self.emptyState = QLabel("No profiles yet.\nPaste vmess/vless links (Ctrl+V) or drag and drop.")
        self.emptyState.setAlignment(Qt.AlignCenter)
        self.emptyState.setStyleSheet("color:#94a3b8;font-size:14px;padding:24px;")
        table_layout.addWidget(self.emptyState)
        content_layout.addWidget(table_card, 2)

        log_card = QFrame()
        log_card.setObjectName("Card")
        log_layout = QVBoxLayout(log_card)
        log_layout.setContentsMargins(10, 10, 10, 10)
        log_layout.setSpacing(8)

        log_toolbar = QHBoxLayout()
        self.logFilterCombo = QComboBox()
        self.logFilterCombo.addItems(["All", "Info", "Warn", "Error"])
        self.logFilterCombo.currentIndexChanged.connect(self.render_logs)
        log_toolbar.addWidget(self.logFilterCombo)

        self.clearLogBtn = QPushButton("Clear")
        self.clearLogBtn.clicked.connect(self.clear_logs)
        log_toolbar.addWidget(self.clearLogBtn)
        self.copyLogBtn = QPushButton("Copy")
        self.copyLogBtn.clicked.connect(self.copy_logs)
        log_toolbar.addWidget(self.copyLogBtn)
        self.exportLogBtn = QPushButton("Export")
        self.exportLogBtn.clicked.connect(self.export_logs)
        log_toolbar.addWidget(self.exportLogBtn)
        log_toolbar.addStretch(1)
        log_layout.addLayout(log_toolbar)

        self.logBox = QTextEdit()
        self.logBox.setReadOnly(True)
        self.logBox.setMinimumHeight(180)
        log_layout.addWidget(self.logBox)
        content_layout.addWidget(log_card, 1)

        self.page_stack = QStackedWidget()
        self.page_stack.addWidget(content)
        self.page_stack.addWidget(self.build_settings_page())
        self.page_stack.addWidget(self.build_subscriptions_page())
        root_layout.addWidget(self.page_stack, 1)
        self.setCentralWidget(root)
        self.statusBar().showMessage("Ready")
        self.setup_tray_icon()

        self.apply_theme()
        self.refresh_table()
        self.update_profile_combo()

        QShortcut(QKeySequence("Ctrl+V"), self).activated.connect(self.handle_paste)
        QShortcut(QKeySequence("Ctrl+R"), self).activated.connect(self.ping_selected)
        QShortcut(QKeySequence("Ctrl+T"), self).activated.connect(self.speed_selected)
        QShortcut(QKeySequence("Return"), self.table).activated.connect(self.select_config)
        QShortcut(QKeySequence("Enter"), self.table).activated.connect(self.select_config)
        QShortcut(QKeySequence("Ctrl+A"), self.table).activated.connect(self.select_all_profiles)
        QShortcut(QKeySequence("Delete"), self.table).activated.connect(self.delete_selected_rows)

        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.context_menu)

        self.status_timer = QTimer(self)
        self.status_timer.setInterval(1000)
        self.status_timer.timeout.connect(self.update_runtime_status)
        self.status_timer.start()

        self.tunnel_monitor_timer = QTimer(self)
        self.tunnel_monitor_timer.setInterval(10000)
        self.tunnel_monitor_timer.timeout.connect(self.check_tunnel_uplink_change)
        self.tunnel_monitor_timer.start()

        self.update_runtime_status()
        QTimer.singleShot(250, self.run_startup_tasks)
        self.switch_sidebar_tab("profiles")

        self.fade = QPropertyAnimation(self, b"windowOpacity")
        self.fade.setDuration(260)
        self.fade.setStartValue(0.96)
        self.fade.setEndValue(1.0)
        self.fade.start()

        self.testing_cells = {}
        self.testing_tick = 0
        self.testing_timer = QTimer(self)
        self.testing_timer.setInterval(350)
        self.testing_timer.timeout.connect(self.animate_testing_cells)
        self.testing_timer.start()

    def _xray_worker_loop(self):
        while True:
            task = self._xray_task_queue.get()
            try:
                task()
            except Exception as e:
                self.log(f"[Xray] background task failed: {e}")
                self.log(traceback.format_exc().strip())
            finally:
                self._xray_task_queue.task_done()

    def _enqueue_xray_task(self, task):
        self._xray_task_queue.put(task)

    # ---------------- LOG FUNCTIONS ----------------

    def create_status_card(self, title, value):
        card = QFrame()
        card.setObjectName("Card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(3)
        t = QLabel(title)
        t.setObjectName("CardTitle")
        v = QLabel(value)
        v.setObjectName("CardValue")
        lay.addWidget(t)
        lay.addWidget(v)
        return card, v

    def apply_theme(self):
        self.setStyleSheet(build_app_stylesheet(self.theme_mode, self.accent_color))
        self.apply_toggle_theme()

    def apply_toggle_theme(self):
        if self.theme_mode == "dark":
            off_bg = "#334155"
            off_border = "#475569"
            knob = "#e5e7eb"
            disabled_bg = "#374151"
            disabled_border = "#4b5563"
        else:
            off_bg = "#dbe2ea"
            off_border = "#c4ced9"
            knob = "#ffffff"
            disabled_bg = "#cbd5e1"
            disabled_border = "#94a3b8"

        for sw in (self.systemProxyToggle, self.systemTunnelToggle):
            sw.set_colors(
                on_bg=self.accent_color,
                off_bg=off_bg,
                on_border=self.accent_color,
                off_border=off_border,
                knob=knob,
                disabled_bg=disabled_bg,
                disabled_border=disabled_border,
            )

    def toggle_theme(self):
        self.theme_mode = "light" if self.theme_mode == "dark" else "dark"
        self.apply_theme()
        self.show_toast(f"Theme: {self.theme_mode.title()}")

    def change_accent(self):
        color_map = {
            "Blue": "#3b82f6",
            "Emerald": "#10b981",
            "Rose": "#f43f5e",
            "Amber": "#f59e0b",
        }
        self.accent_color = color_map.get(self.accentCombo.currentText(), "#3b82f6")
        self.apply_theme()

    def switch_sidebar_tab(self, tab):
        self.navProfiles.setChecked(tab == "profiles")
        self.navSettings.setChecked(tab == "settings")
        self.navSubs.setChecked(tab == "subscriptions")
        if tab == "settings":
            self.load_settings_page_values()
            self.page_stack.setCurrentIndex(1)
        elif tab == "subscriptions":
            self.reload_subscriptions_table()
            self.page_stack.setCurrentIndex(2)
        else:
            self.page_stack.setCurrentIndex(0)

    def show_toast(self, text):
        self.statusBar().showMessage(text, 2500)

    def show_about_dialog(self):
        xray_state = "Found" if os.path.exists(XRAY_PATH) else "Missing"
        wintun_state = "Found" if os.path.exists(WINTUN_PATH) else "Missing"
        details = (
            f"V2rayX\n"
            f"Version: {APP_VERSION}\n"
            f"Platform: Windows\n"
            f"Python: {sys.version.split()[0]}\n"
            f"Qt: {qVersion()}\n"
            f"Xray Core: {xray_state}\n"
            f"Wintun: {wintun_state}\n"
            f"Core Dir: {XRAY_CORE_DIR}\n"
            f"Data Dir: {DATA_DIR}"
        )
        QMessageBox.information(self, "About V2rayX", details)

    def setup_tray_icon(self):
        self.tray_icon = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        icon = self.windowIcon()
        if icon.isNull():
            icon = self.style().standardIcon(QStyle.SP_ComputerIcon)
            self.setWindowIcon(icon)

        self.tray_icon = QSystemTrayIcon(icon, self)
        self.tray_icon.setToolTip("V2rayX")

        tray_menu = QMenu(self)
        open_action = tray_menu.addAction("Open")
        tray_menu.addSeparator()
        self.tray_set_proxy_action = tray_menu.addAction("Set System Proxy")
        self.tray_clear_proxy_action = tray_menu.addAction("Clear System Proxy")
        tray_menu.addSeparator()
        exit_action = tray_menu.addAction("Exit")
        open_action.triggered.connect(self.show_from_tray)
        self.tray_set_proxy_action.triggered.connect(self.on_set_proxy_clicked)
        self.tray_clear_proxy_action.triggered.connect(self.on_clear_proxy_clicked)
        exit_action.triggered.connect(self.exit_from_tray)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_activated)
        self.tray_icon.show()

    def on_tray_activated(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.show_from_tray()

    def show_from_tray(self):
        self.showNormal()
        self.activateWindow()
        self.raise_()

    def exit_from_tray(self):
        self._exit_requested = True
        self.close()

    def run_startup_tasks(self):
        if self.settings["proxy"]["set_proxy_on_app_launch"]:
            self.on_set_proxy_clicked()
        if self.settings["core"]["autostart_core"]:
            row = self.table.currentRow()
            if row >= 0 and self.profiles:
                self.select_config()
            else:
                self._enqueue_xray_task(self.autostart_xray)

    def save_subscriptions(self):
        cleaned = []
        for item in self.subscriptions:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            name = str(item.get("name", "")).strip()
            cleaned.append({"name": name, "url": url})
        self.subscriptions = cleaned
        self.settings["subscriptions"] = cleaned
        save_settings(self.settings)

    def import_profile_links(self, links, source="Import"):
        added = 0
        for link in links:
            try:
                profile = parse_profile_link(link)
                self.profiles.append(profile)
                added += 1
            except Exception as e:
                self.log(f"[{source}] skipped invalid profile: {e}")
        if added:
            save_profiles(self.profiles)
            self.refresh_table()
            self.log(f"[{source}] added {added} profile(s)")
            self.show_toast(f"Imported {added} profile(s)")
        return added

    def fetch_and_import_subscription(self, sub_url, sub_name=""):
        title = sub_name.strip() or sub_url
        self.log(f"[Sub] fetching: {title}")
        links = fetch_subscription_links(sub_url)
        if not links:
            raise ValueError("No valid nodes found in subscription payload")
        added = self.import_profile_links(links, source="Sub")
        self.log(f"[Sub] fetched {len(links)} node(s) from {title}")
        return added

    def _fetch_subscriptions_async(self, items, summary_mode):
        def worker():
            results = []
            errors = []
            for item in items:
                url = item.get("url", "")
                name = item.get("name", "")
                title = name.strip() or url
                self.log(f"[Sub] fetching: {title}")
                try:
                    links = fetch_subscription_links(url)
                    if not links:
                        raise ValueError("No valid nodes found in subscription payload")
                    results.append({"title": title, "links": links})
                except Exception as e:
                    errors.append((title, str(e)))
            QTimer.singleShot(0, lambda: self._apply_subscription_results(results, errors, summary_mode))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_subscription_results(self, results, errors, summary_mode):
        total_added = 0
        for item in results:
            added = self.import_profile_links(item["links"], source="Sub")
            total_added += added
            self.log(f"[Sub] fetched {len(item['links'])} node(s) from {item['title']}")

        for title, err in errors:
            self.log(f"[Sub] failed: {title} -> {err}")

        if summary_mode == "selected":
            if total_added > 0:
                QMessageBox.information(self, "Subscription", f"Imported {total_added} profile(s)")
            else:
                msg = errors[0][1] if errors else "No profiles imported"
                QMessageBox.warning(self, "Subscription Error", msg)
        elif summary_mode == "all":
            QMessageBox.information(self, "Subscription", f"Imported {total_added} profile(s), errors: {len(errors)}")
        elif summary_mode == "paste":
            if total_added == 0 and not errors:
                self.show_toast("No profiles imported")

    def fetch_qr_png(self, text, size=360):
        data = str(text or "").strip()
        if not data:
            raise ValueError("Empty text for QR")

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=2,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        output = io.BytesIO()
        img.save(output, format="PNG")
        png_data = output.getvalue()

        pixmap = QPixmap()
        if not pixmap.loadFromData(png_data):
            raise ValueError("Failed to decode QR image")
        return pixmap, png_data

    def show_qr_dialog(self, title, text, default_name="qrcode.png"):
        try:
            pixmap, png_data = self.fetch_qr_png(text)
        except Exception as e:
            QMessageBox.warning(self, "QR Error", str(e))
            self.log(f"[QR] generation failed: {e}")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        dlg.resize(470, 560)
        layout = QVBoxLayout(dlg)

        img_label = QLabel()
        img_label.setAlignment(Qt.AlignCenter)
        img_label.setPixmap(pixmap.scaled(320, 320, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        layout.addWidget(img_label)

        text_box = QPlainTextEdit()
        text_box.setPlainText(str(text))
        text_box.setReadOnly(True)
        text_box.setMinimumHeight(120)
        layout.addWidget(text_box)

        row = QHBoxLayout()
        copy_link_btn = QPushButton("Copy Link")
        copy_qr_btn = QPushButton("Copy QR")
        save_btn = QPushButton("Save PNG")
        close_btn = QPushButton("Close")
        row.addWidget(copy_link_btn)
        row.addWidget(copy_qr_btn)
        row.addWidget(save_btn)
        row.addStretch(1)
        row.addWidget(close_btn)
        layout.addLayout(row)

        def copy_link():
            QApplication.clipboard().setText(str(text))
            self.show_toast("Link copied")

        def copy_qr():
            QApplication.clipboard().setPixmap(pixmap)
            self.show_toast("QR copied")

        def save_png():
            path, _ = QFileDialog.getSaveFileName(self, "Save QR", default_name, "PNG Files (*.png)")
            if not path:
                return
            with open(path, "wb") as f:
                f.write(png_data)
            self.show_toast(f"Saved: {path}")

        copy_link_btn.clicked.connect(copy_link)
        copy_qr_btn.clicked.connect(copy_qr)
        save_btn.clicked.connect(save_png)
        close_btn.clicked.connect(dlg.accept)
        dlg.exec()

    def share_selected_profile_qr(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.profiles):
            return
        profile = self.profiles[row]
        self.show_qr_dialog(
            title=f"Profile QR - {profile.get('name', 'Profile')}",
            text=profile.get("link", ""),
            default_name=f"profile-{row + 1}.png"
        )

    def share_selected_subscription_qr(self):
        row = self.subTable.currentRow()
        if row < 0 or row >= len(self.subscriptions):
            return
        item = self.subscriptions[row]
        name = item.get("name", "").strip() or "subscription"
        self.show_qr_dialog(
            title=f"Subscription QR - {name}",
            text=item.get("url", ""),
            default_name=f"{name}.png"
        )

    def build_subscriptions_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        card = QFrame()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(12, 12, 12, 12)
        card_layout.setSpacing(8)

        title = QLabel("Subscriptions")
        title.setStyleSheet("font-size:16px;font-weight:700;")
        card_layout.addWidget(title)

        self.subTable = QTableWidget()
        self.subTable.setColumnCount(2)
        self.subTable.setHorizontalHeaderLabels(["Name", "URL"])
        self.subTable.setSelectionBehavior(QTableWidget.SelectRows)
        self.subTable.setSelectionMode(QTableWidget.SingleSelection)
        self.subTable.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.subTable.horizontalHeader().setStretchLastSection(False)
        set_smart_columns(
            self.subTable,
            ratios=(0.30, 0.70),
            min_widths=(160, 320),
            max_widths=(420, 5000),
        )
        card_layout.addWidget(self.subTable, 1)

        form = QHBoxLayout()
        self.subNameEdit = QLineEdit()
        self.subNameEdit.setPlaceholderText("Optional name")
        self.subUrlEdit = QLineEdit()
        self.subUrlEdit.setPlaceholderText("https://... subscription url")
        form.addWidget(self.subNameEdit, 1)
        form.addWidget(self.subUrlEdit, 3)
        card_layout.addLayout(form)

        btn_row = QHBoxLayout()
        add_btn = QPushButton("Add/Update")
        delete_btn = QPushButton("Delete")
        fetch_one_btn = QPushButton("Fetch Selected")
        fetch_all_btn = QPushButton("Fetch All")
        share_qr_btn = QPushButton("Share QR")
        btn_row.addWidget(add_btn)
        btn_row.addWidget(delete_btn)
        btn_row.addWidget(fetch_one_btn)
        btn_row.addWidget(fetch_all_btn)
        btn_row.addWidget(share_qr_btn)
        btn_row.addStretch(1)
        card_layout.addLayout(btn_row)

        layout.addWidget(card, 1)

        self.subTable.itemSelectionChanged.connect(self.on_subscription_select)
        add_btn.clicked.connect(self.on_subscription_add_update)
        delete_btn.clicked.connect(self.on_subscription_delete)
        fetch_one_btn.clicked.connect(self.on_subscription_fetch_selected)
        fetch_all_btn.clicked.connect(self.on_subscription_fetch_all)
        share_qr_btn.clicked.connect(self.share_selected_subscription_qr)
        self.reload_subscriptions_table()
        return page

    def reload_subscriptions_table(self, select_row=-1):
        if not hasattr(self, "subTable"):
            return
        self.subTable.setRowCount(len(self.subscriptions))
        for i, item in enumerate(self.subscriptions):
            self.subTable.setItem(i, 0, QTableWidgetItem(item.get("name", "")))
            self.subTable.setItem(i, 1, QTableWidgetItem(item.get("url", "")))
        if 0 <= select_row < self.subTable.rowCount():
            self.subTable.selectRow(select_row)

    def on_subscription_select(self):
        row = self.subTable.currentRow()
        if row < 0 or row >= len(self.subscriptions):
            return
        item = self.subscriptions[row]
        self.subNameEdit.setText(item.get("name", ""))
        self.subUrlEdit.setText(item.get("url", ""))

    def on_subscription_add_update(self):
        name = self.subNameEdit.text().strip()
        url = self.subUrlEdit.text().strip()
        if not url.lower().startswith(("http://", "https://")):
            QMessageBox.warning(self, "Subscription", "Subscription URL must start with http/https")
            return
        row = self.subTable.currentRow()
        entry = {"name": name, "url": url}
        if 0 <= row < len(self.subscriptions):
            self.subscriptions[row] = entry
            idx = row
        else:
            self.subscriptions.append(entry)
            idx = len(self.subscriptions) - 1
        self.save_subscriptions()
        self.reload_subscriptions_table(select_row=idx)
        self.log("[Sub] subscription saved")

    def on_subscription_delete(self):
        row = self.subTable.currentRow()
        if row < 0 or row >= len(self.subscriptions):
            return
        self.subscriptions.pop(row)
        self.save_subscriptions()
        self.reload_subscriptions_table(select_row=max(0, row - 1))
        self.subNameEdit.clear()
        self.subUrlEdit.clear()
        self.log("[Sub] subscription deleted")

    def on_subscription_fetch_selected(self):
        row = self.subTable.currentRow()
        if row < 0 or row >= len(self.subscriptions):
            return
        item = self.subscriptions[row]
        self._fetch_subscriptions_async([item], summary_mode="selected")

    def on_subscription_fetch_all(self):
        if not self.subscriptions:
            return
        self._fetch_subscriptions_async(list(self.subscriptions), summary_mode="all")

    def append_log(self, text):
        if self._should_suppress_log(text):
            return

        level = "INFO"
        low = text.lower()
        if "error" in low or "[error]" in low:
            level = "ERROR"
        elif "warn" in low or "[warning]" in low:
            level = "WARN"

        now = time.time()
        key = f"{level}|{text}"
        if key == self._log_repeat_key and (now - self._log_repeat_last_ts) <= 1.5:
            self._log_repeat_count += 1
            self._log_repeat_last_ts = now
            return

        if self._log_repeat_count > 0:
            self.log_entries.append(
                ("WARN", f"[{datetime.now().strftime('%H:%M:%S')}] [LogGuard] suppressed {self._log_repeat_count} repeated line(s): {self._log_repeat_sample}")
            )
            self._log_repeat_count = 0

        self._log_repeat_key = key
        self._log_repeat_sample = text
        self._log_repeat_last_ts = now

        stamp = datetime.now().strftime("%H:%M:%S")
        self.log_entries.append((level, f"[{stamp}] {text}"))
        if len(self.log_entries) > self.max_log_entries:
            self.log_entries = self.log_entries[-self.max_log_entries:]
        if not self.log_render_pending:
            self.log_render_pending = True
            QTimer.singleShot(220, self.flush_log_render)

    def log(self, text):
        self.log_signal.emit(text)

    def _log_tunnel_once(self, gate_key, text, cooldown=8.0):
        now = time.time()
        key = str(gate_key)
        last = float(self._tunnel_log_gate.get(key, 0.0))
        if (now - last) < float(cooldown):
            return
        self._tunnel_log_gate[key] = now
        self.log(text)

    def _should_suppress_log(self, text):
        if not bool(self.settings.get("advanced", {}).get("suppress_noisy_core_logs", True)):
            return False
        msg = str(text or "").lower()
        noisy_patterns = (
            "the feature websocket transport",
            "\"allowinsecure\" will be removed",
            "feature \"host\" in \"headers\" is deprecated",
            "the feature vless (with no flow",
        )
        return any(p in msg for p in noisy_patterns)

    def flush_log_render(self):
        now = time.time()
        wait_seconds = self._log_render_min_interval - (now - self._last_log_render_ts)
        if wait_seconds > 0:
            QTimer.singleShot(int(wait_seconds * 1000) + 10, self.flush_log_render)
            return

        if self._log_repeat_count > 0:
            self.log_entries.append(
                ("WARN", f"[{datetime.now().strftime('%H:%M:%S')}] [LogGuard] suppressed {self._log_repeat_count} repeated line(s): {self._log_repeat_sample}")
            )
            self._log_repeat_count = 0
        self.log_render_pending = False
        self._last_log_render_ts = now
        self.render_logs()

    def render_logs(self):
        wanted = self.logFilterCombo.currentText().upper() if hasattr(self, "logFilterCombo") else "ALL"
        colors = {"INFO": "#60a5fa", "WARN": "#f59e0b", "ERROR": "#ef4444"}
        html_lines = []
        for level, line in self.log_entries[-self.max_rendered_logs:]:
            if wanted != "ALL" and level != wanted:
                continue
            color = colors.get(level, "#93c5fd")
            html_lines.append(f'<span style="color:{color};">[{level}]</span> {html.escape(line)}')
        final_html = "<br>".join(html_lines)
        if final_html == self._last_log_html:
            return
        self._last_log_html = final_html
        self.logBox.setHtml(final_html)

    def clear_logs(self):
        self.log_entries = []
        self.log_render_pending = False
        self._log_repeat_count = 0
        self._log_repeat_key = ""
        self._log_repeat_sample = ""
        self._last_log_html = ""
        self.logBox.clear()

    def copy_logs(self):
        QApplication.clipboard().setText(self.logBox.toPlainText())
        self.show_toast("Logs copied")

    def export_logs(self):
        default_log_path = os.path.join(DATA_DIR, "xray-client.log")
        path, _ = QFileDialog.getSaveFileName(self, "Export Logs", default_log_path, "Log Files (*.log)")
        if not path:
            return
        with open(path, "w", encoding="utf8") as f:
            for _, line in self.log_entries:
                f.write(line + "\n")
        self.show_toast(f"Logs exported: {path}")

    def update_table_cell(self, row, col, text):
        self.table.setItem(row, col, QTableWidgetItem(text))

    def set_testing_state(self, row, col, is_running):
        key = (row, col)
        if is_running:
            self.testing_cells[key] = True
            self.table.setItem(row, col, QTableWidgetItem("Testing."))
        else:
            self.testing_cells.pop(key, None)

    def animate_testing_cells(self):
        if not self.testing_cells:
            return
        self.testing_tick = (self.testing_tick + 1) % 3
        dots = "." * (self.testing_tick + 1)
        for (row, col) in list(self.testing_cells.keys()):
            self.table.setItem(row, col, QTableWidgetItem(f"Testing{dots}"))

    def update_profile_combo(self):
        pass

    def _profile_meta(self, link):
        try:
            d = parse_any_link(link)
            proto = str(d.get("protocol", "-")).strip().upper() or "-"
            security = str(d.get("security", "")).strip().lower()
            if not security:
                if proto in {"HYSTERIA2", "TUIC", "SHADOWTLS"}:
                    security = "tls"
                elif proto in {"WIREGUARD"}:
                    security = "none"
            tls_type = security.upper() if security else "-"
            transport = str(d.get("network", d.get("type", "-"))).strip().upper() or "-"
            address = str(d.get("address", "-")).strip() or "-"
            port = d.get("port")
            port_text = str(port) if port not in (None, "") else "-"
            return {
                "proto": proto,
                "tls": tls_type,
                "transport": transport,
                "address": address,
                "port": port_text,
            }
        except Exception:
            return {
                "proto": "UNKNOWN",
                "tls": "-",
                "transport": "-",
                "address": "-",
                "port": "-",
            }

    def update_empty_state(self):
        self.emptyState.setVisible(len(self.profiles) == 0)

    def on_table_selection_changed(self):
        if self.is_profile_ui_locked():
            return
        row = self.table.currentRow()
        if row >= 0:
            self.activeProfileValue.setText(self.profiles[row]["name"])

    def on_table_double_clicked(self, row, _col):
        if self.is_profile_ui_locked():
            self.show_profile_lock_hint()
            return
        if row >= 0:
            self.table.selectRow(row)
            self.select_config()

    def on_profile_combo_changed(self, index):
        return

    def on_system_proxy_toggled(self, checked=False):
        if bool(checked):
            self.on_set_proxy_clicked()
        else:
            self.on_clear_proxy_clicked()

    def _invoke_ui_callable(self, fn):
        try:
            fn()
        except Exception as e:
            self.log(f"[UI] callback failed: {e}")

    def is_profile_ui_locked(self):
        return bool(self.tunnel_enabled or self.tunnel_transition)

    def _request_admin_restart(self):
        if is_running_as_admin():
            return True
        try:
            candidates = []
            argv0 = os.path.abspath(str(sys.argv[0] or "")).strip()
            runtime_exe = os.path.abspath(str(sys.executable or "")).strip()
            app_exe_name = os.path.splitext(os.path.basename(str(__file__ or "V2rayX.py")))[0] + ".exe"
            app_exe_path = os.path.join(BASE_DIR, app_exe_name)

            def _is_python_host(path_text):
                name = os.path.basename(str(path_text or "")).strip().lower()
                return name in {"python.exe", "pythonw.exe"}

            # Always prefer relaunching the current executable when possible.
            if os.path.exists(app_exe_path):
                candidates.append((app_exe_path, list(sys.argv[1:])))

            if argv0.lower().endswith(".exe") and os.path.exists(argv0) and not _is_python_host(argv0):
                candidates.append((argv0, list(sys.argv[1:])))

            # Fallback to runtime executable for source-mode runs.
            if runtime_exe and not _is_python_host(runtime_exe) and (not candidates or runtime_exe not in {c[0] for c in candidates}):
                if getattr(sys, "frozen", False):
                    candidates.append((runtime_exe, list(sys.argv[1:])))
                else:
                    candidates.append((runtime_exe, [os.path.abspath(__file__)] + list(sys.argv[1:])))

            if not candidates:
                if getattr(sys, "frozen", False):
                    if runtime_exe:
                        candidates.append((runtime_exe, list(sys.argv[1:])))
                else:
                    candidates.append((os.path.abspath(str(sys.executable or "python")), [os.path.abspath(__file__)] + list(sys.argv[1:])))

            def shell_execute_runas(exe_path, args):
                if not exe_path or not os.path.exists(exe_path):
                    return 2
                params = subprocess.list2cmdline(args)
                workdir = os.path.dirname(exe_path) or BASE_DIR
                rc = ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    exe_path,
                    params,
                    workdir,
                    1
                )
                return int(rc)

            for exe_path, args in candidates:
                rc = shell_execute_runas(exe_path, args)
                if rc > 32:
                    self.log(f"[Admin] elevation accepted via: {exe_path}")
                    self._exit_requested = True
                    QTimer.singleShot(50, self.close)
                    return True
                self.log(f"[Admin] elevation attempt failed (code={rc}) via: {exe_path}")

            # Fallback for environments where ShellExecuteW on current process path is unreliable.
            def _ps_quote(text):
                return "'" + str(text or "").replace("'", "''") + "'"

            for exe_path, args in candidates:
                if not exe_path or not os.path.exists(exe_path):
                    continue
                arg_line = subprocess.list2cmdline(args)
                cmd = (
                    f"$p={_ps_quote(exe_path)}; "
                    f"$a={_ps_quote(arg_line)}; "
                    "Start-Process -FilePath $p -ArgumentList $a -Verb RunAs"
                )
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", cmd],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                    creationflags=NO_WINDOW_FLAG,
                )
                if result.returncode == 0:
                    self.log(f"[Admin] elevation accepted via PowerShell: {exe_path}")
                    self._exit_requested = True
                    QTimer.singleShot(50, self.close)
                    return True
                err = (result.stderr or result.stdout or "").strip()
                if err:
                    self.log(f"[Admin] PowerShell elevation failed: {err}")

            self.log("[Admin] elevation request was not accepted")
            return False
        except Exception as e:
            self.log(f"[Admin] elevation request failed: {e}")
            return False

    def show_profile_lock_hint(self):
        now = time.time()
        if (now - float(self._profile_lock_tip_ts)) < 0.7:
            return
        self._profile_lock_tip_ts = now
        QToolTip.showText(QCursor.pos(), "To change the profile, first disable tunnel mode.", self.table.viewport())

    def eventFilter(self, obj, event):
        table = getattr(self, "table", None)
        viewport = table.viewport() if table is not None else None
        if obj in {table, viewport}:
            if self.is_profile_ui_locked():
                t = event.type()
                hover_types = {QEvent.Enter, QEvent.MouseMove, QEvent.ToolTip}
                block_types = {
                    QEvent.MouseButtonPress,
                    QEvent.MouseButtonDblClick,
                    QEvent.MouseButtonRelease,
                    QEvent.Wheel,
                    QEvent.ContextMenu,
                    QEvent.KeyPress,
                }
                if t in hover_types:
                    self.show_profile_lock_hint()
                if t in block_types:
                    self.show_profile_lock_hint()
                    return True
        return super().eventFilter(obj, event)

    def _run_powershell(self, command):
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            creationflags=NO_WINDOW_FLAG,
        )
        out = (result.stdout or "").strip()
        err = (result.stderr or "").strip()
        if result.returncode != 0:
            raise RuntimeError(err or out or f"PowerShell exit code {result.returncode}")
        return out

    def _detect_uplink_interface(self):
        cmd = (
            "$routes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | "
            "Where-Object { $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric; "
            "foreach ($r in $routes) { "
            "$ad = Get-NetAdapter -InterfaceAlias $r.InterfaceAlias -ErrorAction SilentlyContinue; "
            "if ($ad -and $ad.Status -eq 'Up') { $r.InterfaceAlias; break } "
            "}"
        )
        return self._run_powershell(cmd)

    def _check_tunnel_upstream_ready(self, socks_port=10808, attempts=2):
        if not shutil.which("curl"):
            return False, "curl was not found in PATH"

        urls = [
            "https://cp.cloudflare.com/generate_204",
            "https://www.gstatic.com/generate_204",
        ]
        last_error = "unknown"
        for _ in range(max(1, int(attempts))):
            for url in urls:
                result = subprocess.run(
                    [
                        "curl",
                        "--socks5-hostname", f"127.0.0.1:{int(socks_port)}",
                        "--connect-timeout", "5",
                        "--max-time", "10",
                        "--silent",
                        "--show-error",
                        "-o", "NUL",
                        "-L",
                        url,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                    creationflags=NO_WINDOW_FLAG,
                )
                if result.returncode == 0:
                    return True, ""
                last_error = (result.stderr or f"curl exit code {result.returncode}").strip()
            time.sleep(0.35)
        return False, last_error

    def _detect_tun_ifindex(self):
        tun_name = str(self.settings.get("tunnel", {}).get("name", "xray0") or "xray0").strip() or "xray0"
        cmd = (
            f"Get-NetIPInterface -AddressFamily IPv4 | "
            f"Where-Object {{ $_.InterfaceAlias -like '{tun_name}*' }} | "
            "Sort-Object InterfaceMetric | Select-Object -First 1 -ExpandProperty ifIndex"
        )
        out = self._run_powershell(cmd)
        return int(out)

    def _has_tunnel_default_route(self, ifindex):
        cmd = (
            "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | "
            f"Where-Object {{ $_.InterfaceIndex -eq {int(ifindex)} -and $_.NextHop -eq '0.0.0.0' }} | "
            "Select-Object -First 1 -ExpandProperty InterfaceIndex"
        )
        out = self._run_powershell(cmd)
        return str(out).strip() != ""

    def _apply_tunnel_routes(self):
        ifindex = self._detect_tun_ifindex()
        subprocess.run(
            ["route", "delete", "0.0.0.0", "mask", "0.0.0.0", "0.0.0.0", "if", str(ifindex)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            creationflags=NO_WINDOW_FLAG,
        )
        result = subprocess.run(
            ["route", "add", "0.0.0.0", "mask", "0.0.0.0", "0.0.0.0", "if", str(ifindex), "metric", "3"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            creationflags=NO_WINDOW_FLAG,
        )
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(err or "failed to add default route to tunnel")
        self.tunnel_route_ifindex = ifindex
        self.log(f"[Tunnel] default route moved to tunnel (ifIndex={ifindex})")

    def _remove_tunnel_routes(self):
        if not self.tunnel_route_ifindex:
            return
        ifindex = int(self.tunnel_route_ifindex)
        subprocess.run(
            ["route", "delete", "0.0.0.0", "mask", "0.0.0.0", "0.0.0.0", "if", str(ifindex)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            creationflags=NO_WINDOW_FLAG,
        )
        self.log(f"[Tunnel] default route removed from tunnel (ifIndex={ifindex})")
        self.tunnel_route_ifindex = None

    def check_tunnel_uplink_change(self):
        if not self.tunnel_enabled or self.tunnel_transition:
            return
        if self.tunnel_probe_running:
            return

        self.tunnel_probe_running = True

        def probe():
            try:
                uplink = self._detect_uplink_interface()
                tun_ifindex = None
                route_ok = False
                try:
                    tun_ifindex = self._detect_tun_ifindex()
                    route_ok = self._has_tunnel_default_route(tun_ifindex)
                except Exception:
                    tun_ifindex = None
                    route_ok = False
                self.ui_call_signal.emit(lambda: self._on_tunnel_uplink_probe_result(uplink, tun_ifindex, route_ok, None))
            except Exception as e:
                self.ui_call_signal.emit(lambda: self._on_tunnel_uplink_probe_result("", None, False, str(e)))

        threading.Thread(target=probe, daemon=True).start()

    def _heal_tunnel_route_if_needed(self, detected_ifindex, route_ok):
        if self.tunnel_transition or not self.tunnel_enabled:
            return
        if self.tunnel_heal_running:
            return

        current_ifindex = int(detected_ifindex) if detected_ifindex else None
        if current_ifindex is None:
            return
        if self.tunnel_route_ifindex and current_ifindex != int(self.tunnel_route_ifindex):
            self.log(f"[Tunnel] adapter reindexed: {self.tunnel_route_ifindex} -> {current_ifindex}")
            route_ok = False
        if route_ok:
            self.tunnel_route_ifindex = current_ifindex
            return

        self.tunnel_heal_running = True
        self._log_tunnel_once("route_missing", "[Tunnel] default route missing. Reapplying tunnel route...", cooldown=12.0)

        def worker():
            try:
                self._apply_tunnel_routes()
                self.log("[Tunnel] route self-heal succeeded")
            except Exception as e:
                self.log(f"[Tunnel] route self-heal failed: {e}")
            finally:
                self.ui_call_signal.emit(lambda: setattr(self, "tunnel_heal_running", False))

        self._enqueue_xray_task(worker)

    def _on_tunnel_uplink_probe_result(self, detected_uplink, detected_ifindex, route_ok, error_text):
        self.tunnel_probe_running = False
        if not self.tunnel_enabled or self.tunnel_transition:
            return
        if error_text:
            self._log_tunnel_once("probe_failed", f"[Tunnel] uplink probe failed: {error_text}", cooldown=12.0)
            return

        new_uplink = str(detected_uplink or "").strip()
        if not new_uplink:
            return
        old_uplink = str(self.tunnel_uplink_interface or "").strip()
        if new_uplink == old_uplink:
            self._heal_tunnel_route_if_needed(detected_ifindex, bool(route_ok))
            return

        self.log(f"[Tunnel] uplink changed: {old_uplink or '-'} -> {new_uplink}")
        self.tunnel_transition = True
        self.update_runtime_status()

        def worker():
            old_value = old_uplink
            try:
                raw = self.base_config or build_bootstrap_config()
                self._remove_tunnel_routes()
                self.tunnel_uplink_interface = new_uplink
                runtime = self.compose_runtime_config(raw, force_tunnel=True)
                write_config(runtime)
                ok = start_xray(self.log, verify_start=True, verify_seconds=2.5)
                upstream_ok = False
                upstream_error = "unknown"
                final_base = None
                final_sig = None
                if ok:
                    upstream_ok, upstream_error = self._check_tunnel_upstream_ready(socks_port=10808, attempts=2)

                if ok and upstream_ok:
                    try:
                        self._apply_tunnel_routes()
                        final_base = raw
                        final_sig = config_signature(runtime)
                        self.log(f"[Tunnel] uplink rebind succeeded: {new_uplink}")
                    except Exception as route_error:
                        self.log(f"[Tunnel] uplink rebind route error: {route_error}")
                elif ok and not upstream_ok:
                    self.log(f"[Tunnel] uplink rebind upstream failed: {upstream_error}")
                    self.log("[Tunnel] keeping previous uplink and retrying old path...")
                    try:
                        self.tunnel_uplink_interface = old_value
                        fallback = self.compose_runtime_config(raw, force_tunnel=True)
                        write_config(fallback)
                        fallback_ok = start_xray(self.log, verify_start=True, verify_seconds=2.0)
                        if fallback_ok:
                            self._apply_tunnel_routes()
                            final_base = raw
                            final_sig = config_signature(fallback)
                            self.log("[Tunnel] uplink restored after failed rebind")
                        else:
                            self.log("[Tunnel] failed to restore uplink after failed rebind")
                    except Exception as restore_error:
                        self.log(f"[Tunnel] uplink restore failed: {restore_error}")
                else:
                    self.log("[Tunnel] uplink rebind failed, restoring previous interface...")
                    try:
                        self.tunnel_uplink_interface = old_value
                        fallback = self.compose_runtime_config(raw, force_tunnel=True)
                        write_config(fallback)
                        fallback_ok = start_xray(self.log, verify_start=True, verify_seconds=2.0)
                        if fallback_ok:
                            self._apply_tunnel_routes()
                            final_base = raw
                            final_sig = config_signature(fallback)
                            self.log("[Tunnel] uplink restored to previous interface")
                        else:
                            self.log("[Tunnel] failed to restore previous interface")
                    except Exception as restore_error:
                        self.log(f"[Tunnel] uplink restore failed: {restore_error}")

                def finish():
                    self.base_config = final_base
                    self.active_config_signature = final_sig
                    self.tunnel_transition = False
                    self.update_runtime_status()

                self.ui_call_signal.emit(finish)
            except Exception as e:
                self.log(f"[Tunnel] uplink rebind exception: {e}")
                self.tunnel_transition = False
                self.ui_call_signal.emit(self.update_runtime_status)

        self._enqueue_xray_task(worker)

    def _set_tunnel_enabled(self, enabled, persist=True):
        self.tunnel_enabled = bool(enabled)
        tunnel_settings = self.settings.setdefault("tunnel", {})
        tunnel_settings["enabled"] = self.tunnel_enabled
        if persist:
            save_settings(self.settings)

    def on_system_tunnel_toggled(self, checked=False):
        if self.tunnel_transition:
            return
        if bool(checked):
            self.enable_system_tunnel()
        else:
            self.disable_system_tunnel()

    def start_core_manual(self):
        def worker():
            try:
                config = self.base_config or build_bootstrap_config()
                runtime = self.compose_runtime_config(config)
                write_config(runtime)
                self.log("[Xray] manual start requested")
                ok = start_xray(self.log, verify_start=True, verify_seconds=2.0)
                def finish():
                    if ok:
                        self.base_config = config
                        self.active_config_signature = config_signature(runtime)
                        self.log("[Xray] manual start successful")
                    else:
                        self.log("[Xray] manual start failed")
                    self.update_runtime_status()
                QTimer.singleShot(0, finish)
            except Exception as e:
                QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Error", str(e)))
        self._enqueue_xray_task(worker)

    def stop_core_manual(self):
        self._remove_tunnel_routes()
        stop_xray_process(self.log)
        self.update_runtime_status()
        self.show_toast("Xray core stopped")

    def reload_core_manual(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.profiles):
            QMessageBox.warning(self, "Reload", "Please select a profile first.")
            return

        link = self.profiles[row]["link"]
        profile_name = self.profiles[row]["name"]

        def worker():
            try:
                self.log("[Reload] rebuilding config...")
                raw_config = self.build_config_from_link(link, apply_runtime_settings=False)
                config = self.compose_runtime_config(raw_config)
                write_config(config)
                self.log("[Reload] config written. Restarting Xray...")
                ok = start_xray(self.log, verify_start=True, verify_seconds=2.0)
                def finish():
                    if ok:
                        self.base_config = raw_config
                        self.active_config_signature = config_signature(config)
                        self.log(f"[Reload] xray restarted with: {profile_name}")
                        if self.settings["proxy"]["auto_set_system_proxy_on_connect"]:
                            self.on_set_proxy_clicked()
                    else:
                        self.log("[Reload] xray restart failed")
                    self.update_runtime_status()
                QTimer.singleShot(0, finish)
            except Exception as e:
                QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Reload Error", str(e)))

        self._enqueue_xray_task(worker)

    def disconnect_core(self):
        self._remove_tunnel_routes()
        stop_xray_process(self.log)
        self.update_runtime_status()
        self.show_toast("Core disconnected")

    def compose_runtime_config(self, base_config, force_tunnel=None):
        runtime_settings = json.loads(json.dumps(self.settings))
        tunnel_on = self.tunnel_enabled if force_tunnel is None else bool(force_tunnel)
        if tunnel_on:
            runtime_settings.setdefault("routing", {})["mode"] = "proxy_all"
            runtime_settings.setdefault("tunnel", {})["uplink_interface"] = self.tunnel_uplink_interface
        cfg = apply_settings_to_config(base_config, runtime_settings)
        if tunnel_on:
            cfg = apply_tunnel_to_config(cfg, runtime_settings)
        return cfg

    def build_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        card = QFrame()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(12, 12, 12, 12)
        card_layout.setSpacing(8)

        title = QLabel("Settings")
        title.setStyleSheet("font-size:16px;font-weight:700;")
        card_layout.addWidget(title)

        self.settings_tabs = QTabWidget()

        core_page = QWidget()
        core_layout = QVBoxLayout(core_page)
        self.st_core_autostart = QCheckBox("Auto-start Xray on app launch")
        self.st_core_restart_on_select = QCheckBox("Restart/start core when selecting a new profile")
        core_layout.addWidget(self.st_core_autostart)
        core_layout.addWidget(self.st_core_restart_on_select)
        core_layout.addStretch(1)
        self.settings_tabs.addTab(core_page, "Core")

        proxy_page = QWidget()
        proxy_layout = QVBoxLayout(proxy_page)
        self.st_proxy_auto_on_connect = QCheckBox("Auto-set system proxy after successful connect")
        self.st_proxy_on_launch = QCheckBox("Set system proxy on app launch")
        proxy_layout.addWidget(self.st_proxy_auto_on_connect)
        proxy_layout.addWidget(self.st_proxy_on_launch)
        proxy_layout.addStretch(1)
        self.settings_tabs.addTab(proxy_page, "Proxy")

        routing_page = QWidget()
        routing_layout = QVBoxLayout(routing_page)
        self.st_route_mode = QComboBox()
        self.st_route_mode.addItems(["bypass_ir_cn", "proxy_all", "direct_all"])
        self.st_route_mode.setToolTip("bypass_ir_cn=direct for IR/CN, proxy_all=all through proxy, direct_all=all direct")
        self.st_route_bypass_lan = QCheckBox("Bypass LAN/Private networks")
        self.st_route_direct_domains = QPlainTextEdit()
        self.st_route_direct_domains.setPlaceholderText("Direct domains, one per line (example.com)")
        self.st_route_proxy_domains = QPlainTextEdit()
        self.st_route_proxy_domains.setPlaceholderText("Proxy domains, one per line")
        self.st_route_direct_ips = QPlainTextEdit()
        self.st_route_direct_ips.setPlaceholderText("Direct IP/CIDR, one per line (1.1.1.1 or 10.0.0.0/8)")
        routing_layout.addWidget(QLabel("Route Mode"))
        routing_layout.addWidget(self.st_route_mode)
        routing_layout.addWidget(self.st_route_bypass_lan)
        routing_layout.addWidget(QLabel("Direct Domains"))
        routing_layout.addWidget(self.st_route_direct_domains)
        routing_layout.addWidget(QLabel("Proxy Domains"))
        routing_layout.addWidget(self.st_route_proxy_domains)
        routing_layout.addWidget(QLabel("Direct IP/CIDR"))
        routing_layout.addWidget(self.st_route_direct_ips)
        self.settings_tabs.addTab(routing_page, "Routing")

        dns_page = QWidget()
        dns_layout = QVBoxLayout(dns_page)
        self.st_dns_enabled = QCheckBox("Enable custom DNS")
        self.st_dns_query_strategy = QComboBox()
        self.st_dns_query_strategy.addItems(["UseIP", "UseIPv4", "UseIPv6"])
        self.st_dns_servers = QPlainTextEdit()
        self.st_dns_servers.setPlaceholderText("DNS servers, one per line")
        dns_layout.addWidget(self.st_dns_enabled)
        dns_layout.addWidget(QLabel("Query Strategy"))
        dns_layout.addWidget(self.st_dns_query_strategy)
        dns_layout.addWidget(QLabel("DNS Servers"))
        dns_layout.addWidget(self.st_dns_servers)
        self.settings_tabs.addTab(dns_page, "DNS")

        adv_page = QWidget()
        adv_layout = QFormLayout(adv_page)
        self.st_adv_allow_insecure = QCheckBox("Allow insecure TLS")
        self.st_adv_suppress_noisy_logs = QCheckBox("Suppress noisy/deprecated core logs")
        self.st_adv_ping_max = QSpinBox()
        self.st_adv_ping_max.setRange(3, 90)
        self.st_adv_speed_max = QSpinBox()
        self.st_adv_speed_max.setRange(3, 180)
        self.st_adv_log_limit = QSpinBox()
        self.st_adv_log_limit.setRange(300, 10000)
        self.st_adv_log_limit.setSingleStep(100)
        adv_layout.addRow("TLS", self.st_adv_allow_insecure)
        adv_layout.addRow("Core Logs", self.st_adv_suppress_noisy_logs)
        adv_layout.addRow("Ping Timeout (s)", self.st_adv_ping_max)
        adv_layout.addRow("Speed Timeout (s)", self.st_adv_speed_max)
        adv_layout.addRow("Max Log Entries", self.st_adv_log_limit)
        self.settings_tabs.addTab(adv_page, "Advanced")

        card_layout.addWidget(self.settings_tabs, 1)

        save_row = QHBoxLayout()
        save_row.addStretch(1)
        self.settings_save_btn = QPushButton("Save Settings")
        self.settings_save_btn.setObjectName("Primary")
        self.settings_save_btn.clicked.connect(self.save_settings_page)
        save_row.addWidget(self.settings_save_btn)
        card_layout.addLayout(save_row)

        layout.addWidget(card, 1)
        self.load_settings_page_values()
        return page

    def load_settings_page_values(self):
        if not hasattr(self, "settings_tabs"):
            return
        self.st_core_autostart.setChecked(self.settings["core"]["autostart_core"])
        self.st_core_restart_on_select.setChecked(self.settings["core"]["restart_on_select"])

        self.st_proxy_auto_on_connect.setChecked(self.settings["proxy"]["auto_set_system_proxy_on_connect"])
        self.st_proxy_on_launch.setChecked(self.settings["proxy"]["set_proxy_on_app_launch"])

        self.st_route_mode.setCurrentText(self.settings["routing"]["mode"])
        self.st_route_bypass_lan.setChecked(self.settings["routing"]["bypass_lan"])
        self.st_route_direct_domains.setPlainText(self.settings["routing"]["direct_domains"])
        self.st_route_proxy_domains.setPlainText(self.settings["routing"]["proxy_domains"])
        self.st_route_direct_ips.setPlainText(self.settings["routing"]["direct_ips"])

        self.st_dns_enabled.setChecked(self.settings["dns"]["enabled"])
        self.st_dns_query_strategy.setCurrentText(self.settings["dns"]["query_strategy"])
        self.st_dns_servers.setPlainText(self.settings["dns"]["servers"])

        self.st_adv_allow_insecure.setChecked(self.settings["advanced"]["allow_insecure_tls"])
        self.st_adv_suppress_noisy_logs.setChecked(bool(self.settings["advanced"].get("suppress_noisy_core_logs", True)))
        self.st_adv_ping_max.setValue(int(self.settings["advanced"]["ping_max_time"]))
        self.st_adv_speed_max.setValue(int(self.settings["advanced"]["speed_max_time"]))
        self.st_adv_log_limit.setValue(int(self.settings["advanced"]["log_limit"]))

    def save_settings_page(self):
        self.settings["core"]["autostart_core"] = self.st_core_autostart.isChecked()
        self.settings["core"]["restart_on_select"] = self.st_core_restart_on_select.isChecked()

        self.settings["proxy"]["auto_set_system_proxy_on_connect"] = self.st_proxy_auto_on_connect.isChecked()
        self.settings["proxy"]["set_proxy_on_app_launch"] = self.st_proxy_on_launch.isChecked()

        self.settings["routing"]["mode"] = self.st_route_mode.currentText()
        self.settings["routing"]["bypass_lan"] = self.st_route_bypass_lan.isChecked()
        self.settings["routing"]["direct_domains"] = self.st_route_direct_domains.toPlainText().strip()
        self.settings["routing"]["proxy_domains"] = self.st_route_proxy_domains.toPlainText().strip()
        self.settings["routing"]["direct_ips"] = self.st_route_direct_ips.toPlainText().strip()

        self.settings["dns"]["enabled"] = self.st_dns_enabled.isChecked()
        self.settings["dns"]["servers"] = self.st_dns_servers.toPlainText().strip()
        self.settings["dns"]["query_strategy"] = self.st_dns_query_strategy.currentText()

        self.settings["advanced"]["allow_insecure_tls"] = self.st_adv_allow_insecure.isChecked()
        self.settings["advanced"]["suppress_noisy_core_logs"] = self.st_adv_suppress_noisy_logs.isChecked()
        self.settings["advanced"]["ping_max_time"] = self.st_adv_ping_max.value()
        self.settings["advanced"]["speed_max_time"] = self.st_adv_speed_max.value()
        self.settings["advanced"]["log_limit"] = self.st_adv_log_limit.value()

        self.max_log_entries = int(self.settings["advanced"]["log_limit"])
        save_settings(self.settings)
        self.log("[Settings] saved")
        self.show_toast("Settings saved")

        if self.settings["proxy"]["set_proxy_on_app_launch"]:
            self.on_set_proxy_clicked()

        row = self.table.currentRow()
        if row >= 0 and self.settings["core"]["restart_on_select"]:
            self.log("[Settings] applying updated runtime settings...")
            self.select_config()

    def dragEnterEvent(self, event):
        if event.mimeData().hasText():
            event.acceptProposedAction()
            return
        event.ignore()

    def dropEvent(self, event):
        text = event.mimeData().text()
        if text:
            QApplication.clipboard().setText(text)
            self.handle_paste()
        event.acceptProposedAction()

    def update_runtime_status(self):
        running = bool(xray_process and xray_process.poll() is None)
        if running:
            self.coreStatusValue.setText("Running")
            self.coreStatusValue.setStyleSheet("color:#22c55e;font-size:15px;font-weight:700;")
        else:
            self.coreStatusValue.setText("Stopped")
            self.coreStatusValue.setStyleSheet("color:#ef4444;font-size:15px;font-weight:700;")
        self.startCoreBtn.setEnabled(not running)
        self.stopCoreBtn.setEnabled(running)

        try:
            enabled, server, is_expected = get_system_proxy_status()
            if enabled and is_expected:
                self.proxyStatusValue.setText(f"Active ({server})")
                self.proxyStatusValue.setStyleSheet("color:#22c55e;font-size:15px;font-weight:700;")
            elif enabled:
                show_server = server if server else "unknown"
                self.proxyStatusValue.setText(f"Enabled ({show_server})")
                self.proxyStatusValue.setStyleSheet("color:#eab308;font-size:15px;font-weight:700;")
            else:
                self.proxyStatusValue.setText("Disabled")
                self.proxyStatusValue.setStyleSheet("color:#ef4444;font-size:15px;font-weight:700;")

            self.systemProxyToggle.blockSignals(True)
            self.systemProxyToggle.setChecked(enabled and is_expected)
            self.systemProxyToggle.blockSignals(False)
        except Exception as e:
            self.proxyStatusValue.setText("Status Error")
            self.proxyStatusValue.setStyleSheet("color:#ef4444;font-size:15px;font-weight:700;")
            self.log(f"[Proxy] status read failed: {e}")
            enabled = False
            is_expected = False

        if enabled and is_expected:
            self.startCoreBtn.setEnabled(False)
            self.stopCoreBtn.setEnabled(False)

        if self.tunnel_transition:
            self.tunnelStatusValue.setText("Switching...")
            self.tunnelStatusValue.setStyleSheet("color:#eab308;font-size:15px;font-weight:700;")
        elif self.tunnel_enabled:
            self.tunnelStatusValue.setText("Enabled")
            self.tunnelStatusValue.setStyleSheet("color:#22c55e;font-size:15px;font-weight:700;")
        else:
            self.tunnelStatusValue.setText("Disabled")
            self.tunnelStatusValue.setStyleSheet("color:#ef4444;font-size:15px;font-weight:700;")

        # Enable proxy toggle only when a profile exists and one is selected
        has_profiles = len(self.profiles) > 0
        has_selection = self.table.currentRow() >= 0 if hasattr(self, "table") else False
        can_use_proxy = has_profiles and has_selection
        can_use_tunnel = has_profiles and has_selection
        self.systemProxyToggle.setEnabled(can_use_proxy)
        self.systemTunnelToggle.setEnabled(can_use_tunnel and not self.tunnel_transition)
        self.systemTunnelToggle.blockSignals(True)
        self.systemTunnelToggle.setChecked(self.tunnel_enabled)
        self.systemTunnelToggle.blockSignals(False)
        if self.is_profile_ui_locked():
            self.table.viewport().setCursor(Qt.ForbiddenCursor)
        else:
            self.table.viewport().setCursor(Qt.ArrowCursor)
        if hasattr(self, "tray_set_proxy_action"):
            self.tray_set_proxy_action.setEnabled(can_use_proxy)
        if hasattr(self, "tray_clear_proxy_action"):
            self.tray_clear_proxy_action.setEnabled(can_use_proxy)

        row = self.table.currentRow()
        if row >= 0:
            ping_item = self.table.item(row, self.COL_PING)
            speed_item = self.table.item(row, self.COL_SPEED)
            ping_text = ping_item.text() if ping_item else "-"
            speed_text = speed_item.text() if speed_item else "-"
            self.netQualityValue.setText(f"{ping_text} | {speed_text}")
        else:
            self.netQualityValue.setText("-")

    def on_set_proxy_clicked(self):
        if not self.profiles:
            QMessageBox.warning(self, "Proxy", "No profiles found. Add a profile first.")
            return
        if self.table.currentRow() < 0:
            QMessageBox.warning(self, "Proxy", "Please select a profile first.")
            return
        try:
            set_system_proxy()
            self.log("[Proxy] system proxy set")
            self.show_toast("System proxy enabled")
        except Exception as e:
            QMessageBox.warning(self, "Proxy Error", str(e))
            self.log(f"[Proxy] set failed: {e}")
        finally:
            self.update_runtime_status()

    def on_clear_proxy_clicked(self):
        try:
            clear_system_proxy()
            self.log("[Proxy] system proxy cleared")
            self.show_toast("System proxy disabled")
        except Exception as e:
            QMessageBox.warning(self, "Proxy Error", str(e))
            self.log(f"[Proxy] clear failed: {e}")
        finally:
            self.update_runtime_status()

    def enable_system_tunnel(self):
        if self.tunnel_transition:
            return
        if not self.profiles:
            QMessageBox.warning(self, "Tunnel", "No profiles found. Add a profile first.")
            self.update_runtime_status()
            return

        row = self.table.currentRow()
        if row < 0 or row >= len(self.profiles):
            QMessageBox.warning(self, "Tunnel", "Please select a profile first.")
            self.update_runtime_status()
            return

        if not is_running_as_admin():
            self.log("[Tunnel] admin privileges required. Requesting elevation...")
            restarted = self._request_admin_restart()
            if not restarted:
                QMessageBox.information(
                    self,
                    "Tunnel",
                    "Administrator permission was not granted.\nTunnel remains disabled."
                )
            self._set_tunnel_enabled(False, persist=False)
            self.update_runtime_status()
            return
        if not os.path.exists(WINTUN_PATH):
            QMessageBox.warning(self, "Tunnel", f"wintun.dll was not found:\n{WINTUN_PATH}")
            self.update_runtime_status()
            return

        link = self.profiles[row]["link"]
        profile_name = self.profiles[row]["name"]
        self.tunnel_transition = True
        self._set_tunnel_enabled(True, persist=False)
        self.update_runtime_status()

        def worker():
            try:
                try:
                    detected_uplink = self._detect_uplink_interface()
                    self.tunnel_uplink_interface = detected_uplink
                    if self.tunnel_uplink_interface:
                        self.log(f"[Tunnel] uplink interface: {self.tunnel_uplink_interface}")
                except Exception as uplink_err:
                    self._set_tunnel_enabled(False, persist=True)
                    self.tunnel_transition = False
                    self.ui_call_signal.emit(lambda: QMessageBox.warning(self, "Tunnel Error", f"Failed to detect uplink interface:\n{uplink_err}"))
                    self.ui_call_signal.emit(self.update_runtime_status)
                    return

                self.log("[Tunnel] enabling tunnel mode...")
                raw_config = self.build_config_from_link(link, apply_runtime_settings=False)
                runtime = self.compose_runtime_config(raw_config, force_tunnel=True)
                write_config(runtime)
                ok = start_xray(self.log, verify_start=True, verify_seconds=3.5)
                upstream_ok = False
                upstream_error = "unknown"
                warn_text = ""
                final_enabled = False
                final_base = None
                final_sig = None
                if ok:
                    upstream_ok, upstream_error = self._check_tunnel_upstream_ready(socks_port=10808, attempts=2)

                if ok and upstream_ok:
                    try:
                        self._apply_tunnel_routes()
                        final_enabled = True
                        final_base = raw_config
                        final_sig = config_signature(runtime)
                        self.log(f"[Tunnel] enabled with profile: {profile_name}")
                    except Exception as route_error:
                        self.log(f"[Tunnel] route setup failed: {route_error}")
                        self.log("[Tunnel] reverting to normal mode...")
                        fallback = self.compose_runtime_config(raw_config, force_tunnel=False)
                        write_config(fallback)
                        fallback_ok = start_xray(self.log, verify_start=True, verify_seconds=2.0)
                        if fallback_ok:
                            final_enabled = False
                            final_base = raw_config
                            final_sig = config_signature(fallback)
                            self.log("[Tunnel] fallback to normal mode succeeded")
                        else:
                            self.log("[Tunnel] fallback to normal mode failed")
                elif ok and not upstream_ok:
                    self.log(f"[Tunnel] upstream check failed before routing: {upstream_error}")
                    self.log("[Tunnel] reverting to normal mode...")
                    fallback = self.compose_runtime_config(raw_config, force_tunnel=False)
                    write_config(fallback)
                    fallback_ok = start_xray(self.log, verify_start=True, verify_seconds=2.0)
                    if fallback_ok:
                        final_enabled = False
                        final_base = raw_config
                        final_sig = config_signature(fallback)
                        warn_text = f"Tunnel upstream is unreachable:\n{upstream_error}"
                        self.log("[Tunnel] fallback to normal mode succeeded")
                    else:
                        self.log("[Tunnel] fallback to normal mode failed")
                else:
                    self.log("[Tunnel] enable failed. Falling back to normal mode...")
                    fallback = self.compose_runtime_config(raw_config, force_tunnel=False)
                    write_config(fallback)
                    fallback_ok = start_xray(self.log, verify_start=True, verify_seconds=2.0)
                    if fallback_ok:
                        final_enabled = False
                        final_base = raw_config
                        final_sig = config_signature(fallback)
                        self.log("[Tunnel] fallback to normal mode succeeded")
                    else:
                        self.log("[Tunnel] fallback to normal mode failed")

                self._set_tunnel_enabled(final_enabled, persist=True)

                def finish():
                    self.base_config = final_base
                    self.active_config_signature = final_sig
                    if final_enabled:
                        self.show_toast("System tunnel enabled")
                    if warn_text:
                        QMessageBox.warning(self, "Tunnel", warn_text)
                    self.tunnel_transition = False
                    self.update_runtime_status()

                self.ui_call_signal.emit(finish)
            except Exception as e:
                self._set_tunnel_enabled(False, persist=True)
                self._remove_tunnel_routes()
                self.tunnel_transition = False
                self.ui_call_signal.emit(lambda: QMessageBox.warning(self, "Tunnel Error", str(e)))
                self.ui_call_signal.emit(self.update_runtime_status)

        self._enqueue_xray_task(worker)

    def disable_system_tunnel(self):
        if self.tunnel_transition:
            return
        if not self.tunnel_enabled:
            self.update_runtime_status()
            return

        row = self.table.currentRow()
        try:
            if row >= 0 and row < len(self.profiles):
                link = self.profiles[row]["link"]
                profile_name = self.profiles[row]["name"]
                raw_fallback = self.build_config_from_link(link, apply_runtime_settings=False)
            elif self.base_config:
                raw_fallback = self.base_config
                profile_name = "current config"
            else:
                raw_fallback = build_bootstrap_config()
                profile_name = "bootstrap"
        except Exception as e:
            QMessageBox.warning(self, "Tunnel Error", str(e))
            self.update_runtime_status()
            return

        self.tunnel_transition = True
        self._set_tunnel_enabled(False, persist=False)
        self.update_runtime_status()

        def worker():
            try:
                self.log("[Tunnel] disabling tunnel mode...")
                self._remove_tunnel_routes()
                runtime = self.compose_runtime_config(raw_fallback, force_tunnel=False)
                write_config(runtime)
                ok = start_xray(self.log, verify_start=True, verify_seconds=2.0)

                def finish():
                    if ok:
                        self._set_tunnel_enabled(False, persist=True)
                        self.base_config = raw_fallback
                        self.active_config_signature = config_signature(runtime)
                        self.log(f"[Tunnel] disabled. Active: {profile_name}")
                        self.show_toast("System tunnel disabled")
                    else:
                        self.log("[Tunnel] disable failed. Keeping tunnel state unchanged.")
                        self._set_tunnel_enabled(True, persist=False)
                        try:
                            self._apply_tunnel_routes()
                        except Exception as route_error:
                            self.log(f"[Tunnel] failed to restore tunnel route: {route_error}")
                    self.tunnel_transition = False
                    self.update_runtime_status()

                self.ui_call_signal.emit(finish)
            except Exception as e:
                self._set_tunnel_enabled(True, persist=False)
                self.tunnel_transition = False
                self.ui_call_signal.emit(lambda: QMessageBox.warning(self, "Tunnel Error", str(e)))
                self.ui_call_signal.emit(self.update_runtime_status)

        self._enqueue_xray_task(worker)

    def autostart_xray(self):
        try:
            config = build_bootstrap_config()
            write_config(config)
            self.log("[Xray] bootstrap config created")

            self.base_config = config
            runtime = self.compose_runtime_config(config)
            write_config(runtime)
            self.active_config_signature = config_signature(runtime)
            ok = start_xray(self.log, verify_start=True, verify_seconds=2.0)
            if ok:
                self.log("[Xray] auto-started on app launch")
            else:
                raise RuntimeError("Xray exited soon after startup")
        except Exception as e:
            self.log(f"[Xray] auto-start failed: {e}")
            self.log(traceback.format_exc().strip())
            try:
                fallback = build_bootstrap_config()
                self.base_config = fallback
                runtime = self.compose_runtime_config(fallback)
                write_config(runtime)
                self.active_config_signature = config_signature(runtime)
                ok = start_xray(self.log, verify_start=True, verify_seconds=2.0)
                if ok:
                    self.log("[Xray] started with fallback bootstrap config")
                else:
                    self.log("[Xray] fallback config also exited early")
            except Exception as fallback_error:
                self.log(f"[Xray] fallback start failed: {fallback_error}")

    # ---------------- EXISTING CODE ----------------

    def refresh_table(self):
        self.table.setRowCount(len(self.profiles))
        for i, p in enumerate(self.profiles):
            meta = self._profile_meta(p.get("link", ""))
            self.table.setItem(i, self.COL_REMARKS, QTableWidgetItem(p["name"]))
            self.table.setItem(i, self.COL_ADDRESS, QTableWidgetItem(meta["address"]))
            self.table.setItem(i, self.COL_PORT, QTableWidgetItem(meta["port"]))
            self.table.setItem(i, self.COL_CONFIG, QTableWidgetItem(meta["proto"]))
            self.table.setItem(i, self.COL_TRANSPORT, QTableWidgetItem(meta["transport"]))
            self.table.setItem(i, self.COL_TLS, QTableWidgetItem(meta["tls"]))
            self.table.setItem(i, self.COL_PING, QTableWidgetItem(""))
            self.table.setItem(i, self.COL_SPEED, QTableWidgetItem(""))
        self.update_profile_combo()
        self.update_empty_state()
        if self.profiles:
            self.table.selectRow(0)
            self.activeProfileValue.setText(self.profiles[0]["name"])
        else:
            self.activeProfileValue.setText("-")

    def handle_paste(self):
        text = QApplication.clipboard().text()
        if not text:
            return

        lines = [x.strip() for x in text.splitlines() if x.strip()]
        profile_links = []
        total_added = 0
        subscription_items = []

        for link in lines:
            if is_profile_link_candidate(link):
                profile_links.append(link)
                continue
            if link.lower().startswith(("http://", "https://")):
                subscription_items.append({"name": "", "url": link})
                continue

            profile_links.append(link)

        if profile_links:
            total_added += self.import_profile_links(profile_links, source="Paste")

        if subscription_items:
            self._fetch_subscriptions_async(subscription_items, summary_mode="paste")

        if total_added == 0:
            self.show_toast("No profiles imported")

    def context_menu(self, pos):
        if self.is_profile_ui_locked():
            self.show_profile_lock_hint()
            return
        menu = QMenu()
        row = self.table.rowAt(pos.y())
        if row < 0:
            return
        self.table.selectRow(row)

        ping = menu.addAction("Ping Test (Ctrl+F) ")
        speed = menu.addAction("Speed Test (Ctrl+T) ")
        menu.addSeparator()
        rename = menu.addAction("Rename")
        edit_link = menu.addAction("Edit")
        share_qr = menu.addAction("Share QR")
        delete = menu.addAction("Delete")

        action = menu.exec(self.table.mapToGlobal(pos))

        if action == ping:
            self.ping_selected()

        if action == speed:
            self.speed_selected()

        if action == rename:
            self.rename_selected()

        if action == edit_link:
            self.edit_link_selected()

        if action == share_qr:
            self.share_selected_profile_qr()

        if action == delete:
            self.delete_selected()

    def rename_selected(self):
        row = self.table.currentRow()
        if row < 0:
            return

        current_name = self.profiles[row]["name"]
        new_name, ok = QInputDialog.getText(self, "Rename Profile", "New name:", text=current_name)
        if not ok:
            return

        new_name = new_name.strip()
        if not new_name:
            QMessageBox.warning(self, "Invalid Name", "Name cannot be empty")
            return

        self.profiles[row]["name"] = new_name
        save_profiles(self.profiles)
        self.refresh_table()

    def _profile_editor_field_defs(self):
        return [
            ("name", "Remarks"),
            ("address", "Address"),
            ("port", "Port"),
            ("uuid", "UUID"),
            ("password", "Password"),
            ("username", "Username"),
            ("method", "SS Method"),
            ("encryption", "Encryption"),
            ("alter_id", "AlterID"),
            ("network", "Transport"),
            ("security", "TLS Type"),
            ("host", "Host"),
            ("path", "Path"),
            ("sni", "SNI"),
            ("alpn", "ALPN"),
            ("fp", "Fingerprint"),
            ("pbk", "Reality PublicKey"),
            ("sid", "Reality ShortID"),
            ("spx", "Reality SpiderX"),
            ("flow", "Flow"),
            ("service_name", "gRPC ServiceName"),
            ("authority", "gRPC Authority"),
            ("header_type", "Header Type"),
            ("kcp_seed", "KCP Seed"),
            ("quic_security", "QUIC Security"),
            ("quic_key", "QUIC Key"),
            ("xhttp_mode", "XHTTP Mode"),
            ("xhttp_extra", "XHTTP Extra JSON"),
            ("allow_insecure", "Allow Insecure (0/1)"),
            ("up_mbps", "Up Mbps"),
            ("down_mbps", "Down Mbps"),
            ("obfs", "Obfs"),
            ("obfs_password", "Obfs Password"),
            ("congestion_control", "Congestion Control"),
            ("udp_relay_mode", "UDP Relay Mode"),
            ("zero_rtt_handshake", "Zero RTT (0/1)"),
            ("version", "Version"),
            ("secret_key", "WG Secret Key"),
            ("public_key", "WG Public Key"),
            ("pre_shared_key", "WG PreShared Key"),
            ("local_address", "WG Local Address"),
            ("allowed_ips", "WG Allowed IPs"),
            ("mtu", "WG MTU"),
            ("keep_alive", "WG KeepAlive"),
            ("reserved", "WG Reserved (a,b,c)"),
        ]

    def _profile_editor_fields_for_protocol(self, protocol):
        p = str(protocol or "").strip().lower()
        mapping = {
            "vmess": {"name", "address", "port", "uuid", "alter_id", "encryption", "network", "security"},
            "vless": {"name", "address", "port", "uuid", "encryption", "flow", "network", "security"},
            "trojan": {"name", "address", "port", "password", "flow", "network", "security"},
            "shadowsocks": {"name", "address", "port", "method", "password"},
            "hysteria2": {"name", "address", "port", "password", "sni", "alpn", "fp", "allow_insecure", "up_mbps", "down_mbps", "obfs", "obfs_password"},
            "tuic": {"name", "address", "port", "uuid", "password", "sni", "alpn", "fp", "congestion_control", "udp_relay_mode", "zero_rtt_handshake"},
            "socks": {"name", "address", "port", "username", "password", "version"},
            "http": {"name", "address", "port", "username", "password", "security"},
            "wireguard": {"name", "address", "port", "secret_key", "public_key", "pre_shared_key", "local_address", "allowed_ips", "mtu", "keep_alive", "reserved"},
            "shadowtls": {"name", "address", "port", "password", "version", "sni", "alpn", "fp"},
        }
        return set(mapping.get(p, {"name", "address", "port"}))

    def _profile_editor_fields_for_transport(self, network):
        n = _normalize_network(network)
        mapping = {
            "ws": {"host", "path"},
            "grpc": {"service_name", "authority", "xhttp_mode"},
            "kcp": {"header_type", "kcp_seed"},
            "quic": {"header_type", "quic_security", "quic_key"},
            "http": {"host", "path"},
            "httpupgrade": {"host", "path"},
            "xhttp": {"host", "path", "xhttp_mode", "xhttp_extra"},
            "tcp": {"header_type"},
        }
        return set(mapping.get(n, set()))

    def _profile_editor_fields_for_security(self, security):
        s = _normalize_security(security)
        if s in {"tls", "xtls"}:
            return {"sni", "alpn", "fp"}
        if s == "reality":
            return {"sni", "fp", "pbk", "sid", "spx"}
        return set()

    def _normalize_profile_for_editor(self, profile):
        link = str(profile.get("link", "")).strip()
        d = parse_any_link(link)
        defaults = {key: "" for key, _ in self._profile_editor_field_defs()}
        defaults["protocol"] = str(d.get("protocol", "")).strip().lower()
        defaults["name"] = str(d.get("name", profile.get("name", ""))).strip()

        for key in defaults.keys():
            if key in {"protocol", "name"}:
                continue
            value = d.get(key, "")
            if isinstance(value, list):
                value = ",".join(str(x) for x in value)
            elif isinstance(value, bool):
                value = "1" if value else "0"
            elif value is None:
                value = ""
            defaults[key] = str(value)
        defaults["network"] = _normalize_network(defaults.get("network", "tcp"))
        defaults["security"] = _normalize_security(defaults.get("security", "none"))
        return defaults

    def _open_profile_editor(self, profile):
        data = self._normalize_profile_for_editor(profile)

        dlg = QDialog(self)
        dlg.setObjectName("ProfileEditorDialog")
        dlg.setWindowTitle("Edit Profile (Advanced)")
        dlg.resize(860, 760)
        main_layout = QVBoxLayout(dlg)

        if self.theme_mode == "dark":
            dlg_bg = "#0f172a"
            panel_bg = "#111827"
            border = "#334155"
            text = "#e5e7eb"
            muted = "#94a3b8"
            tab_bg = "#1f2937"
            input_bg = "#0b1220"
        else:
            dlg_bg = "#f6f8fb"
            panel_bg = "#ffffff"
            border = "#dbe2ea"
            text = "#111827"
            muted = "#6b7280"
            tab_bg = "#eef2ff"
            input_bg = "#ffffff"

        dlg.setStyleSheet(f"""
        QDialog#ProfileEditorDialog {{
            background: {dlg_bg};
            color: {text};
        }}
        QDialog#ProfileEditorDialog QTabWidget::pane {{
            border: 1px solid {border};
            border-radius: 10px;
            background: {panel_bg};
        }}
        QDialog#ProfileEditorDialog QTabBar::tab {{
            background: {tab_bg};
            color: {text};
            border: 1px solid {border};
            border-bottom: none;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            padding: 8px 12px;
            margin-right: 4px;
        }}
        QDialog#ProfileEditorDialog QTabBar::tab:selected {{
            background: {self.accent_color};
            color: #ffffff;
            border-color: {self.accent_color};
        }}
        QDialog#ProfileEditorDialog QScrollArea {{
            border: none;
            background: {panel_bg};
        }}
        QDialog#ProfileEditorDialog QWidget#EditorFormContainer {{
            background: {panel_bg};
            border: 1px solid {border};
            border-radius: 10px;
        }}
        QDialog#ProfileEditorDialog QLabel {{
            color: {text};
        }}
        QDialog#ProfileEditorDialog QLabel#EditorHint {{
            color: {muted};
        }}
        QDialog#ProfileEditorDialog QLineEdit,
        QDialog#ProfileEditorDialog QComboBox,
        QDialog#ProfileEditorDialog QPlainTextEdit {{
            background: {input_bg};
            color: {text};
            border: 1px solid {border};
            border-radius: 8px;
            padding: 6px 8px;
        }}
        """)

        hint = QLabel("Fields are grouped by Basic / Transport / TLS / Advanced. Save will rebuild the link.")
        hint.setObjectName("EditorHint")
        main_layout.addWidget(hint)

        tabs = QTabWidget()
        main_layout.addWidget(tabs, 1)

        def build_tab(title):
            page = QWidget()
            page_layout = QVBoxLayout(page)
            page_layout.setContentsMargins(0, 0, 0, 0)
            page_layout.setSpacing(0)
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            container = QWidget()
            container.setObjectName("EditorFormContainer")
            form = QFormLayout(container)
            form.setLabelAlignment(Qt.AlignLeft)
            form.setFormAlignment(Qt.AlignTop)
            form.setVerticalSpacing(8)
            form.setContentsMargins(12, 12, 12, 12)
            scroll.setWidget(container)
            page_layout.addWidget(scroll)
            tabs.addTab(page, title)
            return form

        basic_form = build_tab("Basic")
        transport_form = build_tab("Transport")
        tls_form = build_tab("TLS")
        advanced_form = build_tab("Advanced")

        widgets = {}
        rows = {}
        protocol_combo = QComboBox()
        protocol_combo.addItems([
            "vmess", "vless", "trojan", "shadowsocks", "hysteria2", "tuic",
            "socks", "http", "wireguard", "shadowtls"
        ])
        idx = protocol_combo.findText(data.get("protocol", ""), Qt.MatchFixedString)
        if idx >= 0:
            protocol_combo.setCurrentIndex(idx)
        widgets["protocol"] = protocol_combo
        basic_form.addRow(QLabel("Protocol"), protocol_combo)

        combo_fields = {
            "network": ["tcp", "ws", "grpc", "kcp", "quic", "http", "httpupgrade", "xhttp"],
            "security": ["none", "tls", "xtls", "reality"],
            "flow": ["", "xtls-rprx-vision", "xtls-rprx-origin", "xtls-rprx-direct", "xtls-rprx-vision-udp443"],
            "fp": ["", "chrome", "firefox", "safari", "edge", "ios", "android", "360", "qq", "random", "randomized"],
            "alpn": ["", "h2", "http/1.1", "h3", "h2,http/1.1", "h3,h2", "h3,http/1.1"],
            "header_type": ["none", "http", "srtp", "utp", "wechat-video", "dtls", "wireguard"],
            "xhttp_mode": ["auto", "packet-up", "stream-up", "stream-one", "multi"],
            "quic_security": ["none", "aes-128-gcm", "chacha20-poly1305"],
            "version": ["3", "4", "5"],
            "allow_insecure": ["0", "1"],
            "zero_rtt_handshake": ["0", "1"],
        }
        strict_menu_fields = {"network", "flow", "fp", "alpn"}

        tab_fields = {
            "Basic": {
                "name", "address", "port", "uuid", "password", "username", "method", "encryption",
                "alter_id", "version", "flow", "up_mbps", "down_mbps", "obfs", "obfs_password",
                "congestion_control", "udp_relay_mode", "zero_rtt_handshake",
                "secret_key", "public_key", "pre_shared_key", "local_address", "allowed_ips",
                "mtu", "keep_alive", "reserved", "allow_insecure"
            },
            "Transport": {
                "network", "host", "path", "service_name", "authority", "header_type",
                "kcp_seed", "quic_security", "quic_key", "xhttp_mode", "xhttp_extra"
            },
            "TLS": {"security", "sni", "alpn", "fp", "pbk", "sid", "spx"},
        }

        for key, label in self._profile_editor_field_defs():
            if key == "xhttp_extra":
                w = QPlainTextEdit()
                w.setMinimumHeight(90)
                w.setPlainText(data.get(key, ""))
            elif key in combo_fields:
                w = QComboBox()
                w.setEditable(key not in strict_menu_fields)
                w.addItems(combo_fields[key])
                v = data.get(key, "")
                idx = w.findText(v, Qt.MatchFixedString)
                if idx >= 0:
                    w.setCurrentIndex(idx)
                else:
                    if w.isEditable():
                        w.setEditText(v)
            else:
                w = QLineEdit()
                w.setText(data.get(key, ""))
            widgets[key] = w
            lbl = QLabel(label)
            if key in tab_fields["Basic"]:
                tab_name = "Basic"
                basic_form.addRow(lbl, w)
            elif key in tab_fields["Transport"]:
                tab_name = "Transport"
                transport_form.addRow(lbl, w)
            elif key in tab_fields["TLS"]:
                tab_name = "TLS"
                tls_form.addRow(lbl, w)
            else:
                tab_name = "Advanced"
                advanced_form.addRow(lbl, w)
            rows[key] = (lbl, w, tab_name)

        def apply_visibility():
            def set_combo_values(widget, values, current_value):
                if not isinstance(widget, QComboBox):
                    return
                widget.blockSignals(True)
                widget.clear()
                widget.addItems(values)
                if current_value in values:
                    widget.setCurrentText(current_value)
                else:
                    widget.setCurrentIndex(0 if values else -1)
                widget.blockSignals(False)

            protocol = protocol_combo.currentText().strip().lower()
            visible = self._profile_editor_fields_for_protocol(protocol)

            if "network" in visible:
                visible.update(self._profile_editor_fields_for_transport(widgets["network"].currentText()))
            if "security" in visible:
                visible.update(self._profile_editor_fields_for_security(widgets["security"].currentText()))

            tab_visible_counts = {"Basic": 0, "Transport": 0, "TLS": 0, "Advanced": 0}
            for key, (lbl, w, tab_name) in rows.items():
                is_visible = key in visible
                lbl.setVisible(is_visible)
                w.setVisible(is_visible)
                if is_visible:
                    tab_visible_counts[tab_name] += 1

            # protocol-specific security options
            if protocol == "http":
                allowed = ["none", "tls"]
            elif protocol in {"vmess", "vless", "trojan"}:
                allowed = ["none", "tls", "xtls", "reality"]
            else:
                allowed = []
            sec_widget = widgets["security"]
            if isinstance(sec_widget, QComboBox):
                current = sec_widget.currentText()
                set_combo_values(sec_widget, allowed if allowed else ["none"], current)

            # protocol-specific transport options
            if protocol in {"vmess", "vless", "trojan"}:
                allowed_networks = ["tcp", "ws", "grpc", "kcp", "quic", "http", "httpupgrade", "xhttp"]
            else:
                allowed_networks = ["tcp"]
            net_widget = widgets["network"]
            if isinstance(net_widget, QComboBox):
                current = _normalize_network(net_widget.currentText())
                set_combo_values(net_widget, allowed_networks, current)

            # protocol/security specific flow options
            flow_widget = widgets["flow"]
            if isinstance(flow_widget, QComboBox):
                current = flow_widget.currentText()
                sec_now = widgets["security"].currentText().strip().lower()
                if protocol in {"vless", "trojan"} and sec_now in {"tls", "xtls", "reality"}:
                    flow_values = ["", "xtls-rprx-vision", "xtls-rprx-origin", "xtls-rprx-direct", "xtls-rprx-vision-udp443"]
                else:
                    flow_values = [""]
                set_combo_values(flow_widget, flow_values, current)

            # xray fingerprints
            fp_widget = widgets["fp"]
            if isinstance(fp_widget, QComboBox):
                current = fp_widget.currentText()
                fp_values = ["", "chrome", "firefox", "safari", "edge", "ios", "android", "360", "qq", "random", "randomized"]
                set_combo_values(fp_widget, fp_values, current)

            # ALPN presets
            alpn_widget = widgets["alpn"]
            if isinstance(alpn_widget, QComboBox):
                current = alpn_widget.currentText()
                alpn_values = ["", "h2", "http/1.1", "h3", "h2,http/1.1", "h3,h2", "h3,http/1.1"]
                set_combo_values(alpn_widget, alpn_values, current)

            # show/hide tabs based on field relevance
            for i in range(tabs.count()):
                title = tabs.tabText(i)
                if title == "Basic":
                    tab_should_show = True  # always keep basic tab visible
                else:
                    tab_should_show = tab_visible_counts.get(title, 0) > 0
                try:
                    tabs.setTabVisible(i, tab_should_show)
                except Exception:
                    pass

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")
        btn_row.addWidget(save_btn)
        btn_row.addWidget(cancel_btn)
        main_layout.addLayout(btn_row)

        def collect_values():
            out = {"protocol": protocol_combo.currentText().strip().lower()}
            for key, _label in self._profile_editor_field_defs():
                w = widgets[key]
                if isinstance(w, QPlainTextEdit):
                    out[key] = w.toPlainText().strip()
                elif isinstance(w, QComboBox):
                    out[key] = w.currentText().strip()
                else:
                    out[key] = w.text().strip()
            return out

        def on_save():
            try:
                edited = collect_values()
                link = build_profile_link_from_dict(edited)
                parsed = parse_profile_link(link)
                dlg._result = parsed
                dlg.accept()
            except Exception as e:
                QMessageBox.warning(dlg, "Invalid Profile", str(e))

        save_btn.clicked.connect(on_save)
        cancel_btn.clicked.connect(dlg.reject)
        protocol_combo.currentTextChanged.connect(lambda _v: apply_visibility())
        if isinstance(widgets.get("network"), QComboBox):
            widgets["network"].currentTextChanged.connect(lambda _v: apply_visibility())
        if isinstance(widgets.get("security"), QComboBox):
            widgets["security"].currentTextChanged.connect(lambda _v: apply_visibility())
        apply_visibility()

        if dlg.exec() == QDialog.Accepted and hasattr(dlg, "_result"):
            return dlg._result
        return None

    def edit_link_selected(self):
        row = self.table.currentRow()
        if row < 0:
            return

        try:
            parsed = self._open_profile_editor(self.profiles[row])
            if not parsed:
                return
            self.profiles[row]["link"] = parsed["link"]
            self.profiles[row]["name"] = parsed["name"]
            save_profiles(self.profiles)
            self.refresh_table()
        except Exception as e:
            QMessageBox.warning(self, "Invalid Link", str(e))
            self.log(f"[Edit] invalid link: {e}")

    def delete_selected(self):
        self.delete_selected_rows()

    def select_all_profiles(self):
        if not self.profiles:
            return
        self.table.selectAll()

    def delete_selected_rows(self):
        selected_rows = sorted(
            {idx.row() for idx in self.table.selectionModel().selectedRows()},
            reverse=True
        )
        if not selected_rows:
            row = self.table.currentRow()
            if row >= 0:
                selected_rows = [row]
        if not selected_rows:
            return

        if len(selected_rows) == 1:
            profile_name = self.profiles[selected_rows[0]]["name"]
            title = "Delete Profile"
            text = f"Delete profile '{profile_name}'?"
        else:
            title = "Delete Profiles"
            text = f"Delete {len(selected_rows)} selected profile(s)?"

        answer = QMessageBox.question(self, title, text)
        if answer != QMessageBox.Yes:
            return

        for row in selected_rows:
            if 0 <= row < len(self.profiles):
                self.profiles.pop(row)
        save_profiles(self.profiles)
        self.refresh_table()

    def build_config_from_link(self, link, inbound_port=10808, apply_runtime_settings=False):
        allow_insecure = bool(self.settings["advanced"]["allow_insecure_tls"])
        parsed = parse_any_link(link)
        protocol = parsed.get("protocol")

        builders = {
            "vless": lambda data: build_vless_config(data, inbound_port=inbound_port, allow_insecure_tls=allow_insecure),
            "vmess": lambda data: build_vmess_config(data, inbound_port=inbound_port, allow_insecure_tls=allow_insecure),
            "trojan": lambda data: build_trojan_config(data, inbound_port=inbound_port, allow_insecure_tls=allow_insecure),
            "shadowsocks": lambda data: build_shadowsocks_config(data, inbound_port=inbound_port),
            "hysteria2": lambda data: build_hysteria2_config(data, inbound_port=inbound_port, allow_insecure_tls=allow_insecure),
            "tuic": lambda data: build_tuic_config(data, inbound_port=inbound_port, allow_insecure_tls=allow_insecure),
            "socks": lambda data: build_socks_config(data, inbound_port=inbound_port),
            "http": lambda data: build_http_config(data, inbound_port=inbound_port, allow_insecure_tls=allow_insecure),
            "wireguard": lambda data: build_wireguard_config(data, inbound_port=inbound_port),
            "shadowtls": lambda data: build_shadowtls_config(data, inbound_port=inbound_port, allow_insecure_tls=allow_insecure),
            "freedom": lambda _data: build_internal_outbound_config("freedom", inbound_port=inbound_port),
            "blackhole": lambda _data: build_internal_outbound_config("blackhole", inbound_port=inbound_port),
            "dns": lambda _data: build_internal_outbound_config("dns", inbound_port=inbound_port),
        }
        builder = builders.get(protocol)
        if not builder:
            raise ValueError("Protocol not supported")
        config = builder(parsed)

        if apply_runtime_settings:
            return apply_settings_to_config(config, self.settings)

        return config

    def start_temp_xray_for_test(self, config, temp_filename, fail_message):
        if not os.path.exists(XRAY_PATH):
            raise FileNotFoundError(f"xray core not found: {XRAY_PATH}")
        temp_path = os.path.join(DATA_DIR, temp_filename)
        with open(temp_path, "w", encoding="utf8") as f:
            json.dump(config, f, indent=2)

        proc = subprocess.Popen(
            [XRAY_PATH, "run", "-config", temp_path],
            cwd=XRAY_CORE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=NO_WINDOW_FLAG
        )

        time.sleep(3)
        if proc.poll() is not None:
            try:
                out = (proc.stdout.read() or "").strip()
                if out:
                    self.log(f"[TempXray] startup error: {out}")
            except Exception:
                pass
            try:
                if proc.stdout:
                    proc.stdout.close()
            except Exception:
                pass
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception as e:
                self.log(f"[TempXray] failed to remove temp config {temp_path}: {e}")
            raise RuntimeError(fail_message)

        return proc, temp_path

    def stop_temp_xray_for_test(self, proc, log_prefix, temp_path=None):
        if not proc:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception as e:
                    self.log(f"[{log_prefix}] Failed to remove temp config {temp_path}: {e}")
            return
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=1.0)
        except Exception as e:
            self.log(f"[{log_prefix}] Failed to stop temp xray process: {e}")
        finally:
            try:
                if proc.stdout:
                    proc.stdout.close()
            except Exception:
                pass
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception as e:
                    self.log(f"[{log_prefix}] Failed to remove temp config {temp_path}: {e}")

    # ------------------- Ping -------------------

    def ping_selected(self):
        row = self.table.currentRow()
        if row < 0:
            return

        if not shutil.which("curl"):
            QMessageBox.warning(self, "Dependency Error", "curl was not found in PATH.")
            self.log("[Ping] curl was not found in PATH")
            return

        link = self.profiles[row]["link"]
        self.testing_state_signal.emit(row, self.COL_PING, True)

        def worker():
            proc = None
            temp_path = None
            test_port = find_free_local_port()

            try:
                config = self.build_config_from_link(link, inbound_port=test_port)
                proc, temp_path = self.start_temp_xray_for_test(
                    config=config,
                    temp_filename="ping.json",
                    fail_message="Temporary Xray process exited before ping test"
                )

                ping_urls = [
                    "https://cp.cloudflare.com/generate_204",
                    "https://www.gstatic.com/generate_204",
                    "http://www.google.com/generate_204",
                ]
                latency = None
                last_error = "unknown"

                for url in ping_urls:
                    for _ in range(2):
                        start = time.time()
                        result = subprocess.run([
                            "curl",
                            "--socks5-hostname", f"127.0.0.1:{test_port}",
                            "--connect-timeout", "5",
                            "--max-time", str(self.settings["advanced"]["ping_max_time"]),
                            "--silent",
                            "--show-error",
                            "-o", "NUL",
                            "-L",
                            url
                        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False, creationflags=NO_WINDOW_FLAG)

                        if result.returncode == 0:
                            latency = int((time.time() - start) * 1000)
                            break

                        last_error = (result.stderr or f"curl exit code {result.returncode}").strip()
                        time.sleep(0.35)

                    if latency is not None:
                        break

                if latency is None:
                    raise RuntimeError(f"curl ping failed after retries: {last_error}")

                self.table_update_signal.emit(row, self.COL_PING, f"{latency} ms")

            except Exception as e:
                self.table_update_signal.emit(row, self.COL_PING, "FAIL")
                self.log(f"[Ping] row={row} failed: {e}")
                if "result" in locals():
                    err = (result.stderr or "").strip()
                    if err:
                        self.log(f"[Ping] curl stderr: {err}")
                self.log(traceback.format_exc().strip())

            finally:
                self.stop_temp_xray_for_test(proc, "Ping", temp_path=temp_path)
                self.testing_state_signal.emit(row, self.COL_PING, False)

        threading.Thread(target=worker, daemon=True).start()

    # ------------------- Speed -------------------

    def speed_selected(self):
        row = self.table.currentRow()
        if row < 0:
            return

        if not shutil.which("curl"):
            QMessageBox.warning(self, "Dependency Error", "curl was not found in PATH.")
            self.log("[Speed] curl was not found in PATH")
            return

        link = self.profiles[row]["link"]
        self.testing_state_signal.emit(row, self.COL_SPEED, True)

        def worker():
            proc = None
            temp_path = None
            test_port = find_free_local_port()

            try:
                config = self.build_config_from_link(link, inbound_port=test_port)
                proc, temp_path = self.start_temp_xray_for_test(
                    config=config,
                    temp_filename="speed.json",
                    fail_message="Temporary Xray process exited before speed test"
                )

                test_bytes = 1_000_000
                url = f"https://speed.cloudflare.com/__down?bytes={test_bytes}"

                speed_mb_s = None
                last_error = "unknown"
                for _ in range(2):
                    start = time.time()
                    result = subprocess.run([
                        "curl",
                        "--socks5-hostname", f"127.0.0.1:{test_port}",
                        "--connect-timeout", "5",
                        "--max-time", str(self.settings["advanced"]["speed_max_time"]),
                        "--silent",
                        "--show-error",
                        "-o", "NUL",
                        "-L",
                        url
                    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False, creationflags=NO_WINDOW_FLAG)
                    if result.returncode == 0:
                        end = time.time()
                        elapsed = max(end - start, 1e-6)
                        speed_mb_s = (test_bytes / elapsed) / 1_000_000
                        break
                    last_error = (result.stderr or f"curl exit code {result.returncode}").strip()
                    time.sleep(0.35)

                if speed_mb_s is None:
                    raise RuntimeError(f"curl speed test failed after retries: {last_error}")

                self.table_update_signal.emit(row, self.COL_SPEED, f"{speed_mb_s:.2f} MB/s")

            except Exception as e:
                self.table_update_signal.emit(row, self.COL_SPEED, "FAIL")
                self.log(f"[Speed] row={row} failed: {e}")
                if "result" in locals():
                    err = (result.stderr or "").strip()
                    if err:
                        self.log(f"[Speed] curl stderr: {err}")
                self.log(traceback.format_exc().strip())

            finally:
                self.stop_temp_xray_for_test(proc, "Speed", temp_path=temp_path)
                self.testing_state_signal.emit(row, self.COL_SPEED, False)

        threading.Thread(target=worker, daemon=True).start()

    # ------------------- Connect (Select) -------------------

    def select_config(self):
        if self.is_profile_ui_locked():
            self.show_profile_lock_hint()
            return
        row = self.table.currentRow()
        if row < 0:
            return

        link = self.profiles[row]["link"]
        profile_name = self.profiles[row]["name"]

        def worker():
            try:
                self.log("[Select] building config...")
                raw_config = self.build_config_from_link(link, apply_runtime_settings=False)
                config = self.compose_runtime_config(raw_config)
                new_signature = config_signature(config)
                write_config(config)
                self.log("[Select] config written")

                should_restart = new_signature != self.active_config_signature
                is_running = bool(xray_process and xray_process.poll() is None)

                if not is_running:
                    self.log("Xray is stopped. Starting with selected config...")
                    self.log("[Xray] starting core...")
                    ok = start_xray(self.log, verify_start=True, verify_seconds=2.0)
                    def finish_start():
                        if ok:
                            self.base_config = raw_config
                            self.active_config_signature = new_signature
                            self.log(f"[Select] new config selected: {profile_name} (started)")
                            if self.settings["proxy"]["auto_set_system_proxy_on_connect"]:
                                self.on_set_proxy_clicked()
                        else:
                            self.log("[Select] runtime config crashed. Trying raw profile config...")
                            write_config(raw_config)
                            self.log("[Xray] starting core (fallback)...")
                            fallback_ok = start_xray(self.log, verify_start=True, verify_seconds=2.0)
                            if fallback_ok:
                                self.base_config = raw_config
                                self.active_config_signature = config_signature(raw_config)
                                self.log(f"[Select] fallback raw config selected: {profile_name}")
                            else:
                                self.log(f"[Select] fallback raw config also failed: {profile_name}")
                        self.update_runtime_status()
                    QTimer.singleShot(0, finish_start)
                elif should_restart:
                    self.log("Config changed. Restarting Xray...")
                    self.log("[Xray] restarting core...")
                    ok = start_xray(self.log, verify_start=True, verify_seconds=2.0)
                    def finish_restart():
                        if ok:
                            self.base_config = raw_config
                            self.active_config_signature = new_signature
                            self.log(f"[Select] new config selected: {profile_name} (restarted)")
                            if self.settings["proxy"]["auto_set_system_proxy_on_connect"]:
                                self.on_set_proxy_clicked()
                        else:
                            self.log("[Select] runtime config crashed after restart. Trying raw profile config...")
                            write_config(raw_config)
                            self.log("[Xray] starting core (fallback)...")
                            fallback_ok = start_xray(self.log, verify_start=True, verify_seconds=2.0)
                            if fallback_ok:
                                self.base_config = raw_config
                                self.active_config_signature = config_signature(raw_config)
                                self.log(f"[Select] fallback raw config selected: {profile_name}")
                            else:
                                self.log(f"[Select] fallback raw config also failed: {profile_name}")
                        self.update_runtime_status()
                    QTimer.singleShot(0, finish_restart)
                else:
                    def finish_no_restart():
                        self.log("Config unchanged. No Xray restart needed.")
                        self.log(f"[Select] config selected: {profile_name} (no restart)")
                        self.update_runtime_status()
                    QTimer.singleShot(0, finish_no_restart)
            except ValueError:
                QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Error", "Protocol not supported"))
            except Exception as e:
                QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Error", str(e)))

        self._enqueue_xray_task(worker)

    def closeEvent(self, event):
        if not self._exit_requested and self.tray_icon and self.tray_icon.isVisible():
            self.hide()
            event.ignore()
            if not self._tray_minimize_notice_shown:
                self.tray_icon.showMessage(
                    "V2rayX",
                    "App is still running in system tray. Use tray menu to Exit.",
                    QSystemTrayIcon.Information,
                    2500
                )
                self._tray_minimize_notice_shown = True
            return

        self.status_timer.stop()
        if hasattr(self, "tunnel_monitor_timer"):
            self.tunnel_monitor_timer.stop()
        self._remove_tunnel_routes()
        stop_xray_process(self.log, terminate_timeout=0.8, kill_timeout=0.8)
        self.update_runtime_status()
        if self.tray_icon:
            self.tray_icon.hide()
        super().closeEvent(event)

# ===============================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    if os.path.exists(APP_ICON_PATH):
        app.setWindowIcon(QIcon(APP_ICON_PATH))

    win = MainWindow()
    win.show()

    def _handle_sigint(_sig, _frame):
        try:
            win._exit_requested = True
            win.close()
        except Exception:
            pass
        app.quit()

    signal.signal(signal.SIGINT, _handle_sigint)

    try:
        sys.exit(app.exec())
    except KeyboardInterrupt:
        try:
            win._exit_requested = True
            win.close()
        except Exception:
            pass
        sys.exit(0)
