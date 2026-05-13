"""
whois_checker.py
Verifica a idade e dados de registo de um domínio via WHOIS.
Um domínio com menos de 30 dias é fortemente suspeito.
Um domínio com menos de 90 dias merece atenção.
Não requer API key — usa consultas WHOIS nativas (socket/whois protocol).
"""

import re
import socket
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Timeout para ligação WHOIS
WHOIS_TIMEOUT = 8

# Servidores WHOIS por TLD (os mais comuns em Moçambique + globais suspeitos)
WHOIS_SERVERS = {
    "com":  "whois.verisign-grs.com",
    "net":  "whois.verisign-grs.com",
    "org":  "whois.pir.org",
    "info": "whois.afilias.net",
    "biz":  "whois.biz",
    "co":   "whois.nic.co",
    "mz":   "whois.nic.mz",
    "io":   "whois.nic.io",
    "xyz":  "whois.nic.xyz",
    "tk":   "whois.dot.tk",
    "ml":   "whois.dot.ml",
    "ga":   "whois.dot.ga",
    "cf":   "whois.dot.cf",
    "gq":   "whois.dot.gq",
    "top":  "whois.nic.top",
    "click":"whois.uniregistry.net",
    "link": "whois.uniregistry.net",
    "work": "whois.nic.work",
    "loan": "whois.nic.loan",
    "win":  "whois.nic.win",
    # fallback genérico
    "_default": "whois.iana.org",
}

# Padrões de data nos registos WHOIS (vários formatos)
DATE_PATTERNS = [
    r"[Cc]reation\s+[Dd]ate\s*:\s*(.+)",
    r"[Cc]reated\s+[Oo]n\s*:\s*(.+)",
    r"[Cc]reated\s*:\s*(.+)",
    r"[Rr]egistered\s+[Oo]n\s*:\s*(.+)",
    r"[Rr]egistered\s*:\s*(.+)",
    r"[Rr]egistration\s+[Dd]ate\s*:\s*(.+)",
    r"[Dd]omain\s+[Rr]egistration\s+[Dd]ate\s*:\s*(.+)",
]

DATE_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d",
    "%d-%b-%Y",
    "%d/%m/%Y",
    "%B %d, %Y",
    "%d %B %Y",
]


def _extract_domain(url: str) -> str:
    """Extrai o domínio base de um URL."""
    try:
        netloc = urlparse(url).netloc.lower()
        if not netloc:
            netloc = url.lower()
        # Remove porta e www
        netloc = netloc.split(":")[0].lstrip("www.")
        return netloc
    except Exception:
        return url.lower()


def _get_tld(domain: str) -> str:
    parts = domain.split(".")
    return parts[-1] if parts else ""


def _get_sld(domain: str) -> str:
    """Segundo nível de domínio — ex: google.com → google.com"""
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _whois_query(domain: str) -> str:
    """Faz consulta WHOIS raw e devolve a resposta em texto."""
    tld = _get_tld(domain)
    server = WHOIS_SERVERS.get(tld, WHOIS_SERVERS["_default"])

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(WHOIS_TIMEOUT)
        sock.connect((server, 43))
        query = f"{domain}\r\n"
        sock.sendall(query.encode("utf-8"))

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()

        text = response.decode("utf-8", errors="replace")

        # Alguns WHOIS devolvem um servidor de referência — segue uma vez
        referral = re.search(r"[Ww]hois [Ss]erver:\s*(.+)", text)
        if referral:
            ref_server = referral.group(1).strip()
            if ref_server != server:
                try:
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock2.settimeout(WHOIS_TIMEOUT)
                    sock2.connect((ref_server, 43))
                    sock2.sendall(query.encode("utf-8"))
                    resp2 = b""
                    while True:
                        c = sock2.recv(4096)
                        if not c:
                            break
                        resp2 += c
                    sock2.close()
                    text = resp2.decode("utf-8", errors="replace")
                except Exception:
                    pass  # usa a resposta original

        return text

    except Exception as e:
        logger.warning(f"WHOIS falhou para {domain}: {e}")
        return ""


def _parse_creation_date(whois_text: str) -> datetime | None:
    """Extrai a data de criação do registo WHOIS."""
    for pattern in DATE_PATTERNS:
        match = re.search(pattern, whois_text)
        if match:
            raw_date = match.group(1).strip().split("\n")[0].strip()
            # Remove timezone textual (ex: "UTC", "EST")
            raw_date = re.sub(r"\s+[A-Z]{2,4}$", "", raw_date).strip()
            for fmt in DATE_FORMATS:
                try:
                    dt = datetime.strptime(raw_date, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                except ValueError:
                    continue
    return None


def check_domain_age(url: str) -> dict:
    """
    Verifica a idade de registo do domínio de um URL.

    Retorna:
        {
            "domain":          str,
            "creation_date":   str | None,
            "age_days":        int | None,
            "age_risk":        str,   # "Novo (<30d)", "Recente (<90d)", "Estabelecido", "Desconhecido"
            "risk_score":      int,   # pontuação adicional de risco (0–5)
            "risk_reason":     str | None,
            "whois_available": bool,
            "raw_snippet":     str    # primeiras linhas do WHOIS para diagnóstico
        }
    """
    domain = _extract_domain(url)
    sld = _get_sld(domain)

    result = {
        "domain": sld,
        "creation_date": None,
        "age_days": None,
        "age_risk": "Desconhecido",
        "risk_score": 0,
        "risk_reason": None,
        "whois_available": False,
        "raw_snippet": "",
    }

    whois_text = _whois_query(sld)
    if not whois_text:
        return result

    result["whois_available"] = True
    # Guarda as primeiras 20 linhas para diagnóstico
    result["raw_snippet"] = "\n".join(whois_text.splitlines()[:20])

    creation_date = _parse_creation_date(whois_text)
    if not creation_date:
        return result

    now = datetime.now(timezone.utc)
    age_days = (now - creation_date).days

    result["creation_date"] = creation_date.strftime("%Y-%m-%d")
    result["age_days"] = age_days

    if age_days < 30:
        result["age_risk"] = "Novo (<30 dias)"
        result["risk_score"] = 5
        result["risk_reason"] = (
            f"Domínio registado há apenas {age_days} dia(s) — "
            "criação muito recente é sinal forte de fraude"
        )
    elif age_days < 90:
        result["age_risk"] = "Recente (<90 dias)"
        result["risk_score"] = 3
        result["risk_reason"] = (
            f"Domínio registado há {age_days} dias — "
            "sites legítimos raramente têm menos de 3 meses"
        )
    elif age_days < 365:
        result["age_risk"] = "Jovem (<1 ano)"
        result["risk_score"] = 1
        result["risk_reason"] = f"Domínio registado há {age_days} dias"
    else:
        years = age_days // 365
        result["age_risk"] = f"Estabelecido ({years}+ ano{'s' if years > 1 else ''})"
        result["risk_score"] = 0

    return result


def check_all_domains(urls: list[str]) -> dict[str, dict]:
    """Verifica a idade de todos os domínios únicos numa lista de URLs."""
    seen_domains = set()
    results = {}
    for url in urls:
        domain = _get_sld(_extract_domain(url))
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            results[url] = check_domain_age(url)
    return results
