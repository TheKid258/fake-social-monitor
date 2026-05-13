"""
virustotal.py
Integração com a API do VirusTotal para verificar URLs e domínios
contra 90+ motores de antivírus e análise de ameaças.

Requer: VIRUSTOTAL_API_KEY no ficheiro .env
API gratuita: 4 pedidos/minuto, 500 pedidos/dia
Documentação: https://developers.virustotal.com/reference
"""

import os
import hashlib
import base64
import logging
import time
from functools import lru_cache

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"

# Cache simples em memória para evitar consultas repetidas na mesma sessão
# (a API gratuita tem limite de 4 req/min)
_vt_cache: dict[str, dict] = {}
_last_request_time: float = 0.0
MIN_REQUEST_INTERVAL = 15.1  # segundos entre pedidos (4/min = 15s de intervalo)


def _get_api_key() -> str:
    return os.getenv("VIRUSTOTAL_API_KEY", "")


def _rate_limit():
    """Respeita o limite de 4 pedidos/minuto da API gratuita."""
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < MIN_REQUEST_INTERVAL:
        time.sleep(MIN_REQUEST_INTERVAL - elapsed)
    _last_request_time = time.time()


def _url_id(url: str) -> str:
    """
    VirusTotal identifica URLs pelo seu SHA-256 em base64url (sem padding).
    """
    url_bytes = url.encode("utf-8")
    sha256 = hashlib.sha256(url_bytes).digest()
    return base64.urlsafe_b64encode(sha256).rstrip(b"=").decode()


def check_url(url: str, use_cache: bool = True) -> dict:
    """
    Consulta o VirusTotal para um URL específico.

    Fluxo:
      1. Verifica o cache local
      2. GET /urls/{id} — resultado em cache do VT (instantâneo, sem custo)
      3. Se não encontrado, POST /urls — submete para análise
      4. GET /analyses/{id} — aguarda resultado

    Retorna:
        {
            "available":        bool,
            "url":              str,
            "malicious":        int,   # motores que detectaram como malicioso
            "suspicious":       int,   # motores que detectaram como suspeito
            "harmless":         int,
            "undetected":       int,
            "total_engines":    int,
            "threat_names":     list,  # nomes das ameaças detectadas
            "categories":       dict,  # categorias atribuídas (ex: phishing, malware)
            "last_analysis":    str | None,
            "risk_score":       int,   # pontuação adicional (0–8)
            "verdict":          str,   # "Limpo", "Suspeito", "Malicioso", "Indisponível"
            "error":            str | None
        }
    """
    # Cache local
    if use_cache and url in _vt_cache:
        logger.info(f"VT cache hit: {url[:60]}")
        return _vt_cache[url]

    result = {
        "available": False,
        "url": url,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "total_engines": 0,
        "threat_names": [],
        "categories": {},
        "last_analysis": None,
        "risk_score": 0,
        "verdict": "Indisponível",
        "error": None,
    }

    api_key = _get_api_key()
    if not api_key:
        result["error"] = "VIRUSTOTAL_API_KEY não configurada"
        return result

    try:
        import requests as _req

        headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
        }

        url_id = _url_id(url)

        # --- Passo 1: tentar obter análise já existente ---
        _rate_limit()
        resp = _req.get(
            f"{VT_BASE}/urls/{url_id}",
            headers=headers,
            timeout=10,
        )

        if resp.status_code == 404:
            # URL não está em cache no VT — submeter para análise
            _rate_limit()
            submit_resp = _req.post(
                f"{VT_BASE}/urls",
                headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                data=f"url={url}",
                timeout=10,
            )
            if submit_resp.status_code not in (200, 201):
                result["error"] = f"VT submission error: HTTP {submit_resp.status_code}"
                return result

            analysis_id = submit_resp.json().get("data", {}).get("id", "")
            if not analysis_id:
                result["error"] = "VT: resposta de submissão inválida"
                return result

            # Aguardar análise (máx. 2 tentativas com 5s de intervalo)
            for _ in range(2):
                time.sleep(5)
                _rate_limit()
                analysis_resp = _req.get(
                    f"{VT_BASE}/analyses/{analysis_id}",
                    headers=headers,
                    timeout=10,
                )
                if analysis_resp.status_code == 200:
                    status = analysis_resp.json().get("data", {}).get("attributes", {}).get("status", "")
                    if status == "completed":
                        resp = analysis_resp
                        break

            if resp.status_code != 200:
                result["error"] = "VT: análise não concluída a tempo"
                return result

        if resp.status_code != 200:
            result["error"] = f"VT API error: HTTP {resp.status_code}"
            return result

        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        last_results = attrs.get("last_analysis_results", {})

        result["available"] = True
        result["malicious"] = stats.get("malicious", 0)
        result["suspicious"] = stats.get("suspicious", 0)
        result["harmless"] = stats.get("harmless", 0)
        result["undetected"] = stats.get("undetected", 0)
        result["total_engines"] = sum(stats.values())
        result["categories"] = attrs.get("categories", {})
        result["last_analysis"] = attrs.get("last_analysis_date")
        if result["last_analysis"]:
            from datetime import datetime
            try:
                result["last_analysis"] = datetime.fromtimestamp(
                    int(result["last_analysis"])
                ).strftime("%Y-%m-%d %H:%M")
            except Exception:
                pass

        # Recolher nomes das ameaças detectadas
        threat_names = set()
        for engine_result in last_results.values():
            if engine_result.get("category") in ("malicious", "suspicious"):
                name = engine_result.get("result")
                if name and name not in ("malicious", "suspicious", "phishing"):
                    threat_names.add(name)
        result["threat_names"] = sorted(threat_names)[:5]  # máximo 5

        # Calcular veredicto e pontuação
        mal = result["malicious"]
        sus = result["suspicious"]

        if mal >= 5:
            result["verdict"] = "Malicioso"
            result["risk_score"] = 8
        elif mal >= 2:
            result["verdict"] = "Malicioso"
            result["risk_score"] = 6
        elif mal == 1 or sus >= 3:
            result["verdict"] = "Suspeito"
            result["risk_score"] = 4
        elif sus >= 1:
            result["verdict"] = "Suspeito"
            result["risk_score"] = 2
        else:
            result["verdict"] = "Limpo"
            result["risk_score"] = 0

        # Guardar em cache
        if use_cache:
            _vt_cache[url] = result

        logger.info(
            f"VT resultado para {url[:60]}: "
            f"malicioso={mal} suspeito={sus} total={result['total_engines']}"
        )

    except ImportError:
        result["error"] = "Biblioteca 'requests' não disponível"
    except Exception as e:
        result["error"] = f"Erro VT: {str(e)[:100]}"
        logger.error(f"VirusTotal erro para {url}: {e}")

    return result


def check_all_urls(urls: list[str]) -> dict[str, dict]:
    """
    Verifica uma lista de URLs no VirusTotal.
    Respeita automaticamente os limites de taxa da API gratuita.
    """
    results = {}
    for url in urls:
        results[url] = check_url(url)
    return results


def format_vt_summary(vt_result: dict) -> str:
    """Formata um resumo legível do resultado VirusTotal."""
    if not vt_result.get("available"):
        return f"VirusTotal indisponível: {vt_result.get('error', 'sem dados')}"

    verdict = vt_result["verdict"]
    mal = vt_result["malicious"]
    sus = vt_result["suspicious"]
    total = vt_result["total_engines"]

    summary = f"VirusTotal: {verdict} — {mal}/{total} motores detectaram ameaça"
    if sus > 0:
        summary += f" ({sus} suspeitos)"
    if vt_result["threat_names"]:
        summary += f" — {', '.join(vt_result['threat_names'][:3])}"
    if vt_result["last_analysis"]:
        summary += f" (análise: {vt_result['last_analysis']})"

    return summary
