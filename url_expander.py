"""
url_expander.py
Expande URLs encurtados (bit.ly, abre.ai, tinyurl, etc.) sem clicar no link.
Segue a cadeia de redirects HTTP 301/302 e devolve o destino final.
Totalmente passivo — nunca executa JavaScript nem carrega recursos.
"""

import re
import logging
import urllib.request
from urllib.parse import urlparse
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)

# Serviços de encurtamento conhecidos
SHORTENER_DOMAINS = {
    "bit.ly", "bitly.com",
    "abre.ai",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "goo.gl",
    "ow.ly",
    "rb.gy",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
    "lnkd.in",
    "buff.ly",
    "dlvr.it",
    "soo.gd",
    "s2r.co",
    "clck.ru",
    "vzturl.com",
    "qr.ae",
}

MAX_REDIRECTS = 10
TIMEOUT_SECONDS = 6


def is_shortener(url: str) -> bool:
    """Verifica se um URL pertence a um serviço de encurtamento."""
    try:
        domain = urlparse(url).netloc.lower().lstrip("www.")
        base = ".".join(domain.split(".")[-2:]) if domain.count(".") >= 1 else domain
        return base in SHORTENER_DOMAINS or domain in SHORTENER_DOMAINS
    except Exception:
        return False


def expand_url(url: str) -> dict:
    """
    Segue a cadeia de redirects de um URL encurtado e devolve o destino final.

    Retorna:
        {
            "original":        str,   # URL de entrada
            "final":           str,   # destino final após todos os redirects
            "chain":           list,  # toda a cadeia de redirects
            "hops":            int,   # número de saltos
            "expanded":        bool,  # True se o URL mudou
            "is_shortener":    bool,  # True se o original era um encurtador
            "error":           str | None
        }
    """
    result = {
        "original": url,
        "final": url,
        "chain": [url],
        "hops": 0,
        "expanded": False,
        "is_shortener": is_shortener(url),
        "error": None,
    }

    current = url
    visited = set()

    for _ in range(MAX_REDIRECTS):
        if current in visited:
            result["error"] = "Ciclo de redirects detectado"
            break
        visited.add(current)

        try:
            req = urllib.request.Request(
                current,
                headers={
                    # Simula um browser para evitar bloqueios de bot
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    ),
                    "Accept": "text/html,application/xhtml+xml",
                },
            )

            # Abre sem seguir redirects automaticamente
            opener = urllib.request.build_opener(
                urllib.request.HTTPRedirectHandler()
            )

            # Usamos um opener que NÃO segue redirects automaticamente:
            # em vez disso capturamos o Location header manualmente
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None  # impede o seguimento automático

            no_redirect_opener = urllib.request.build_opener(NoRedirect())
            try:
                response = no_redirect_opener.open(req, timeout=TIMEOUT_SECONDS)
                # Chegou ao destino final sem mais redirects
                final_url = response.geturl()
                if final_url and final_url != current:
                    result["chain"].append(final_url)
                    current = final_url
                    result["hops"] += 1
                break

            except HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    location = e.headers.get("Location", "")
                    if not location:
                        break
                    # Resolve URLs relativos
                    if location.startswith("/"):
                        parsed = urlparse(current)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    result["chain"].append(location)
                    result["hops"] += 1
                    current = location
                else:
                    result["error"] = f"HTTP {e.code}"
                    break

        except URLError as e:
            result["error"] = f"Erro de rede: {str(e.reason)[:80]}"
            break
        except Exception as e:
            result["error"] = f"Erro inesperado: {str(e)[:80]}"
            break

    result["final"] = current
    result["expanded"] = current != url

    if result["hops"] > 0:
        logger.info(
            f"URL expandido em {result['hops']} salto(s): "
            f"{url[:60]} → {current[:60]}"
        )

    return result


def expand_all_links(text: str) -> dict[str, dict]:
    """
    Extrai todos os URLs de um texto e expande os que são encurtadores.
    Devolve um dicionário {url_original: resultado_expansão}.
    """
    urls = re.findall(r"https?://\S+", text)
    results = {}
    for url in urls:
        # Remove pontuação final que pode ter sido apanhada
        url = url.rstrip(".,;:!?)")
        if is_shortener(url):
            results[url] = expand_url(url)
    return results
