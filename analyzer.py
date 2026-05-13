"""
analyzer.py
Módulo principal de análise de mensagens suspeitas.
"""

import re
import os
import logging
import requests
from dotenv import load_dotenv
from urllib.parse import urlparse, parse_qs
import math

from database import save_analysis, is_blacklisted
from text_utils import preprocess
from ml_model import predict_all

# Novos módulos de análise
try:
    from url_expander import expand_url, is_shortener as _is_shortener
    _HAS_EXPANDER = True
except ImportError:
    _HAS_EXPANDER = False

try:
    from whois_checker import check_domain_age
    _HAS_WHOIS = True
except ImportError:
    _HAS_WHOIS = False

try:
    from virustotal import check_url as vt_check_url
    _HAS_VT = True
except ImportError:
    _HAS_VT = False

load_dotenv()
logger = logging.getLogger(__name__)

API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

SHORTENERS = r"(abre\.ai|bit\.ly|tinyurl|t\.co|is\.gd|goo\.gl|ow\.ly|rb\.gy|cutt\.ly|shorturl\.at)"

# Domínios suspeitos de apostas comuns em Moçambique
SUSPICIOUS_DOMAINS = r"(apostasdemoz|apostas\w+\.com|bet\w+\.com|jogo\w+\.com|casino\w+\.com|play\w+\.mz)"

# Links de grupo WhatsApp — muito usados em golpes de emprego
WHATSAPP_GROUP_LINKS = r"(chat\.whatsapp\.com|wa\.me/|whatsapp\.com/send)"

PATTERNS = {
    # Fake News / Desinformação
    "Boato alarmista":          (r"(vai fechar|contas bloqueadas|ultimo aviso|informacao interna)",  2),
    "Linguagem de pânico":      (r"(partilha|espalha|antes que apaguem)",                            2),
    "Falta de fonte":           (r"(ninguem fala|nao mostram na tv|segredo)",                         1),

    # Golpes / Phishing
    "Pedido urgente":           (r"(urgente|agora|imediatamente|corre|rapido)",                       2),
    "Pedido de dados":          (r"(confirme|actualize|envie seus dados|palavra.passe|senha)",        3),
    "Imitação de instituição":  (r"(mpesa|emola|mkesh|banco|paypal|gov\.mz)",                        2),
    "Link encurtado":           (SHORTENERS,                                                          2),
    "Link externo":             (r"http[s]?://",                                                      1),
    "Domínio suspeito":         (SUSPICIOUS_DOMAINS,                                                  3),

    # Golpe de emprego / Recrutamento falso
    "Falsa oferta de emprego":  (r"(documentos aprovados|vaga aprovada|vaga reservada|candidatura aprovada|seleccionado|selecionado|recursos humanos|departamento de rh|rh contacto|entrar no grupo|grupo de trabalho|grupo de vagas|grupo whatsapp.*vaga|vaga.*grupo)", 3),
    "Promessa de vaga":         (r"(vaga garantida|vaga disponivel|vaga aberta|lugar reservado|sua vaga|seu pedido foi aprovado|pedido aprovado|foi aprovado)", 3),
    "Contacto suspeito de RH":  (r"(contacto.*\d{9}|\d{9}.*contacto|ligar para|enviar cv|enviar bi|enviar documentos|mandar documentos)", 2),
    "Link de grupo WhatsApp":   (WHATSAPP_GROUP_LINKS,                                               4),
    "Instruções suspeitas":     (r"(clique para entrar|entre no grupo|acesse o grupo|ultimas instrucoes|instruções do grupo|mais informacoes.*contacto)", 2),

    # Apostas / Aliciamento
    "Promoção de apostas":      (r"(aposta|jogo|casino|aviaozinho|jtx|bet|play|slot)",               2),
    "Incentivo a depósito":     (r"(deposita|carrega|investe|recarga)",                              2),
    "Promessa de ganho fácil":  (r"(ganha dinheiro|lucro garantido|dinheiro rapido|100%|funciona mesmo|ta funcionando|ta a funcionar)", 3),
    "Convite emocional":        (r"(venha se divertir|nao perca|aproveite|ve so|ve aqui|olha so)",   1),

    # Manipulação social
    "Pedido de segredo":        (r"(nao conta|nao contar|nao diz|guardar segredo|entre nos|so nos|melhor nao contar|nao fala pra ninguem|nao fales a ninguem)", 3),
    "Validação social falsa":   (r"(funciona mesmo|ja tentei|ja usei|e verdade|testei|comprovado|confirmado|funciona de verdade)", 2),
    "Linguagem informal aliciante": (r"(bro|mano|parceiro|amigo|cara|ve so|olha so|acredita|confia)", 1),
    "Urgência informal":        (r"(ve o que ta|ve o que esta|acontecendo agora|agora mesmo|neste momento|so agora)", 2),

    # Spam
    "Linguagem sensacionalista": (r"(!!!|💰|🔥|\$\$\$|😱|🤑|⬇️)",                                  1),

    # Curanderismo / Golpe Tradicional
    "Curandeiro / Médico tradicional": (r"(medico tradicional|curandeiro|feiticeiro|benzedor|pastor milagre|profeta|homem de deus|mulher de deus|pai de santo|mae de santo|espiritualismo|forca espiritual|poder espiritual|trabalho espiritual|oracoes poderosas)", 4),
    "Promessa sobrenatural":    (r"(ficar rico em \d|dias sem matar|sorte magica|carteira magica|crteira magica|recuperar.*amado|trazer.*de volta|casamento de volta|amor de volta|ex de volta|unir casal|separar casal|amarracao|desamarracao|tirar feitico|quebrar feitico|tirar mau olhado|proteccao espiritual)", 4),
    "Serviços mágicos suspeitos": (r"(sorte.*emprego|sorte.*negocio|sorte.*aposta|sorte.*jogo|apanhar ouro|pedras preciosas|ser famoso.*dias|recuperar bens roubados|faco tratamento|tratamento.*doencas|ligar whatsapp|asseguramento.*espiritual)", 3),
    "Contacto de curandeiro":   (r"(ligar whatsapp|whatsapp.*tratamento|contacto.*curandeiro|\d{9}.*ligar|\d{9}.*whatsapp|whatsapp.*\d{9}|marcar consulta)", 3),
}

RISK_CATEGORIES = {
    "Golpe de Emprego / Recrutamento Falso": [
        "Falsa oferta de emprego", "Promessa de vaga", "Contacto suspeito de RH",
        "Link de grupo WhatsApp", "Instruções suspeitas"
    ],
    "Curanderismo / Golpe Tradicional": [
        "Curandeiro / Médico tradicional", "Promessa sobrenatural",
        "Serviços mágicos suspeitos", "Contacto de curandeiro"
    ],
    "Apostas / Aliciamento Digital": [
        "Promoção de apostas", "Incentivo a depósito", "Promessa de ganho fácil",
        "Domínio suspeito"
    ],
    "Golpe Financeiro / Phishing": [
        "Pedido urgente", "Pedido de dados", "Imitação de instituição", "Link encurtado"
    ],
    "Manipulação Social": [
        "Pedido de segredo", "Validação social falsa", "Urgência informal",
        "Linguagem informal aliciante"
    ],
    "Fake News / Desinformação": [
        "Boato alarmista", "Linguagem de pânico", "Falta de fonte"
    ],
}

# ============================================================
# ANÁLISE HEURÍSTICA DE LINKS — camada independente da API
# ============================================================

# Domínios legítimos conhecidos (whitelist básica)
TRUSTED_DOMAINS = {
    "google.com", "google.co.mz", "youtube.com", "facebook.com",
    "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "gov.mz", "mmo.co.mz", "vodacom.co.mz", "tmcel.co.mz",
    "emola.co.mz", "mpesa.co.mz", "wikipedia.org", "github.com",
    "microsoft.com", "apple.com", "amazon.com", "whatsapp.com",
    "streamlit.app", "streamlit.io",
}

# Palavras-chave suspeitas em URLs
SUSPICIOUS_URL_KEYWORDS = [
    "login", "signin", "verify", "confirm", "secure", "update",
    "account", "banking", "paypal", "mpesa", "emola", "mkesh",
    "password", "senha", "credential", "free", "prize", "winner",
    "click", "redirect", "token", "invite", "join", "promo",
    "bonus", "offer", "win", "earn", "money", "cash", "reward",
    "aposta", "casino", "bet", "slot", "play", "jogo",
    "vaga", "emprego", "rh", "recrutamento", "contratando",
]

# Extensões de ficheiros perigosos
DANGEROUS_EXTENSIONS = [
    ".exe", ".apk", ".bat", ".cmd", ".scr", ".vbs",
    ".zip", ".rar", ".js", ".jar", ".dmg",
]

# TLDs suspeitos frequentemente usados em phishing
SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
    ".click", ".link", ".work", ".date", ".party", ".loan",
    ".download", ".stream", ".gdn", ".win",
]


def _calculate_url_entropy(url: str) -> float:
    """Calcula a entropia de Shannon do URL — URLs gerados aleatoriamente têm alta entropia."""
    if not url:
        return 0.0
    freq = {}
    for c in url:
        freq[c] = freq.get(c, 0) + 1
    length = len(url)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 2)


def analyze_url_heuristic(url: str) -> dict:
    """
    Análise heurística do URL sem depender de APIs externas.
    Verifica estrutura, domínio, parâmetros, entropia e palavras-chave.
    Retorna um dicionário com score de suspeita, razões e nível de risco.
    """
    result = {
        "heuristic_score": 0,
        "heuristic_reasons": [],
        "heuristic_level": "Baixo",
        "is_trusted": False,
    }

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full_url_lower = url.lower()

        # --- 1. Verificar se é domínio confiável ---
        base_domain = ".".join(domain.split(".")[-2:]) if domain.count(".") >= 1 else domain
        if base_domain in TRUSTED_DOMAINS:
            result["is_trusted"] = True
            result["heuristic_level"] = "Confiável"
            return result

        # --- 2. Protocolo HTTP (não HTTPS) ---
        if parsed.scheme == "http":
            result["heuristic_score"] += 2
            result["heuristic_reasons"].append("Não usa HTTPS (conexão insegura)")

        # --- 3. TLD suspeito ---
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                result["heuristic_score"] += 3
                result["heuristic_reasons"].append(f"TLD suspeito: {tld}")
                break

        # --- 4. IP como domínio (em vez de nome) ---
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            result["heuristic_score"] += 4
            result["heuristic_reasons"].append("URL usa endereço IP em vez de domínio — sinal de phishing")

        # --- 5. Domínio muito longo ou com muitos hífens ---
        if len(domain) > 40:
            result["heuristic_score"] += 2
            result["heuristic_reasons"].append("Domínio excessivamente longo")
        if domain.count("-") >= 3:
            result["heuristic_score"] += 2
            result["heuristic_reasons"].append("Domínio com muitos hífens — padrão comum em phishing")

        # --- 6. Subdomínios excessivos (ex: secure.login.bank.xyz.com) ---
        subdomain_count = domain.count(".") - 1
        if subdomain_count >= 3:
            result["heuristic_score"] += 2
            result["heuristic_reasons"].append(f"Muitos subdomínios ({subdomain_count}) — padrão suspeito")

        # --- 7. Palavras-chave suspeitas no URL ---
        found_keywords = []
        for kw in SUSPICIOUS_URL_KEYWORDS:
            if kw in full_url_lower:
                found_keywords.append(kw)
        if found_keywords:
            score_kw = min(len(found_keywords) * 2, 6)
            result["heuristic_score"] += score_kw
            result["heuristic_reasons"].append(f"Palavras suspeitas no URL: {', '.join(found_keywords[:5])}")

        # --- 8. Extensão de ficheiro perigosa ---
        for ext in DANGEROUS_EXTENSIONS:
            if path.endswith(ext):
                result["heuristic_score"] += 4
                result["heuristic_reasons"].append(f"Link aponta para ficheiro perigoso ({ext})")
                break

        # --- 9. Muitos parâmetros na query string ---
        params = parse_qs(query)
        if len(params) >= 5:
            result["heuristic_score"] += 2
            result["heuristic_reasons"].append(f"Muitos parâmetros na URL ({len(params)}) — pode ser rastreamento ou redirecionamento")

        # --- 10. Parâmetros suspeitos na query string ---
        suspicious_params = ["token", "verify", "confirm", "redirect", "url", "goto", "next", "redir"]
        found_params = [p for p in suspicious_params if p in params]
        if found_params:
            result["heuristic_score"] += 3
            result["heuristic_reasons"].append(f"Parâmetros suspeitos: {', '.join(found_params)}")

        # --- 11. Entropia alta (URL gerado aleatoriamente) ---
        path_entropy = _calculate_url_entropy(path + query)
        if path_entropy > 4.2:
            result["heuristic_score"] += 2
            result["heuristic_reasons"].append(f"URL com estrutura aleatória suspeita (entropia: {path_entropy})")

        # --- 12. Link encurtador ---
        shortener_pattern = re.compile(SHORTENERS)
        if shortener_pattern.search(domain):
            result["heuristic_score"] += 3
            result["heuristic_reasons"].append("Serviço de encurtamento de links — destino real desconhecido")

        # --- 13. Imitação de domínios conhecidos (typosquatting) ---
        typosquat_targets = ["mpesa", "emola", "vodacom", "tmcel", "google", "facebook", "paypal", "banco"]
        for target in typosquat_targets:
            if target in domain and base_domain not in TRUSTED_DOMAINS:
                result["heuristic_score"] += 4
                result["heuristic_reasons"].append(f"Possível imitação de '{target}' (typosquatting)")
                break

        # --- Calcular nível final ---
        score = result["heuristic_score"]
        if score >= 8:
            result["heuristic_level"] = "Alto Risco"
        elif score >= 5:
            result["heuristic_level"] = "Médio Risco"
        elif score >= 2:
            result["heuristic_level"] = "Baixo Risco"
        else:
            result["heuristic_level"] = "Aparentemente Seguro"

    except Exception as e:
        result["heuristic_reasons"].append(f"Erro na análise heurística: {e}")

    return result


def extract_links(text: str):
    return re.findall(r"http[s]?://\S+", text)


def is_whatsapp_phishing(url: str) -> bool:
    suspicious_wa_patterns = [
        r"wa\.me/\d+",
        r"whatsapp\.com/send\?phone=",
        r"api\.whatsapp\.com",
        r"whatsapp.*\?(token|invite|join|verify|confirm|code)=",
        r"wa\.me/.*\?text=",
    ]
    for pattern in suspicious_wa_patterns:
        if re.search(pattern, url.lower()):
            return True
    return False


def check_link_safety(url: str) -> dict:
    """
    Verificação completa de um link em 7 camadas:
      1. Análise heurística local    (sempre)
      2. Detecção de WhatsApp phishing
      3. URL Expander                — expande bit.ly/abre.ai/etc. e re-analisa destino
      4. WHOIS / Idade do domínio   — domínios com < 30 dias = risco alto
      5. Google Safe Browsing API
      6. Google Web Risk API
      7. VirusTotal                  — 90+ motores antivírus
    """
    # ── Camada 1: Heurística local ──────────────────────────────────────────────
    heuristic = analyze_url_heuristic(url)

    result = {
        "status": "Seguro",
        "threat_type": None,
        "whatsapp_phishing": False,
        "score_bonus": 0,
        "heuristic_level": heuristic["heuristic_level"],
        "heuristic_reasons": heuristic["heuristic_reasons"],
        "heuristic_score": heuristic["heuristic_score"],
        "is_trusted": heuristic.get("is_trusted", False),
        "verified_by": [],
        # Campos novos
        "expanded_url": None,
        "expansion_chain": [],
        "whois": {},
        "virustotal": {},
    }

    if heuristic.get("is_trusted"):
        result["status"] = "Confiável"
        return result

    h_score = heuristic["heuristic_score"]
    if h_score >= 8:
        result["status"] = "Suspeito — Alto Risco"
        result["score_bonus"] = min(h_score, 6)
    elif h_score >= 5:
        result["status"] = "Suspeito — Médio Risco"
        result["score_bonus"] = 3
    elif h_score >= 2:
        result["status"] = "Baixo Risco"
        result["score_bonus"] = 1

    # ── Camada 2: WhatsApp phishing ─────────────────────────────────────────────
    if is_whatsapp_phishing(url):
        result["whatsapp_phishing"] = True
        result["status"] = "Suspeito — WhatsApp Phishing"
        result["threat_type"] = "WhatsApp Phishing"
        result["score_bonus"] = max(result["score_bonus"], 4)

    # ── Camada 3: URL Expander ───────────────────────────────────────────────────
    # URL que será usado nas camadas seguintes (pode ser o destino expandido)
    analysis_url = url
    if _HAS_EXPANDER and _is_shortener(url):
        try:
            expansion = expand_url(url)
            if expansion["expanded"] and expansion["final"] != url:
                analysis_url = expansion["final"]
                result["expanded_url"] = analysis_url
                result["expansion_chain"] = expansion["chain"]
                result["heuristic_reasons"].append(
                    f"Link encurtado expandido → {analysis_url[:80]}"
                )
                # Re-analisa o destino real heuristicamente
                h2 = analyze_url_heuristic(analysis_url)
                if not h2.get("is_trusted") and h2["heuristic_score"] > h_score:
                    result["heuristic_score"] = h2["heuristic_score"]
                    result["heuristic_reasons"] += [
                        f"[URL real] {r}" for r in h2["heuristic_reasons"]
                    ]
                    extra = h2["heuristic_score"] - h_score
                    result["score_bonus"] += min(extra, 4)
                    if h2["heuristic_score"] >= 8:
                        result["status"] = "Suspeito — Alto Risco"
            elif expansion.get("error"):
                result["heuristic_reasons"].append(
                    f"Não foi possível expandir o link encurtado: {expansion['error']}"
                )
        except Exception as e:
            logger.warning(f"URL Expander erro: {e}")

    # ── Camada 4: WHOIS / Idade do domínio ──────────────────────────────────────
    if _HAS_WHOIS:
        try:
            whois = check_domain_age(analysis_url)
            result["whois"] = whois
            if whois.get("risk_score", 0) > 0:
                result["score_bonus"] += whois["risk_score"]
                if whois.get("risk_reason"):
                    result["heuristic_reasons"].append(f"WHOIS: {whois['risk_reason']}")
                if whois["risk_score"] >= 5:
                    result["status"] = "Suspeito — Alto Risco"
                    result["threat_type"] = result["threat_type"] or "Domínio muito recente"
                    if "WHOIS / Domínio recente" not in result["verified_by"]:
                        result["verified_by"].append("WHOIS / Domínio recente")
        except Exception as e:
            logger.warning(f"WHOIS erro para {analysis_url}: {e}")

    # ── Camada 5: Google Safe Browsing API ──────────────────────────────────────
    if API_KEY:
        try:
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
            payload = {
                "client": {"clientId": "phishing_monitor", "clientVersion": "1.3"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE", "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": analysis_url}],
                },
            }
            resp = requests.post(endpoint, json=payload, timeout=5)
            data = resp.json()
            if "matches" in data:
                threat = data["matches"][0].get("threatType", "AMEAÇA DETECTADA")
                result["status"] = "Perigoso"
                result["threat_type"] = threat
                result["score_bonus"] = 8
                result["verified_by"].append("Google Safe Browsing")
        except Exception as e:
            result["api_error_sb"] = str(e)

    # ── Camada 6: Google Web Risk API ───────────────────────────────────────────
    WEB_RISK_KEY = os.getenv("GOOGLE_WEB_RISK_API_KEY", "")
    if WEB_RISK_KEY and result["status"] != "Perigoso":
        try:
            from urllib.parse import quote
            encoded_url = quote(analysis_url, safe="")
            endpoint = (
                f"https://webrisk.googleapis.com/v1/uris:search"
                f"?key={WEB_RISK_KEY}"
                f"&threatTypes=MALWARE"
                f"&threatTypes=SOCIAL_ENGINEERING"
                f"&threatTypes=UNWANTED_SOFTWARE"
                f"&uri={encoded_url}"
            )
            resp = requests.get(endpoint, timeout=5)
            data = resp.json()
            if "threat" in data:
                threat_types_found = data["threat"].get("threatTypes", ["AMEAÇA DETECTADA"])
                threat = ", ".join(threat_types_found)
                result["status"] = "Perigoso"
                result["threat_type"] = f"Web Risk: {threat}"
                result["score_bonus"] = 8
                result["verified_by"].append("Google Web Risk")
        except Exception as e:
            result["api_error_wr"] = str(e)

    # ── Camada 7: VirusTotal ─────────────────────────────────────────────────────
    if _HAS_VT and result["status"] != "Perigoso":
        try:
            vt = vt_check_url(analysis_url)
            result["virustotal"] = vt
            if vt.get("available") and vt.get("risk_score", 0) > 0:
                result["score_bonus"] += vt["risk_score"]
                vt_summary = (
                    f"VirusTotal: {vt['verdict']} — "
                    f"{vt['malicious']}/{vt['total_engines']} motores"
                )
                if vt["threat_names"]:
                    vt_summary += f" ({', '.join(vt['threat_names'][:2])})"
                result["heuristic_reasons"].append(vt_summary)

                if vt["verdict"] == "Malicioso":
                    result["status"] = "Perigoso"
                    result["threat_type"] = (
                        ", ".join(vt["threat_names"][:2]) if vt["threat_names"]
                        else "VirusTotal: Malicioso"
                    )
                    result["score_bonus"] = max(result["score_bonus"], 8)
                    result["verified_by"].append("VirusTotal")
                elif vt["verdict"] == "Suspeito" and "Suspeito" not in result["status"]:
                    result["status"] = "Suspeito — Médio Risco"
                    result["verified_by"].append("VirusTotal")
        except Exception as e:
            logger.warning(f"VirusTotal erro: {e}")

    return result


def detect_patterns(normalized_text: str) -> dict:
    detected = []
    weighted_score = 0
    for name, (pattern, weight) in PATTERNS.items():
        if re.search(pattern, normalized_text):
            detected.append(name)
            weighted_score += weight

    risk_type = "Baixo ou Nenhum Risco"
    for category, patterns in RISK_CATEGORIES.items():
        if any(p in detected for p in patterns):
            risk_type = category
            break

    return {"patterns_detected": detected, "weighted_score": weighted_score, "risk_type": risk_type}


def calculate_risk_level(score: int, meta: dict) -> tuple[str, int]:
    bonus = 0
    if meta["uppercase_ratio"] > 0.5:
        bonus += 1
    if meta["exclamations"] >= 3:
        bonus += 1
    if meta["emojis"] >= 3:
        bonus += 1
    if meta["mixed_scripts"]:
        bonus += 2

    final_score = score + bonus

    if final_score >= 8:
        level = "Alto"
    elif final_score >= 4:
        level = "Médio"
    elif final_score >= 1:
        level = "Baixo"
    else:
        level = "Nenhum"

    return level, final_score


def analyze_message(text: str, phone_number: str = None, image_b64: str = None, image_mime: str = "image/jpeg") -> dict:
    """
    Pipeline completo de análise:
    1. Normaliza texto
    2. Detecta padrões com pesos
    3. Verifica blacklist
    4. Verifica links (heurística + APIs + VT + WHOIS + expansão)
    5. Predição ML — usa texto E imagem directamente se OCR falhou
    """
    meta = preprocess(text) if text.strip() else {
        "normalized": "", "uppercase_ratio": 0,
        "exclamations": 0, "emojis": 0, "mixed_scripts": False
    }
    normalized = meta["normalized"]

    pattern_result = detect_patterns(normalized)
    detected_patterns = pattern_result["patterns_detected"]
    risk_type = pattern_result["risk_type"]
    weighted_score = pattern_result["weighted_score"]

    risk_level, final_score = calculate_risk_level(weighted_score, meta)

    # Verificar blacklist
    blacklisted = False
    if phone_number and phone_number.strip():
        blacklisted = is_blacklisted(phone_number.strip())
        if blacklisted:
            risk_level = "Alto"
            final_score = max(final_score, 10)
            if "Número na blacklist" not in detected_patterns:
                detected_patterns.append("Número na blacklist")

    # Verificar links — 7 camadas
    link_results = {}
    for link in extract_links(text):
        link_check = check_link_safety(link)
        link_results[link] = link_check

        if link_check["score_bonus"] > 0:
            final_score += link_check["score_bonus"]
            if link_check["score_bonus"] >= 4:
                risk_level = "Alto"
            elif risk_level == "Nenhum":
                risk_level = "Baixo"

            if link_check["whatsapp_phishing"] and "Link de WhatsApp suspeito" not in detected_patterns:
                detected_patterns.append("Link de WhatsApp suspeito")
                risk_type = "Golpe Financeiro / Phishing"

            if link_check["status"] == "Perigoso" and "Link perigoso confirmado" not in detected_patterns:
                detected_patterns.append("Link perigoso confirmado")
                risk_type = "Golpe Financeiro / Phishing"

            if "Alto Risco" in str(link_check.get("status", "")) and "Link suspeito (análise heurística)" not in detected_patterns:
                detected_patterns.append("Link suspeito (análise heurística)")

            # Sinalizar domínio muito recente (WHOIS)
            whois = link_check.get("whois", {})
            if whois.get("risk_score", 0) >= 5 and "Domínio recém-criado (WHOIS)" not in detected_patterns:
                detected_patterns.append("Domínio recém-criado (WHOIS)")

            # Sinalizar detecção VirusTotal
            vt = link_check.get("virustotal", {})
            if vt.get("verdict") == "Malicioso" and "Malware confirmado (VirusTotal)" not in detected_patterns:
                detected_patterns.append("Malware confirmado (VirusTotal)")
                risk_type = "Golpe Financeiro / Phishing"

    # Predição ML — passa imagem se texto for insuficiente
    use_image = image_b64 and len(normalized.split()) < 5
    ml_results = predict_all(normalized, image_b64=image_b64 if use_image else None, image_mime=image_mime)

    ml_decision = ml_results.get("final_decision")
    if ml_decision and ml_decision not in ("Baixo ou Nenhum Risco", "Mensagem Normal / Segura"):
        if final_score < 4 or (use_image and final_score == 0):
            risk_type = ml_decision
            final_score = max(final_score, 4)
            risk_level = "Médio" if final_score < 8 else "Alto"
            if "Padrão detectado pelo ML" not in detected_patterns:
                detected_patterns.append("Padrão detectado pelo ML")
        elif final_score >= 4 and risk_type == "Baixo ou Nenhum Risco":
            risk_type = ml_decision

    # Se Gemini detectou texto na imagem e não tínhamos texto, actualiza
    gemini_result = ml_results.get("gemini", {})
    if gemini_result.get("texto_detectado") and not text.strip():
        text = gemini_result["texto_detectado"]

    # Alerta educativo
    if risk_type == "Golpe de Emprego / Recrutamento Falso":
        educational_alert = (
            "⚠️ ATENÇÃO: Este tipo de mensagem é um golpe de emprego muito comum! "
            "Empresas legítimas NUNCA recrutam através de grupos de WhatsApp nem pedem "
            "para clicar em links para 'entrar no grupo'. "
            "Nunca envies os teus documentos (BI, CV) a desconhecidos. "
            "Verifica sempre a empresa em fontes oficiais antes de qualquer contacto."
        )
    elif risk_type == "Curanderismo / Golpe Tradicional":
        educational_alert = (
            "⚠️ ATENÇÃO: Esta mensagem apresenta características de golpe de curanderismo! "
            "Promessas de riqueza rápida, sorte, amor ou cura através de práticas espirituais "
            "são esquemas para extorquir dinheiro de pessoas vulneráveis. "
            "Nenhum 'médico tradicional' ou 'curandeiro' pode garantir riqueza, emprego ou amor. "
            "Não contactes este número nem faças qualquer pagamento. "
            "Em Moçambique podes denunciar à PRM (Polícia da República de Moçambique)."
        )
    elif risk_type in ["Golpe Financeiro / Phishing", "Manipulação Social"]:
        educational_alert = (
            "⚠️ Esta mensagem apresenta características de phishing ou manipulação social. "
            "Nunca cliques em links suspeitos nem partilhes dados pessoais ou bancários. "
            "Confirme sempre junto de fontes oficiais antes de qualquer acção."
        )
    else:
        educational_alert = (
            "Mensagens com padrões suspeitos, links encurtados ou promessas de ganho fácil "
            "são frequentemente associadas a golpes ou desinformação. "
            "Nunca cliques em links de fontes desconhecidas nem partilhes dados pessoais. "
            "Confirme sempre junto de fontes oficiais antes de qualquer ação."
        )

    result = {
        "score": final_score,
        "risk_level": risk_level,
        "risk_type": risk_type,
        "reasons": detected_patterns,
        "educational_alert": educational_alert,
        "link_results": link_results,
        "blacklisted": blacklisted,
        "ml_results": ml_results,
        "meta": {
            "uppercase_ratio": meta["uppercase_ratio"],
            "exclamations": meta["exclamations"],
            "emojis": meta["emojis"],
            "mixed_scripts": meta["mixed_scripts"],
        },
    }

    log_id = save_analysis(text, result, phone_number=phone_number)
    result["log_id"] = log_id
    return result