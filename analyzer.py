"""
analyzer.py
Módulo principal de análise de mensagens suspeitas.
"""

import re
import os
import requests
from dotenv import load_dotenv

from database import save_analysis, is_blacklisted
from text_utils import preprocess

load_dotenv()
API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

SHORTENERS = r"(abre\.ai|bit\.ly|tinyurl|t\.co|is\.gd)"

# Domínios suspeitos de apostas comuns em Moçambique
SUSPICIOUS_DOMAINS = r"(apostasdemoz|apostas\w+\.com|bet\w+\.com|jogo\w+\.com|casino\w+\.com|play\w+\.mz)"

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

    # Apostas / Aliciamento
    "Promoção de apostas":      (r"(aposta|jogo|casino|aviaozinho|jtx|bet|play|slot)",               2),
    "Incentivo a depósito":     (r"(deposita|carrega|investe|recarga)",                              2),
    "Promessa de ganho fácil":  (r"(ganha dinheiro|lucro garantido|dinheiro rapido|100%|funciona mesmo|ta funcionando|ta a funcionar)", 3),
    "Convite emocional":        (r"(venha se divertir|nao perca|aproveite|ve so|ve aqui|olha so)",   1),

    # Manipulação social — NOVOS
    "Pedido de segredo":        (r"(nao conta|nao contar|nao diz|guardar segredo|entre nos|so nos|melhor nao contar|nao fala pra ninguem|nao fales a ninguem)", 3),
    "Validação social falsa":   (r"(funciona mesmo|ja tentei|ja usei|e verdade|testei|comprovado|confirmado|funciona de verdade)", 2),
    "Linguagem informal aliciante": (r"(bro|mano|parceiro|amigo|cara|ve so|olha so|acredita|confia)", 1),
    "Urgência informal":        (r"(ve o que ta|ve o que esta|acontecendo agora|agora mesmo|neste momento|so agora)", 2),

    # Spam
    "Linguagem sensacionalista": (r"(!!!|💰|🔥|\$\$\$|😱|🤑)",                                      1),
}

RISK_CATEGORIES = {
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


def extract_links(text: str):
    return re.findall(r"http[s]?://\S+", text)


def is_whatsapp_phishing(url: str) -> bool:
    """
    Detecta links de WhatsApp usados para phishing.
    Padrões conhecidos:
    - wa.me/<número> — links de convite directo para chat
    - whatsapp.com/... — links suspeitos da plataforma
    - links com parâmetros suspeitos como ?phone=, ?invite=
    """
    suspicious_wa_patterns = [
        r"wa\.me/\d+",                          # wa.me/258xxxxxxx
        r"whatsapp\.com/send\?phone=",           # link de envio directo
        r"api\.whatsapp\.com",                   # API não oficial
        r"whatsapp.*\?(token|invite|join|verify|confirm|code)=",  # parâmetros suspeitos
        r"wa\.me/.*\?text=",                     # link com texto pré-preenchido
    ]
    for pattern in suspicious_wa_patterns:
        if re.search(pattern, url.lower()):
            return True
    return False


def check_link_safety(url: str) -> dict:
    """
    Verifica a segurança de um link usando Google Safe Browsing API.
    Detecta também padrões de phishing de WhatsApp.
    Retorna dict com status, tipo de ameaça e se é WhatsApp phishing.
    """
    result = {
        "status": "Seguro",
        "threat_type": None,
        "whatsapp_phishing": False,
        "score_bonus": 0,
    }

    # Verificar padrões de WhatsApp phishing
    if is_whatsapp_phishing(url):
        result["whatsapp_phishing"] = True
        result["status"] = "Suspeito"
        result["threat_type"] = "WhatsApp Phishing"
        result["score_bonus"] = 4

    if not API_KEY:
        if result["status"] == "Seguro":
            result["status"] = "API Key não configurada"
        return result

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
    payload = {
        "client": {"clientId": "phishing_monitor", "clientVersion": "1.2"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
                "THREAT_TYPE_UNSPECIFIED",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=5)
        data = resp.json()
        if "matches" in data:
            match = data["matches"][0]
            threat = match.get("threatType", "AMEAÇA DETECTADA")
            result["status"] = "Perigoso"
            result["threat_type"] = threat
            result["score_bonus"] = 5  # Link perigoso confirmado pela API eleva o score
    except Exception as e:
        result["status"] = f"Erro: {e}"

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


def analyze_message(text: str, phone_number: str = None) -> dict:
    """
    Pipeline completo de análise.
    - Normaliza texto
    - Detecta padrões com pesos
    - Verifica blacklist
    - Verifica links via Google Safe Browsing
    - Resultado da API influencia directamente o score final
    """
    meta = preprocess(text)
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

    # Verificar links — resultado da API influencia o score
    link_results = {}
    for link in extract_links(text):
        link_check = check_link_safety(link)
        link_results[link] = link_check

        # Se o link for perigoso ou WhatsApp phishing, eleva o score
        if link_check["score_bonus"] > 0:
            final_score += link_check["score_bonus"]
            risk_level = "Alto"

            # Adicionar padrão detectado
            if link_check["whatsapp_phishing"] and "Link de WhatsApp suspeito" not in detected_patterns:
                detected_patterns.append("Link de WhatsApp suspeito")
                risk_type = "Golpe Financeiro / Phishing"

            if link_check["status"] == "Perigoso" and "Link perigoso confirmado (Google Safe Browsing)" not in detected_patterns:
                detected_patterns.append("Link perigoso confirmado (Google Safe Browsing)")
                risk_type = "Golpe Financeiro / Phishing"

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