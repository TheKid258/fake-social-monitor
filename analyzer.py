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

PATTERNS = {
    "Boato alarmista":        (r"(vai fechar|contas bloqueadas|ultimo aviso|informacao interna)", 2),
    "Linguagem de pânico":    (r"(partilha|espalha|antes que apaguem)",                          2),
    "Falta de fonte":         (r"(ninguem fala|nao mostram na tv|segredo)",                       1),
    "Pedido urgente":         (r"(urgente|agora|imediatamente)",                                  2),
    "Pedido de dados":        (r"(confirme|actualize|envie seus dados|palavra.passe|senha)",      3),
    "Imitação de instituição":(r"(mpesa|emola|mkesh|banco|paypal|gov\.mz)",                      2),
    "Link encurtado":         (SHORTENERS,                                                        2),
    "Link externo":           (r"http[s]?://",                                                    1),
    "Promoção de apostas":    (r"(aposta|jogo|casino|aviaozinho|jtx|bet)",                       2),
    "Incentivo a depósito":   (r"(deposita|carrega|investe)",                                    2),
    "Promessa de ganho fácil":(r"(ganha dinheiro|lucro garantido|dinheiro rapido|100%)",         3),
    "Convite emocional":      (r"(venha se divertir|nao perca|aproveite)",                       1),
    "Linguagem sensacionalista": (r"(!!!|💰|🔥|\$\$\$)",                                        1),
}

RISK_CATEGORIES = {
    "Apostas / Aliciamento Digital": [
        "Promoção de apostas", "Incentivo a depósito", "Promessa de ganho fácil"
    ],
    "Golpe Financeiro / Phishing": [
        "Pedido urgente", "Pedido de dados", "Imitação de instituição", "Link encurtado"
    ],
    "Fake News / Desinformação": [
        "Boato alarmista", "Linguagem de pânico", "Falta de fonte"
    ],
}


def extract_links(text: str):
    return re.findall(r"http[s]?://\S+", text)


def check_link_safety(url: str) -> str:
    if not API_KEY:
        return "API Key não configurada"
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
    payload = {
        "client": {"clientId": "phishing_monitor", "clientVersion": "1.1"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=5)
        data = resp.json()
        return "Perigoso" if "matches" in data else "Seguro"
    except Exception as e:
        return f"Erro: {e}"


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
    Se o número estiver na blacklist, o risco é automaticamente Alto.
    """
    meta = preprocess(text)
    normalized = meta["normalized"]

    pattern_result = detect_patterns(normalized)
    detected_patterns = pattern_result["patterns_detected"]
    risk_type = pattern_result["risk_type"]
    weighted_score = pattern_result["weighted_score"]

    risk_level, final_score = calculate_risk_level(weighted_score, meta)

    # Verificar blacklist — se o número for conhecido, eleva o risco
    blacklisted = False
    if phone_number and phone_number.strip():
        blacklisted = is_blacklisted(phone_number.strip())
        if blacklisted:
            risk_level = "Alto"
            final_score = max(final_score, 10)
            if "Número na blacklist" not in detected_patterns:
                detected_patterns.append("Número na blacklist")

    link_results = {}
    for link in extract_links(text):
        link_results[link] = check_link_safety(link)

    educational_alert = (
        "Mensagens com padrões suspeitos, links encurtados ou promessas de ganho fácil "
        "são frequentemente associadas a golpes ou desinformação. "
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
