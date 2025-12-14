import re
import requests
from database import save_analysis

API_KEY = "SUA_CHAVE_GOOGLE_SAFE_BROWSING"  # Substitua pela sua chave real

# ----------------------------
# Padrões linguísticos
# ----------------------------
SHORTENERS = r"(abre\.ai|bit\.ly|tinyurl|t\.co|is\.gd)"

PATTERNS = {
    # Fake News / Desinformação
    "Boato alarmista": r"(vai fechar|contas bloqueadas|último aviso|informação interna)",
    "Linguagem de pânico": r"(partilha|espalha|antes que apaguem)",
    "Falta de fonte": r"(ninguém fala|não mostram na tv|segredo)",

    # Golpes / Phishing
    "Pedido urgente": r"(urgente|agora|imediatamente)",
    "Pedido de dados": r"(confirme|actualize|envie seus dados)",
    "Imitação de instituição": r"(mpesa|emola|mkesh|banco)",
    "Link encurtado": SHORTENERS,
    "Link externo": r"http[s]?://",

    # Apostas / Aliciamento
    "Promoção de apostas": r"(aposta|jogo|casino|avia[oõ]zinho|jtx)",
    "Incentivo a depósito": r"(deposita|carrega|investe)",
    "Promessa de ganho fácil": r"(ganha dinheiro|lucro garantido|dinheiro rápido)",
    "Convite emocional": r"(venha se divertir|não perca|aproveite)",

    # Spam
    "Linguagem sensacionalista": r"(!!!|💰|🔥|\$\$\$)"
}

# ----------------------------
# Funções auxiliares
# ----------------------------
def extract_links(text):
    """Detecta links no texto"""
    return re.findall(r"http[s]?://\S+", text)

def check_link_safety(url):
    """Verifica link com Google Safe Browsing"""
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
    payload = {
        "client": {"clientId": "fake_news_monitor", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        resp = requests.post(endpoint, json=payload)
        data = resp.json()
        if "matches" in data:
            return "Perigoso"
        else:
            return "Seguro"
    except Exception as e:
        return f"Erro: {e}"

def detect_patterns(text: str):
    text_lower = text.lower()
    detected = []

    for name, pattern in PATTERNS.items():
        if re.search(pattern, text_lower):
            detected.append(name)

    # Classificação do tipo de risco
    if any(p in detected for p in ["Promoção de apostas", "Incentivo a depósito", "Promessa de ganho fácil"]):
        risk_type = "Apostas / Aliciamento Digital"
    elif any(p in detected for p in ["Pedido urgente", "Pedido de dados", "Imitação de instituição", "Link encurtado"]):
        risk_type = "Golpe Financeiro / Phishing"
    elif any(p in detected for p in ["Boato alarmista", "Linguagem de pânico", "Falta de fonte"]):
        risk_type = "Fake News / Desinformação"
    else:
        risk_type = "Baixo ou Nenhum Risco"

    educational_alert = (
        "Mensagens com padrões suspeitos, links encurtados ou promessas de ganho fácil "
        "são frequentemente associadas a golpes ou desinformação. "
        "Confirme sempre junto de fontes oficiais antes de qualquer ação."
    )

    return {
        "patterns_detected": detected,
        "risk_type": risk_type,
        "educational_alert": educational_alert
    }

# ----------------------------
# Função principal
# ----------------------------
def analyze_message(text: str):
    analysis = detect_patterns(text)
    detected_patterns = analysis["patterns_detected"]
    risk_type = analysis["risk_type"]
    educational_alert = analysis["educational_alert"]

    score = len(detected_patterns)
    if score >= 5:
        risk_level = "Alto"
    elif score >= 3:
        risk_level = "Médio"
    elif score >= 1:
        risk_level = "Baixo"
    else:
        risk_level = "Nenhum"

    # Verificação de links
    link_results = {}
    links = extract_links(text)
    for link in links:
        link_results[link] = check_link_safety(link)

    result = {
        "score": score,
        "risk_level": risk_level,
        "risk_type": risk_type,
        "reasons": detected_patterns,
        "educational_alert": educational_alert,
        "link_results": link_results
    }

    save_analysis(text, result)
    return result
