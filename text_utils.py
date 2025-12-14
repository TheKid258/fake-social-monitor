import re

SHORTENERS = r"(abre\.ai|bit\.ly|tinyurl|t\.co|is\.gd)"
PATTERNS = {
    "Boato alarmista": r"(vai fechar|contas bloqueadas|último aviso|informação interna)",
    "Linguagem de pânico": r"(partilha|espalha|antes que apaguem)",
    "Falta de fonte": r"(ninguém fala|não mostram na tv|segredo)",
    "Pedido urgente": r"(urgente|agora|imediatamente)",
    "Pedido de dados": r"(confirme|actualize|envie seus dados)",
    "Imitação de instituição": r"(mpesa|emola|mkesh|banco)",
    "Link encurtado": SHORTENERS,
    "Link externo": r"http[s]?://",
    "Promoção de apostas": r"(aposta|jogo|casino|avia[oõ]zinho|jtx)",
    "Incentivo a depósito": r"(deposita|carrega|investe)",
    "Promessa de ganho fácil": r"(ganha dinheiro|lucro garantido|dinheiro rápido)",
    "Convite emocional": r"(venha se divertir|não perca|aproveite)",
    "Linguagem sensacionalista": r"(!!!|💰|🔥|\$\$\$)"
}

def detect_patterns(text: str):
    text = text.lower()
    detected = []

    for name, pattern in PATTERNS.items():
        if re.search(pattern, text):
            detected.append(name)

    # Classificação de risco
    if any(p in detected for p in ["Promoção de apostas","Incentivo a depósito","Promessa de ganho fácil"]):
        risk_type = "Apostas / Aliciamento Digital"
    elif any(p in detected for p in ["Pedido urgente","Pedido de dados","Imitação de instituição","Link encurtado"]):
        risk_type = "Golpe Financeiro / Phishing"
    elif any(p in detected for p in ["Boato alarmista","Linguagem de pânico","Falta de fonte"]):
        risk_type = "Fake News / Desinformação"
    else:
        risk_type = "Baixo ou Nenhum Risco"

    return {
        "patterns_detected": detected,
        "risk_type": risk_type
    }

def extract_links(text: str):
    """Extrai todos os links do texto."""
    return re.findall(r'http[s]?://\S+', text)
