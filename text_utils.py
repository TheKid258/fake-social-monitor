"""
text_utils.py
Utilitários de normalização e pré-processamento de texto
para melhorar a detecção de padrões suspeitos.
"""

import re
import unicodedata


# ----------------------------
# Normalização base
# ----------------------------

def normalize_text(text: str) -> str:
    """
    Normaliza o texto para análise:
    - Converte para minúsculas
    - Remove acentos
    - Remove caracteres especiais desnecessários
    - Colapsa espaços múltiplos
    """
    text = text.lower()
    text = remove_accents(text)
    text = remove_extra_spaces(text)
    return text


def remove_accents(text: str) -> str:
    """
    Remove acentos mantendo as letras base.
    Ex: 'confirmação' → 'confirmacao'
    Útil para detectar padrões mesmo com variações ortográficas.
    """
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def remove_extra_spaces(text: str) -> str:
    """Remove espaços múltiplos e espaços no início/fim"""
    return re.sub(r"\s+", " ", text).strip()


# ----------------------------
# Detecção de ofuscação
# ----------------------------

def normalize_obfuscation(text: str) -> str:
    """
    Detecta e normaliza técnicas comuns de ofuscação usadas em phishing.
    Ex: 'c l i q u e' → 'clique'
         'urgenteee' → 'urgente' (repetição excessiva de letras)
         '@' usado como 'a', '0' como 'o', '3' como 'e', etc.
    """
    # Substituições de caracteres leetspeak comuns
    LEET_MAP = {
        "@": "a",
        "0": "o",
        "3": "e",
        "1": "i",
        "5": "s",
        "$": "s",
        "4": "a",
        "7": "t",
    }
    for char, replacement in LEET_MAP.items():
        text = text.replace(char, replacement)

    # Remove espaços entre letras individuais: "c l i q u e" → "clique"
    text = re.sub(r"(?<!\w)(\w) (\w)(?!\w)", r"\1\2", text)
    # Aplica duas vezes para apanhar sequências mais longas
    text = re.sub(r"(?<!\w)(\w) (\w)(?!\w)", r"\1\2", text)

    # Colapsa letras repetidas excessivamente: "urgenteee" → "urgente"
    text = re.sub(r"(.)\1{2,}", r"\1", text)

    return text


# ----------------------------
# Extracção de metadados do texto
# ----------------------------

def count_exclamations(text: str) -> int:
    """Conta pontos de exclamação — indicador de linguagem sensacionalista"""
    return text.count("!")


def count_emojis(text: str) -> int:
    """Conta emojis no texto"""
    emoji_pattern = re.compile(
        "[\U00010000-\U0010ffff"
        "\U0001F600-\U0001F64F"
        "\U0001F300-\U0001F5FF"
        "\U0001F680-\U0001F6FF"
        "\U0001F1E0-\U0001F1FF]+",
        flags=re.UNICODE,
    )
    return len(emoji_pattern.findall(text))


def count_uppercase_ratio(text: str) -> float:
    """
    Calcula a proporção de letras maiúsculas no texto.
    Textos com muitas maiúsculas são frequentemente associados a alarme falso.
    Retorna valor entre 0.0 e 1.0
    """
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    uppercase = [c for c in letters if c.isupper()]
    return round(len(uppercase) / len(letters), 2)


def has_mixed_scripts(text: str) -> bool:
    """
    Detecta uso de caracteres de diferentes alfabetos no mesmo texto
    (ex: latim + cirílico), técnica usada para enganar filtros.
    """
    scripts = set()
    for char in text:
        name = unicodedata.name(char, "")
        if "LATIN" in name:
            scripts.add("LATIN")
        elif "CYRILLIC" in name:
            scripts.add("CYRILLIC")
        elif "ARABIC" in name:
            scripts.add("ARABIC")
        elif "GREEK" in name:
            scripts.add("GREEK")
    return len(scripts) > 1


# ----------------------------
# Pipeline completo
# ----------------------------

def preprocess(text: str) -> dict:
    """
    Executa o pipeline completo de pré-processamento e devolve
    o texto normalizado mais metadados úteis para a análise.

    Retorna:
        {
            "original": str,
            "normalized": str,
            "exclamations": int,
            "emojis": int,
            "uppercase_ratio": float,
            "mixed_scripts": bool
        }
    """
    normalized = normalize_obfuscation(normalize_text(text))

    return {
        "original": text,
        "normalized": normalized,
        "exclamations": count_exclamations(text),
        "emojis": count_emojis(text),
        "uppercase_ratio": count_uppercase_ratio(text),
        "mixed_scripts": has_mixed_scripts(text),
    }
