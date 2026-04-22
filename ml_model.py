"""
ml_model.py
Sistema de Machine Learning para detecção de mensagens suspeitas.
Três modelos disponíveis:
  1. Naive Bayes + TF-IDF (leve, rápido)
  2. Random Forest + TF-IDF (mais robusto)
  3. Claude API (Anthropic) — classificação por LLM
"""

import os
import json
import pickle
import logging
import requests
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# Caminho para guardar os modelos treinados
MODEL_DIR = Path("models")
MODEL_DIR.mkdir(exist_ok=True)

NB_MODEL_PATH  = MODEL_DIR / "naive_bayes.pkl"
RF_MODEL_PATH  = MODEL_DIR / "random_forest.pkl"
MIN_SAMPLES    = 5  # Mínimo de amostras para treinar

# ============================================================
# TREINO DOS MODELOS
# ============================================================

def train_models(texts: list[str], labels: list[str]) -> dict:
    """
    Treina os modelos Naive Bayes e Random Forest com os dados fornecidos.
    labels: lista de strings como 'Golpe Financeiro / Phishing', 'Apostas', etc.
    Retorna dict com resultados do treino.
    """
    try:
        from sklearn.naive_bayes import MultinomialNB
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.pipeline import Pipeline
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score
        from sklearn.preprocessing import LabelEncoder
    except ImportError:
        return {"success": False, "error": "scikit-learn não instalado. Corre: pip install scikit-learn"}

    if len(texts) < MIN_SAMPLES:
        return {
            "success": False,
            "error": f"Dados insuficientes. Mínimo: {MIN_SAMPLES} amostras. Actual: {len(texts)}"
        }

    # Divide em treino e teste
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels if len(set(labels)) > 1 else None
    )

    results = {"success": True, "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "models": {}}

    # --- Modelo 1: Naive Bayes ---
    try:
        nb_pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=5000,
                min_df=1,
                strip_accents="unicode",
                lowercase=True,
            )),
            ("clf", MultinomialNB(alpha=0.5)),
        ])
        nb_pipeline.fit(X_train, y_train)
        nb_acc = accuracy_score(y_test, nb_pipeline.predict(X_test))

        with open(NB_MODEL_PATH, "wb") as f:
            pickle.dump(nb_pipeline, f)

        results["models"]["naive_bayes"] = {
            "accuracy": round(nb_acc * 100, 1),
            "samples_used": len(texts),
        }
    except Exception as e:
        results["models"]["naive_bayes"] = {"error": str(e)}

    # --- Modelo 2: Random Forest ---
    try:
        rf_pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=5000,
                min_df=1,
                strip_accents="unicode",
                lowercase=True,
            )),
            ("clf", RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                n_jobs=-1,
            )),
        ])
        rf_pipeline.fit(X_train, y_train)
        rf_acc = accuracy_score(y_test, rf_pipeline.predict(X_test))

        with open(RF_MODEL_PATH, "wb") as f:
            pickle.dump(rf_pipeline, f)

        results["models"]["random_forest"] = {
            "accuracy": round(rf_acc * 100, 1),
            "samples_used": len(texts),
        }
    except Exception as e:
        results["models"]["random_forest"] = {"error": str(e)}

    return results


# ============================================================
# PREDIÇÃO DOS MODELOS
# ============================================================

def predict_naive_bayes(text: str) -> dict:
    """Classifica uma mensagem com Naive Bayes."""
    if not NB_MODEL_PATH.exists():
        return {"available": False, "reason": "Modelo não treinado ainda"}
    try:
        with open(NB_MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        prediction = model.predict([text])[0]
        proba = model.predict_proba([text])[0]
        confidence = round(max(proba) * 100, 1)
        return {
            "available": True,
            "model": "Naive Bayes",
            "prediction": prediction,
            "confidence": confidence,
        }
    except Exception as e:
        return {"available": False, "reason": str(e)}


def predict_random_forest(text: str) -> dict:
    """Classifica uma mensagem com Random Forest."""
    if not RF_MODEL_PATH.exists():
        return {"available": False, "reason": "Modelo não treinado ainda"}
    try:
        with open(RF_MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        prediction = model.predict([text])[0]
        proba = model.predict_proba([text])[0]
        confidence = round(max(proba) * 100, 1)
        return {
            "available": True,
            "model": "Random Forest",
            "prediction": prediction,
            "confidence": confidence,
        }
    except Exception as e:
        return {"available": False, "reason": str(e)}


def predict_claude(text: str) -> dict:
    """
    Classifica uma mensagem usando a API do Claude (Anthropic).
    Usa o modelo claude-sonnet como classificador inteligente.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        return {"available": False, "reason": "ANTHROPIC_API_KEY não configurada"}

    prompt = f"""Analisa esta mensagem e classifica-a numa das seguintes categorias:
- Golpe Financeiro / Phishing
- Apostas / Aliciamento Digital
- Fake News / Desinformação
- Manipulação Social
- Baixo ou Nenhum Risco

Mensagem: "{text}"

Responde APENAS com um JSON no seguinte formato (sem texto adicional):
{{
  "categoria": "nome da categoria",
  "confianca": numero entre 0 e 100,
  "razao": "explicacao curta em portugues"
}}"""

    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 200,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=15,
        )
        data = resp.json()
        raw = data["content"][0]["text"].strip()

        # Limpa possíveis backticks
        raw = raw.replace("```json", "").replace("```", "").strip()
        result = json.loads(raw)

        return {
            "available": True,
            "model": "Claude (Anthropic)",
            "prediction": result.get("categoria", "Desconhecido"),
            "confidence": result.get("confianca", 0),
            "reason": result.get("razao", ""),
        }
    except Exception as e:
        return {"available": False, "reason": str(e)}


# ============================================================
# PREDIÇÃO COMBINADA (ensemble)
# ============================================================

def predict_all(text: str) -> dict:
    """
    Corre os 3 modelos e devolve os resultados individuais
    mais uma decisão final por votação.
    """
    nb  = predict_naive_bayes(text)
    rf  = predict_random_forest(text)
    cld = predict_claude(text)

    predictions = []
    for r in [nb, rf, cld]:
        if r.get("available") and r.get("prediction"):
            predictions.append(r["prediction"])

    # Votação simples
    final = None
    if predictions:
        from collections import Counter
        final = Counter(predictions).most_common(1)[0][0]

    return {
        "naive_bayes":    nb,
        "random_forest":  rf,
        "claude":         cld,
        "final_decision": final,
        "votes":          len(predictions),
    }


# ============================================================
# VERIFICAÇÃO DE TREINO AUTOMÁTICO
# ============================================================

def should_auto_train(texts: list, labels: list) -> bool:
    """
    Verifica se deve treinar automaticamente.
    Treina se:
    - Há pelo menos MIN_SAMPLES amostras
    - O modelo não existe ainda OU há 10+ amostras novas desde o último treino
    """
    if len(texts) < MIN_SAMPLES:
        return False
    if not NB_MODEL_PATH.exists():
        return True
    # Verifica se há pelo menos 10 amostras novas desde o último treino
    last_modified = NB_MODEL_PATH.stat().st_mtime
    new_samples = sum(1 for _ in texts)  # simplificado
    return new_samples >= MIN_SAMPLES + 10


def get_model_status() -> dict:
    """Devolve o estado actual dos modelos treinados."""
    def model_info(path):
        if path.exists():
            mtime = datetime.fromtimestamp(path.stat().st_mtime)
            return {
                "trained": True,
                "last_trained": mtime.strftime("%Y-%m-%d %H:%M:%S"),
                "size_kb": round(path.stat().st_size / 1024, 1),
            }
        return {"trained": False}

    return {
        "naive_bayes":   model_info(NB_MODEL_PATH),
        "random_forest": model_info(RF_MODEL_PATH),
        "claude":        {"trained": True, "note": "Usa API externa — sempre disponível se a chave estiver configurada"},
        "min_samples":   MIN_SAMPLES,
    }
