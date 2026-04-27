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
from collections import Counter

logger = logging.getLogger(__name__)

MODEL_DIR = Path("models")
MODEL_DIR.mkdir(exist_ok=True)

NB_MODEL_PATH = MODEL_DIR / "naive_bayes.pkl"
RF_MODEL_PATH = MODEL_DIR / "random_forest.pkl"
MIN_SAMPLES   = 5


# ============================================================
# TREINO DOS MODELOS
# ============================================================

def train_models(texts: list[str], labels: list[str]) -> dict:
    try:
        from sklearn.naive_bayes import MultinomialNB
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.pipeline import Pipeline
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score
    except ImportError:
        return {"success": False, "error": "scikit-learn não instalado."}

    if len(texts) < MIN_SAMPLES:
        return {
            "success": False,
            "error": f"Dados insuficientes. Mínimo: {MIN_SAMPLES}. Actual: {len(texts)}"
        }

    # -------------------------------------------------------
    # Verificar se é possível usar stratify
    # stratify só funciona se TODAS as classes tiverem >= 2 exemplos
    # E se o número de amostras permitir pelo menos 1 em teste por classe
    # -------------------------------------------------------
    label_counts = Counter(labels)
    min_count = min(label_counts.values())
    n_classes = len(label_counts)

    # Usar stratify só se houver amostras suficientes por classe
    # Regra: cada classe precisa de ter pelo menos 2 amostras
    # E o número total deve ser >= 2 * n_classes
    use_stratify = (
        min_count >= 2 and
        len(texts) >= 2 * n_classes and
        n_classes > 1
    )

    try:
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels,
            test_size=0.2,
            random_state=42,
            stratify=labels if use_stratify else None
        )
    except ValueError:
        # Fallback sem stratify se ainda falhar
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels,
            test_size=0.2,
            random_state=42,
            stratify=None
        )

    results = {
        "success": True,
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "models": {}
    }

    # --- Naive Bayes ---
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

    # --- Random Forest ---
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
# PREDIÇÃO
# ============================================================

def predict_naive_bayes(text: str) -> dict:
    if not NB_MODEL_PATH.exists():
        return {"available": False, "reason": "Modelo não treinado ainda"}
    try:
        with open(NB_MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        prediction = model.predict([text])[0]
        proba = model.predict_proba([text])[0]
        confidence = round(max(proba) * 100, 1)
        return {"available": True, "model": "Naive Bayes", "prediction": prediction, "confidence": confidence}
    except Exception as e:
        return {"available": False, "reason": str(e)}


def predict_random_forest(text: str) -> dict:
    if not RF_MODEL_PATH.exists():
        return {"available": False, "reason": "Modelo não treinado ainda"}
    try:
        with open(RF_MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        prediction = model.predict([text])[0]
        proba = model.predict_proba([text])[0]
        confidence = round(max(proba) * 100, 1)
        return {"available": True, "model": "Random Forest", "prediction": prediction, "confidence": confidence}
    except Exception as e:
        return {"available": False, "reason": str(e)}


def predict_claude(text: str) -> dict:
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        return {"available": False, "reason": "ANTHROPIC_API_KEY não configurada"}

    prompt = f"""Analisa esta mensagem e classifica-a numa das seguintes categorias:
- Golpe Financeiro / Phishing
- Apostas / Aliciamento Digital
- Fake News / Desinformação
- Manipulação Social
- Curanderismo / Golpe Tradicional
- Baixo ou Nenhum Risco

Mensagem: "{text}"

Responde APENAS com um JSON (sem texto adicional):
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
        raw = data["content"][0]["text"].strip().replace("```json", "").replace("```", "").strip()
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


def predict_all(text: str) -> dict:
    nb  = predict_naive_bayes(text)
    rf  = predict_random_forest(text)
    cld = predict_claude(text)

    predictions = [r["prediction"] for r in [nb, rf, cld] if r.get("available") and r.get("prediction")]
    final = Counter(predictions).most_common(1)[0][0] if predictions else None

    return {
        "naive_bayes":    nb,
        "random_forest":  rf,
        "claude":         cld,
        "final_decision": final,
        "votes":          len(predictions),
    }


# ============================================================
# TREINO AUTOMÁTICO
# ============================================================

def should_auto_train(texts: list, labels: list) -> bool:
    if len(texts) < MIN_SAMPLES:
        return False
    if not NB_MODEL_PATH.exists():
        return True
    return len(texts) >= MIN_SAMPLES + 10


def get_model_status() -> dict:
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
        "claude":        {"trained": True, "note": "Usa API externa — disponível se a chave estiver configurada"},
        "min_samples":   MIN_SAMPLES,
    }