#!/usr/bin/env python3
"""
Tier 2 — Clasificador de reducción de falsos positivos.

Sobre los candidatos que produce el Tier 1 (regex + entropía), entrena un
clasificador supervisado que decide, a partir de las características del
contexto, si cada hallazgo es un secreto REAL (mantener) o un FALSO POSITIVO
(descartar). El objetivo es subir la Precision sin sacrificar Recall.

Punto clave de metodología: el Tier 2 SOLO opera sobre candidatos del Tier 1,
por lo que nunca puede recuperar un secreto que el Tier 1 no detectó (no crea
Recall). Su función es filtrar falsos positivos.

Uso:
    python tier2_classifier.py --candidates ../results/tier1_candidates.jsonl \
                               --out ../results
"""
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (precision_score, recall_score, f1_score,
                             confusion_matrix, classification_report)
import joblib


NUMERIC_FEATURES = [
    "length", "entropy", "charset_diversity", "ratio_upper", "ratio_lower",
    "ratio_digit", "ratio_special", "n_segments", "is_hex", "is_uuid_shape",
    "has_known_prefix", "detected_by_pattern", "ctx_has_fp_word",
    "ctx_has_secret_word", "ctx_has_placeholder",
    "ctx_in_test_file", "ctx_sample_comment",
]


def load_candidates(path):
    rows = [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]
    return pd.DataFrame(rows)


def build_matrix(df):
    X = df[NUMERIC_FEATURES].astype(float).copy()
    # one-hot de la regla que disparó el hallazgo (info disponible en inferencia)
    rule_dummies = pd.get_dummies(df["rule"], prefix="rule")
    X = pd.concat([X, rule_dummies], axis=1)
    y = df["label"].astype(int).values
    return X, y


def main():
    ap = argparse.ArgumentParser(description="Tier 2: clasificador de reducción de FP")
    ap.add_argument("--candidates", default="../results/tier1_candidates.jsonl")
    ap.add_argument("--out", default="../results")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    df = load_candidates(args.candidates)
    X, y = build_matrix(df)
    feat_names = list(X.columns)

    n_pos = int(y.sum())
    n_neg = int((y == 0).sum())
    print(f"Dataset Tier 2: {len(y)} candidatos  |  secretos={n_pos}  falsos_positivos={n_neg}")

    # ---- Validación cruzada (dataset pequeño -> 5-fold estratificado) ----
    clf_cv = RandomForestClassifier(n_estimators=300, max_depth=None,
                                    class_weight="balanced", random_state=args.seed, n_jobs=-1)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=args.seed)
    cv_f1 = cross_val_score(clf_cv, X, y, cv=skf, scoring="f1")
    cv_prec = cross_val_score(clf_cv, X, y, cv=skf, scoring="precision")
    cv_rec = cross_val_score(clf_cv, X, y, cv=skf, scoring="recall")
    print(f"\n5-fold CV  ->  P={cv_prec.mean():.4f}±{cv_prec.std():.4f}  "
          f"R={cv_rec.mean():.4f}±{cv_rec.std():.4f}  F1={cv_f1.mean():.4f}±{cv_f1.std():.4f}")

    # ---- Held-out test (70/30 estratificado) ----
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=args.seed)
    clf = RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                 random_state=args.seed, n_jobs=-1)
    clf.fit(X_tr, y_tr)
    y_pred = clf.predict(X_te)

    prec = precision_score(y_te, y_pred)
    rec = recall_score(y_te, y_pred)
    f1 = f1_score(y_te, y_pred)
    cm = confusion_matrix(y_te, y_pred)

    print("\n=== TIER 2 — Held-out test (30%) ===")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall:    {rec:.4f}")
    print(f"  F1-score:  {f1:.4f}")
    print(f"  Matriz de confusión [ [TN FP] [FN TP] ]:\n{cm}")
    print("\n" + classification_report(y_te, y_pred, target_names=["falso_positivo", "secreto"]))

    # ---- Importancia de características ----
    importances = sorted(zip(feat_names, clf.feature_importances_),
                         key=lambda x: x[1], reverse=True)
    print("Top-10 características más informativas:")
    for name, imp in importances[:10]:
        print(f"  {imp:.4f}  {name}")

    # ---- Efecto sobre el pipeline (Tier 1 -> Tier 2) en el conjunto de test ----
    # Tier 1 sobre el test = marcar TODOS como secreto (no filtra).
    tier1_prec = precision_score(y_te, np.ones_like(y_te))
    tier1_rec = recall_score(y_te, np.ones_like(y_te))
    tier1_f1 = f1_score(y_te, np.ones_like(y_te))

    comparison = {
        "dataset": {"total": len(y), "secrets": n_pos, "false_positives": n_neg},
        "cv_5fold": {
            "precision": [round(cv_prec.mean(), 4), round(cv_prec.std(), 4)],
            "recall": [round(cv_rec.mean(), 4), round(cv_rec.std(), 4)],
            "f1": [round(cv_f1.mean(), 4), round(cv_f1.std(), 4)],
        },
        "tier1_on_testset": {"precision": round(tier1_prec, 4),
                             "recall": round(tier1_rec, 4), "f1": round(tier1_f1, 4)},
        "tier2_on_testset": {"precision": round(prec, 4),
                             "recall": round(rec, 4), "f1": round(f1, 4)},
        "confusion_matrix_testset": cm.tolist(),
        "feature_importances": [[n, round(float(i), 5)] for n, i in importances],
    }
    (out / "tier2_metrics.json").write_text(json.dumps(comparison, indent=2), encoding="utf-8")

    # Reentrena con todo el dataset para el modelo final entregable
    clf_full = RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                      random_state=args.seed, n_jobs=-1)
    clf_full.fit(X, y)
    joblib.dump({"model": clf_full, "features": feat_names}, out / "tier2_model.joblib")

    print(f"\n  -> {out/'tier2_metrics.json'}")
    print(f"  -> {out/'tier2_model.joblib'}")
    print("\n=== COMPARATIVA (test set) ===")
    print(f"  Tier 1  ->  P={tier1_prec:.4f}  R={tier1_rec:.4f}  F1={tier1_f1:.4f}")
    print(f"  Tier 2  ->  P={prec:.4f}  R={rec:.4f}  F1={f1:.4f}")


if __name__ == "__main__":
    main()
