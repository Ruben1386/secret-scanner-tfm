#!/usr/bin/env python3
"""
Genera las figuras del TFM (PNG 300 dpi) listas para incluir en el documento.

Figuras producidas:
  fig1_comparison_bar.png   — Barras P/R/F1 de las 4 herramientas
  fig2_confusion_matrix.png — Matrices de confusión Tier 1 vs Tier 2
  fig3_feature_importance.png — Top-10 importancias del Tier 2

Uso:
    python generate_figures.py --results ../results --out ../results/figures
"""
import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np


PALETTE = {
    "GitLeaks":  "#e15759",
    "TruffleHog": "#f28e2b",
    "Tier 1":    "#4e79a7",
    "Tier 2":    "#59a14f",
}


def fig_comparison_bar(data, out):
    tools = ["GitLeaks\nv8.30", "TruffleHog\nv3.96", "Tier 1\n(regex+Shannon)", "Tier 2\n(Tier1+RF)"]
    p_vals = [data["gitleaks"]["precision"], data["trufflehog"]["precision"],
              data["tier1_full_corpus"]["precision"], data["tier2_testset"]["precision"]]
    r_vals = [data["gitleaks"]["recall"], data["trufflehog"]["recall"],
              data["tier1_full_corpus"]["recall"], data["tier2_testset"]["recall"]]
    f_vals = [data["gitleaks"]["f1"], data["trufflehog"]["f1"],
              data["tier1_full_corpus"]["f1"], data["tier2_testset"]["f1"]]

    x = np.arange(len(tools))
    width = 0.25
    fig, ax = plt.subplots(figsize=(10, 5.5))
    ax.bar(x - width, p_vals, width, label="Precision", color="#4e79a7", zorder=3)
    ax.bar(x,         r_vals, width, label="Recall",    color="#f28e2b", zorder=3)
    ax.bar(x + width, f_vals, width, label="F1-score",  color="#59a14f", zorder=3)

    # etiquetas sobre barras
    for bars in [ax.containers[0], ax.containers[1], ax.containers[2]]:
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.01, f"{h:.2f}",
                    ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(tools, fontsize=10)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Valor métrico")
    ax.set_title("Comparativa Precision / Recall / F1-score\n(corpus propio, n=900 instancias etiquetadas)", fontsize=11)
    ax.legend(loc="upper left", fontsize=9)
    ax.yaxis.grid(True, alpha=0.4, zorder=0)
    ax.set_axisbelow(True)
    # Resaltar columna Tier 2
    ax.axvspan(3 - 0.45, 3 + 0.45, alpha=0.06, color="#59a14f", zorder=1)

    fig.tight_layout()
    path = out / "fig1_comparison_bar.png"
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {path}")


def fig_confusion_matrices(tier1_raw, tier2_raw, out):
    # Tier 1: usamos métricas del corpus completo (tp/fp/fn/tn directos)
    t1 = tier1_raw
    cm1 = np.array([[t1["tn"], t1["fp"]], [t1["fn"], t1["tp"]]])

    # Tier 2: usamos la matriz del held-out test
    cm2_list = tier2_raw.get("confusion_matrix_testset", [[0, 0], [0, 0]])
    cm2 = np.array(cm2_list)

    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for ax, cm, title in zip(axes,
                              [cm1, cm2],
                              ["Tier 1 — Baseline (corpus completo)", "Tier 2 — RandomForest (test 30%)"]):
        im = ax.imshow(cm, cmap="Blues", vmin=0)
        ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
        ax.set_xticklabels(["Pred FP", "Pred Secreto"], fontsize=9)
        ax.set_yticklabels(["Real FP", "Real Secreto"], fontsize=9)
        ax.set_title(title, fontsize=10, pad=8)
        total = cm.sum()
        for i in range(2):
            for j in range(2):
                val = cm[i, j]
                color = "white" if val > total * 0.35 else "black"
                ax.text(j, i, f"{val}", ha="center", va="center",
                        fontsize=14, color=color, fontweight="bold")
        plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

    fig.suptitle("Matrices de confusión: Tier 1 vs Tier 2", fontsize=12)
    fig.tight_layout()
    path = out / "fig2_confusion_matrix.png"
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {path}")


def fig_feature_importance(tier2_raw, out):
    importances = tier2_raw.get("feature_importances", [])
    if not importances:
        print("  [skip] sin importancias en tier2_metrics.json")
        return

    names = [r[0] for r in importances[:12]]
    vals = [r[1] for r in importances[:12]]
    # Invertir para que el más importante quede arriba
    names = names[::-1]
    vals = vals[::-1]

    LABEL_MAP = {
        "ctx_in_test_file": "Fichero de test",
        "ctx_sample_comment": "Comentario 'sample/ejemplo'",
        "entropy": "Entropía de Shannon",
        "ratio_lower": "Ratio minúsculas",
        "ratio_upper": "Ratio mayúsculas",
        "ratio_digit": "Ratio dígitos",
        "charset_diversity": "Diversidad charset",
        "ratio_special": "Ratio especiales",
        "n_segments": "N.º segmentos (-, _, .)",
        "length": "Longitud del token",
        "ctx_has_secret_word": "Var. con palabra clave",
        "ctx_has_fp_word": "Palabra clave FP en contexto",
        "rule_Generic Secret Assignment": "Regla Generic Secret",
    }
    labels = [LABEL_MAP.get(n, n) for n in names]

    colors = ["#59a14f" if v > 0.10 else "#4e79a7" if v > 0.05 else "#aecbf5" for v in vals]
    fig, ax = plt.subplots(figsize=(9, 5.5))
    bars = ax.barh(labels, vals, color=colors, edgecolor="white")
    for bar, v in zip(bars, vals):
        ax.text(v + 0.002, bar.get_y() + bar.get_height() / 2,
                f"{v:.3f}", va="center", fontsize=8)
    ax.set_xlabel("Importancia media (Gini)", fontsize=9)
    ax.set_title("Top-12 características más informativas — RandomForest Tier 2", fontsize=10)
    ax.set_xlim(0, max(vals) * 1.20)
    ax.xaxis.grid(True, alpha=0.3)
    ax.set_axisbelow(True)
    fig.tight_layout()
    path = out / "fig3_feature_importance.png"
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="../results")
    ap.add_argument("--out", default="../results/figures")
    args = ap.parse_args()

    res = Path(args.results)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    comp = json.loads((res / "comparison_table.json").read_text())
    t1 = json.loads((res / "tier1_metrics.json").read_text())
    t2 = json.loads((res / "tier2_metrics.json").read_text())

    print("Generando figuras:")
    fig_comparison_bar(comp, out)
    fig_confusion_matrices(t1, t2, out)
    fig_feature_importance(t2, out)
    print("Listo.")


if __name__ == "__main__":
    main()
