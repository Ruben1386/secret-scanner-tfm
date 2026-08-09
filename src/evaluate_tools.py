#!/usr/bin/env python3
"""
Evaluación comparativa de GitLeaks y TruffleHog sobre el corpus del TFM.

Calcula Precision, Recall y F1-score de cada herramienta usando el mismo
ground_truth.json que se usa para evaluar el Tier 1 y el Tier 2.

Un hallazgo de la herramienta se considera TRUE POSITIVE si su (fichero, línea)
coincide con una instancia marcada como "secret" en el ground truth.

Uso:
    python evaluate_tools.py \
        --gt      ../data/corpus/ground_truth.json \
        --gl      /tmp/gitleaks_out.json \
        --th      /tmp/trufflehog_out.jsonl \
        --tier1   ../results/tier1_metrics.json \
        --tier2   ../results/tier2_metrics.json \
        --out     ../results
"""
import argparse
import json
from pathlib import Path


def load_gt(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def build_gt_index(gt):
    secrets = set()
    fps = set()
    for g in gt:
        fn = Path(g["file"]).name
        key = (fn, g["line"])
        if g["kind"] == "secret":
            secrets.add(key)
        else:
            fps.add(key)
    return secrets, fps


def compute_metrics(flagged_set, secrets, fps):
    tp = len(flagged_set & secrets)
    fp = len(flagged_set & fps)
    fn = len(secrets - flagged_set)
    tn = len(fps - flagged_set)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4)}


def parse_gitleaks(path):
    """Devuelve set de (filename, lineno) detectados por GitLeaks."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    flagged = set()
    for item in data:
        fn = Path(item.get("File", "")).name
        line = item.get("StartLine", item.get("Line", 0))
        if fn and line:
            flagged.add((fn, int(line)))
    return flagged


def parse_trufflehog(path):
    """Devuelve set de (filename, lineno) detectados por TruffleHog (JSONL)."""
    flagged = set()
    for ln in Path(path).read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        item = json.loads(ln)
        src = item.get("SourceMetadata", {})
        data = src.get("Data", {})
        # TruffleHog FS: SourceMetadata.Data.Filesystem
        fs = data.get("Filesystem", data.get("filesystem", {}))
        fn = Path(fs.get("file", fs.get("File", ""))).name
        line = fs.get("line", fs.get("Line", 0))
        if fn and line:
            flagged.add((fn, int(line)))
    return flagged


def load_tier_metrics(path, key_precision, key_recall, key_f1):
    if not Path(path).exists():
        return None
    d = json.loads(Path(path).read_text())
    return {"precision": d[key_precision], "recall": d[key_recall], "f1": d[key_f1]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt", default="../data/corpus/ground_truth.json")
    ap.add_argument("--gl", default="/tmp/gitleaks_out.json")
    ap.add_argument("--th", default="/tmp/trufflehog_out.jsonl")
    ap.add_argument("--tier1", default="../results/tier1_metrics.json")
    ap.add_argument("--tier2", default="../results/tier2_metrics.json")
    ap.add_argument("--out", default="../results")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    gt = load_gt(args.gt)
    secrets, fps = build_gt_index(gt)
    n_secrets = len(secrets)
    n_fps = len(fps)
    print(f"Ground truth: {n_secrets} secretos reales, {n_fps} falsos positivos\n")

    # Cargar y evaluar herramientas externas
    gl_flagged = parse_gitleaks(args.gl) if Path(args.gl).exists() else set()
    th_flagged = parse_trufflehog(args.th) if Path(args.th).exists() else set()

    gl_m = compute_metrics(gl_flagged, secrets, fps)
    th_m = compute_metrics(th_flagged, secrets, fps)

    # Cargar métricas de nuestros tiers del mismo held-out test
    t1_raw = json.loads(Path(args.tier1).read_text()) if Path(args.tier1).exists() else {}
    t2_raw = json.loads(Path(args.tier2).read_text()) if Path(args.tier2).exists() else {}
    t1_m = {"precision": t1_raw.get("precision", 0),
             "recall": t1_raw.get("recall", 0), "f1": t1_raw.get("f1", 0)}
    t2_m = t2_raw.get("tier2_on_testset", {"precision": 0, "recall": 0, "f1": 0})

    # ---- Tabla comparativa ----
    tools = [
        ("GitLeaks v8.30", gl_m, gl_flagged),
        ("TruffleHog v3.96", th_m, th_flagged),
        ("Nuestro Tier 1 (regex+Shannon)", t1_m, None),
        ("Nuestro Tier 2 (Tier1+RF)", t2_m, None),
    ]

    print("=" * 65)
    print(f"{'Herramienta':<30} {'Precision':>9} {'Recall':>7} {'F1':>7}")
    print("-" * 65)
    for name, m, _ in tools:
        print(f"{name:<30} {m['precision']:>9.4f} {m['recall']:>7.4f} {m['f1']:>7.4f}")
    print("=" * 65)

    # Análisis adicional GitLeaks
    gl_tp = gl_flagged & secrets
    gl_fp_set = gl_flagged & fps
    gl_fn = secrets - gl_flagged
    gl_unknown = gl_flagged - secrets - fps  # lineas detectadas fuera del GT
    print(f"\nGitLeaks detalle:  {len(gl_flagged)} hallazgos total")
    print(f"  TP={gl_m['tp']}  FP={gl_m['fp']}  FN={gl_m['fn']}  fuera-de-GT={len(gl_unknown)}")
    print(f"TruffleHog detalle: {len(th_flagged)} hallazgos total")
    print(f"  TP={th_m['tp']}  FP={th_m['fp']}  FN={th_m['fn']}")

    comparison = {
        "corpus": {"secrets": n_secrets, "false_positives": n_fps},
        "gitleaks": {**gl_m, "total_findings": len(gl_flagged)},
        "trufflehog": {**th_m, "total_findings": len(th_flagged)},
        "tier1_full_corpus": t1_m,
        "tier2_testset": t2_m,
    }
    (out / "comparison_table.json").write_text(json.dumps(comparison, indent=2), encoding="utf-8")
    print(f"\n  -> {out/'comparison_table.json'}")


if __name__ == "__main__":
    main()
