#!/usr/bin/env python3
"""
Tier 1 — Detector baseline (regex + entropía de Shannon).

Porta el núcleo de detección del Módulo 6 Tarea 2 y lo convierte en una
librería evaluable. Además del hallazgo, extrae un vector de características
del contexto que servirá de entrada al clasificador del Tier 2 (reducción
de falsos positivos).

Funciones públicas:
    scan_corpus(corpus_dir) -> list[Candidate]   # detecta y extrae features
    evaluate(candidates, ground_truth) -> dict    # P/R/F1 a nivel instancia

Uso CLI:
    python tier1_baseline.py --corpus ../data/corpus --out ../results
"""
import argparse
import json
import math
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path


# --------------------------------------------------------------------------
# Patrones (portados del M6 Tarea 2) + entropía
# --------------------------------------------------------------------------
PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("AWS Secret Access Key", re.compile(r"(?i)aws(.{0,20})?(secret|access).{0,5}key.{0,5}['\"]([A-Za-z0-9/+=]{40})['\"]")),
    ("GitHub Personal Access Token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("GitHub OAuth Token", re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    ("GitHub App Token", re.compile(r"\b(ghu|ghs)_[A-Za-z0-9]{36}\b")),
    ("GitHub Fine-grained Token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("Stripe Test Secret Key", re.compile(r"\bsk_test_[0-9a-zA-Z]{24,}\b")),
    ("OpenAI API Key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("Anthropic API Key", re.compile(r"\bsk-ant-api03-[A-Za-z0-9_\-]{20,}\b")),
    ("JWT Token", re.compile(r"\beyJ[A-Za-z0-9_=\-]{8,}\.eyJ[A-Za-z0-9_=\-]{8,}\.[A-Za-z0-9_\-+/=]{8,}\b")),
    ("Private Key (RSA/OpenSSH/EC/DSA)", re.compile(r"-----BEGIN (RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY( BLOCK)?-----")),
    ("Generic Password Assignment", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]")),
    ("Generic API Key Assignment", re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]")),
    ("Generic Secret Assignment", re.compile(r"(?i)(secret|client_secret)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]")),
    ("Generic Token Assignment", re.compile(r"(?i)(token|auth_token|access_token|bearer)\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]")),
    ("Database Connection String", re.compile(r"(?i)(mongodb|postgres(ql)?|mysql|redis)://[^:]+:([^@\s]+)@")),
]

ENTROPY_TOKEN_RE = re.compile(r"['\"]([A-Za-z0-9+/=_\-]{20,})['\"]")
ENTROPY_THRESHOLD = 4.5

INLINE_IGNORE_MARKERS = (
    "# noqa: secrets", "# pragma: allowlist",
    "# secret-scanner: ignore", "# IGNORE",
)


def is_inline_ignored(line_text: str) -> bool:
    return any(m in line_text for m in INLINE_IGNORE_MARKERS)

# Marcadores que la baseline del M6T2 ya usa para suprimir (FP handling básico)
PLACEHOLDER_HINTS = (
    "your_", "yourkey", "example", "placeholder", "changeme", "todo",
    "xxxx", "***", "...", "<your", "fake", "dummy", "test_only", "replace_with",
)

# Palabras del contexto que sugieren que NO es un secreto (para features Tier 2)
FP_CONTEXT_WORDS = (
    "uuid", "hash", "checksum", "integrity", "commit", "sha", "digest",
    "example", "sample", "placeholder", "dummy", "test", "icon", "asset",
    "public", "authorized_key",
)


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {ch: s.count(ch) / len(s) for ch in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def looks_like_placeholder(value):
    lo = value.lower()
    return any(p in lo for p in PLACEHOLDER_HINTS)


@dataclass
class Candidate:
    file: str
    line: int
    rule: str
    secret: str
    detected_by: str            # "pattern" | "entropy"
    features: dict = field(default_factory=dict)


# --------------------------------------------------------------------------
# Extracción de características (entrada del Tier 2)
# --------------------------------------------------------------------------
SAMPLE_WORDS = ("ejemplo", "sample", "fixture", "mock", "documentaci", "do not use", "example")


def extract_features(secret, line_text, rule, detected_by, filename="", prev_line=""):
    s = secret
    n = max(len(s), 1)
    n_upper = sum(c.isupper() for c in s)
    n_lower = sum(c.islower() for c in s)
    n_digit = sum(c.isdigit() for c in s)
    n_special = sum(not c.isalnum() for c in s)
    unique = len(set(s))
    lo_ctx = line_text.lower()
    lo_prev = prev_line.lower()
    is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", s))
    return {
        "length": len(s),
        "entropy": round(shannon_entropy(s), 4),
        "charset_diversity": round(unique / n, 4),
        "ratio_upper": round(n_upper / n, 4),
        "ratio_lower": round(n_lower / n, 4),
        "ratio_digit": round(n_digit / n, 4),
        "ratio_special": round(n_special / n, 4),
        "n_segments": s.count("-") + s.count(".") + s.count("_"),
        "is_hex": int(is_hex),
        "is_uuid_shape": int(bool(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", s))),
        "has_known_prefix": int(bool(re.match(r"(AKIA|ASIA|ghp_|gho_|ghu_|ghs_|github_pat_|AIza|xox|sk_live_|sk_test_|sk-ant-|sk-)", s))),
        "detected_by_pattern": int(detected_by == "pattern"),
        "ctx_has_fp_word": int(any(w in lo_ctx for w in FP_CONTEXT_WORDS)),
        "ctx_has_secret_word": int(any(w in lo_ctx for w in ("secret", "password", "token", "api_key", "apikey", "credential", "auth"))),
        "ctx_has_placeholder": int(looks_like_placeholder(line_text)),
        "ctx_in_test_file": int("test" in filename.lower()),
        "ctx_sample_comment": int(any(w in lo_prev for w in SAMPLE_WORDS)),
    }


# --------------------------------------------------------------------------
# Escaneo
# --------------------------------------------------------------------------
def scan_text(text, filename):
    candidates = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        if is_inline_ignored(line):
            continue
        prev_line = lines[lineno - 2] if lineno >= 2 else ""
        seen_on_line = set()
        for rule_name, regex in PATTERNS:
            for m in regex.finditer(line):
                secret = m.group(0)
                if looks_like_placeholder(secret):
                    continue
                if (lineno, secret) in seen_on_line:
                    continue
                seen_on_line.add((lineno, secret))
                candidates.append(Candidate(
                    file=filename, line=lineno, rule=rule_name, secret=secret,
                    detected_by="pattern",
                    features=extract_features(secret, line, rule_name, "pattern", filename, prev_line),
                ))
        for m in ENTROPY_TOKEN_RE.finditer(line):
            value = m.group(1)
            if looks_like_placeholder(value):
                continue
            if any(value in s for (_, s) in seen_on_line):
                continue
            if shannon_entropy(value) >= ENTROPY_THRESHOLD:
                seen_on_line.add((lineno, value))
                candidates.append(Candidate(
                    file=filename, line=lineno, rule="High-Entropy String", secret=value,
                    detected_by="entropy",
                    features=extract_features(value, line, "High-Entropy String", "entropy", filename, prev_line),
                ))
    return candidates


def scan_corpus(corpus_dir):
    corpus = Path(corpus_dir)
    candidates = []
    for fp in sorted(corpus.glob("*.txt")):
        text = fp.read_text(encoding="utf-8", errors="ignore")
        candidates.extend(scan_text(text, fp.name))
    return candidates


# --------------------------------------------------------------------------
# Evaluación P/R/F1 a nivel de instancia contra ground_truth.json
# --------------------------------------------------------------------------
def load_ground_truth(corpus_dir):
    gt = json.loads((Path(corpus_dir) / "ground_truth.json").read_text(encoding="utf-8"))
    return gt


def evaluate(candidates, ground_truth):
    # ¿Qué (file,line) han sido señalados por el detector?
    flagged = {(c.file, c.line) for c in candidates}

    tp = fn = fp = tn = 0
    for gt in ground_truth:
        key = (gt["file"], gt["line"])
        is_flagged = key in flagged
        if gt["kind"] == "secret":
            if is_flagged:
                tp += 1
            else:
                fn += 1
        else:  # false_positive
            if is_flagged:
                fp += 1
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "total_findings": len(candidates),
    }


def label_candidates(candidates, ground_truth):
    """Etiqueta cada candidato del detector como 1=secreto real / 0=falso positivo.
    Es el dataset supervisado para el Tier 2."""
    gt_index = {(g["file"], g["line"]): g["kind"] for g in ground_truth}
    rows = []
    for c in candidates:
        kind = gt_index.get((c.file, c.line))
        if kind is None:
            # candidato sobre una línea sin ground truth -> ruido detectado = FP
            label = 0
        else:
            label = 1 if kind == "secret" else 0
        row = dict(c.features)
        row["rule"] = c.rule
        row["detected_by"] = c.detected_by
        row["file"] = c.file
        row["line"] = c.line
        row["label"] = label
        rows.append(row)
    return rows


def main():
    ap = argparse.ArgumentParser(description="Tier 1 baseline: regex + entropía de Shannon")
    ap.add_argument("--corpus", default="../data/corpus")
    ap.add_argument("--out", default="../results")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    candidates = scan_corpus(args.corpus)
    gt = load_ground_truth(args.corpus)
    metrics = evaluate(candidates, gt)

    # Guarda métricas del Tier 1
    (out / "tier1_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    # Guarda candidatos etiquetados (dataset para Tier 2)
    rows = label_candidates(candidates, gt)
    (out / "tier1_candidates.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8"
    )

    print("=== TIER 1 — Baseline (regex + Shannon) ===")
    print(f"  Hallazgos totales:  {metrics['total_findings']}")
    print(f"  TP={metrics['tp']}  FP={metrics['fp']}  FN={metrics['fn']}  TN={metrics['tn']}")
    print(f"  Precision: {metrics['precision']}")
    print(f"  Recall:    {metrics['recall']}")
    print(f"  F1-score:  {metrics['f1']}")
    print(f"\n  -> {out/'tier1_metrics.json'}")
    print(f"  -> {out/'tier1_candidates.jsonl'} ({len(rows)} candidatos etiquetados)")


if __name__ == "__main__":
    main()
