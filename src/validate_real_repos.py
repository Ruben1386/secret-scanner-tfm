#!/usr/bin/env python3
"""
Validación real (Sección 5.3 "Validación sobre repositorios reales" del TFM): prueba del pipeline sobre repos públicos reales.

Metodología:
  - Modo filesystem: escaneamos el estado ACTUAL del working tree (sin historial git).
    Esto replica el uso pre-commit, que es el caso de uso declarado del trabajo.
  - Ground truth proxy: unión de hallazgos de GitLeaks y TruffleHog (filesystem).
    Cualquier credencial que al menos UNA herramienta del estado del arte detecta
    se considera candidato real. Las que AMBAS detectan = alta confianza.
  - Análisis cualitativo por caso.

Repos usados:
  1. trufflesecurity/test_keys — repo oficial TruffleHog con secretos reales intencionados
  2. Yelp/detect-secrets testdata — fixtures de test de la herramienta de referencia
  3. awslabs/git-secrets — herramienta contra filtrado de secretos (esperamos 0 FP)
"""
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from tier1_baseline import scan_text, looks_like_placeholder


TOOLS_DIR = Path(__file__).parent.parent / "tools"
REPOS_DIR = Path(__file__).parent.parent / "data" / "real_repos"
OUT_DIR = Path(__file__).parent.parent / "results"


@dataclass
class RepoConfig:
    name: str
    path: Path
    description: str
    expected_secrets: int   # aproximado según la documentación del repo


REPOS = [
    RepoConfig("test_keys",
               REPOS_DIR / "test_keys",
               "Repo oficial de TruffleHog con credenciales reales intencionadas",
               3),
    RepoConfig("detect-secrets testdata",
               REPOS_DIR / "detect_secrets_repo" / "test_data",
               "Fixtures de Yelp/detect-secrets — incluye claves de EJEMPLO (AWS docs canonical)",
               0),  # las AWS keys son AKIAIOSFODNN7EXAMPLE → placeholder
    RepoConfig("awslabs/git-secrets",
               REPOS_DIR / "awslabs_git_secrets",
               "Herramienta de seguridad — esperamos 0 secretos (high precision test)",
               0),
]


def run_gitleaks_no_git(repo_path: Path) -> set[tuple[str, int]]:
    report = Path("/tmp/gl_real.json")
    result = subprocess.run(
        [str(TOOLS_DIR / "gitleaks"), "detect", "--no-git",
         "--report-format", "json", "--report-path", str(report),
         "--source", str(repo_path), "--exit-code", "0"],
        capture_output=True, text=True
    )
    if not report.exists():
        return set()
    items = json.loads(report.read_text())
    return {(Path(i["File"]).name, i.get("StartLine", i.get("Line", 0))) for i in items}


def run_trufflehog_fs(repo_path: Path) -> set[tuple[str, int]]:
    result = subprocess.run(
        [str(TOOLS_DIR / "trufflehog"), "filesystem", str(repo_path),
         "--json", "--no-update"],
        capture_output=True, text=True
    )
    flagged = set()
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        fs = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        fn = Path(fs.get("file", "")).name
        line_no = fs.get("line", 0)
        if fn and line_no:
            flagged.add((fn, int(line_no)))
    return flagged


def run_tier1(repo_path: Path) -> list:
    findings = []
    for fp in sorted(repo_path.rglob("*")):
        if not fp.is_file() or ".git" in str(fp):
            continue
        text = fp.read_text(encoding="utf-8", errors="ignore")
        found = scan_text(text, fp.name)
        findings.extend(found)
    return findings


def evaluate_repo(cfg: RepoConfig) -> dict:
    if not cfg.path.exists():
        return {"repo": cfg.name, "error": "path not found"}

    print(f"\n{'='*60}")
    print(f"Repo: {cfg.name}")
    print(f"  {cfg.description}")

    gl = run_gitleaks_no_git(cfg.path)
    th = run_trufflehog_fs(cfg.path)
    t1_findings = run_tier1(cfg.path)
    t1 = {(f.file, f.line) for f in t1_findings}

    # Ground truth proxy
    gt_union = gl | th          # cualquiera lo detecta
    gt_intersect = gl & th      # ambas coinciden = alta confianza

    print(f"  GitLeaks:   {len(gl)} hallazgos")
    print(f"  TruffleHog: {len(th)} hallazgos")
    print(f"  Tier 1:     {len(t1)} hallazgos")
    print(f"  GT unión:   {len(gt_union)}  |  GT intersección (alta confianza): {len(gt_intersect)}")

    # Métricas de Tier 1 vs GT intersección (conservadora)
    if gt_intersect:
        tp = len(t1 & gt_intersect)
        fp = len(t1 - gt_union)          # detectamos algo que ninguna herramienta detecta
        fn = len(gt_intersect - t1)
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2*precision*recall/(precision+recall) if (precision+recall) else 0.0
    else:
        tp = fp = fn = 0
        # Si no hay GT (esperamos 0 secretos): precision = 1 si Tier 1 no dispara
        precision = 1.0 if not t1 else len(t1 - gt_union) / len(t1)
        recall = 1.0  # N/A
        f1 = precision

    print(f"\n  >> Tier 1 vs GT alta confianza: P={precision:.2f}  R={recall:.2f}  F1={f1:.2f}")
    print(f"     TP={tp}  FP={fp}  FN={fn}")

    # Análisis cualitativo de hallazgos del Tier 1
    if t1_findings:
        print(f"\n  Detalle hallazgos Tier 1:")
        for f in t1_findings[:10]:
            tag = "[COINCIDE GT]" if (f.file, f.line) in gt_union else "[SOLO TIER1]"
            print(f"    {tag} {f.rule} | {f.file}:{f.line} | {f.secret[:55]}")

    # Análisis de lo que NO capturamos pero sí el GT
    missed = gt_intersect - t1
    if missed:
        print(f"\n  FN (GT alta confianza NO detectados por Tier 1): {len(missed)}")
        for fn_key in missed:
            print(f"    MISS: {fn_key}")

    return {
        "repo": cfg.name,
        "gitleaks_findings": len(gl),
        "trufflehog_findings": len(th),
        "tier1_findings": len(t1),
        "gt_union": len(gt_union),
        "gt_intersect": len(gt_intersect),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for cfg in REPOS:
        res = evaluate_repo(cfg)
        results.append(res)

    (OUT_DIR / "real_world_validation.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )

    print(f"\n\n{'='*60}")
    print("RESUMEN VALIDACIÓN REAL")
    print(f"{'='*60}")
    print(f"{'Repo':<30} {'GL':>4} {'TH':>4} {'T1':>4} {'P':>6} {'R':>6} {'F1':>6}")
    print("-"*60)
    for r in results:
        if "error" not in r:
            print(f"{r['repo']:<30} {r['gitleaks_findings']:>4} {r['trufflehog_findings']:>4} "
                  f"{r['tier1_findings']:>4} {r['precision']:>6.2f} {r['recall']:>6.2f} {r['f1']:>6.2f}")

    print(f"\n  -> {OUT_DIR/'real_world_validation.json'}")


if __name__ == "__main__":
    main()
