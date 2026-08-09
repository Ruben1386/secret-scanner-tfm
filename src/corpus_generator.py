#!/usr/bin/env python3
"""
Generador de corpus etiquetado para el TFM (Plan B: corpus propio).

Produce ficheros de código realistas con secretos REALES y falsos positivos
DIFÍCILES, evitando deliberadamente que ninguna característica aislada separe
las clases de forma perfecta (para que el experimento sea honesto y no trivial).

Fuentes de dificultad introducidas a propósito:
  1. Secretos reales detectados SOLO por entropía (valores genéricos de alta
     entropía en variables con nombre de credencial, sin prefijo de proveedor).
  2. Falsos positivos con FORMATO válido de proveedor (claves de ejemplo/test
     que casan con las regex) situados en ficheros de test/documentación.
  3. Contexto CORRELACIONADO pero RUIDOSO con la etiqueta: ~15% de claves reales
     aparecen en ficheros de test (hardcodeo real) y ~15% de ejemplos aparecen
     copiados en código de producción. El rol del fichero es señal fuerte pero
     no determinista.
  4. Falsos positivos de alta entropía que NO son secretos (UUID, SHA, integrity
     hashes) distinguibles por la forma del valor (hex puro, forma de UUID).

Etiqueta canónica en ground_truth.json: label = "secret" | "false_positive".

Uso:
    python corpus_generator.py --out ../data/corpus --seed 42
"""
import argparse
import json
import random
import string
from pathlib import Path


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
def rand_str(n, alphabet=string.ascii_letters + string.digits):
    return "".join(random.choice(alphabet) for _ in range(n))


def rand_b64(n):
    return "".join(random.choice(string.ascii_letters + string.digits + "+/") for _ in range(n))


def rand_hex(n):
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def rand_uuid():
    return f"{rand_hex(8)}-{rand_hex(4)}-4{rand_hex(3)}-{random.choice('89ab')}{rand_hex(3)}-{rand_hex(12)}"


# --------------------------------------------------------------------------
# Valores con FORMATO de proveedor (casan con regex del Tier 1).
# Se usan tanto para secretos reales como para FP con formato válido.
# --------------------------------------------------------------------------
def val_aws_key():
    return random.choice(["AKIA", "ASIA"]) + rand_str(16, string.ascii_uppercase + string.digits)


def val_github_pat():
    return "ghp_" + rand_str(36)


def val_google_api():
    return "AIza" + rand_str(35, string.ascii_letters + string.digits + "_-")


def val_slack():
    return "xoxb-" + rand_str(12, string.digits) + "-" + rand_str(12, string.digits) + "-" + rand_str(24)


def val_stripe_live():
    return "sk_live_" + rand_str(24)


def val_openai():
    return "sk-" + rand_str(48)


def val_anthropic():
    return "sk-ant-api03-" + rand_str(40, string.ascii_letters + string.digits + "_-")


def val_jwt():
    return f"eyJ{rand_b64(30).rstrip('=')}.eyJ{rand_b64(60).rstrip('=')}.{rand_b64(43).rstrip('=')}"


FORMAT_VALUE_GENS = [
    ("AWS Access Key ID", val_aws_key, "AWS_ACCESS_KEY_ID"),
    ("GitHub Personal Access Token", val_github_pat, "GITHUB_TOKEN"),
    ("Google API Key", val_google_api, "GOOGLE_API_KEY"),
    ("Slack Token", val_slack, "SLACK_BOT_TOKEN"),
    ("Stripe Live Secret Key", val_stripe_live, "STRIPE_KEY"),
    ("OpenAI API Key", val_openai, "OPENAI_API_KEY"),
    ("Anthropic API Key", val_anthropic, "ANTHROPIC_API_KEY"),
    ("JWT Token", val_jwt, "AUTH_TOKEN"),
]

# Variables con nombre de credencial para secretos genéricos (solo entropía)
SECRET_VAR_NAMES = ["api_key", "secret_key", "client_secret", "access_token",
                    "auth_token", "password", "session_secret", "app_secret"]

# Valores de alta entropía que NO son secretos (falsos positivos de entropía)
def val_uuid():
    return rand_uuid()


def val_sha1():
    return rand_hex(40)


def val_sha256():
    return rand_hex(64)


def val_npm_integrity():
    return "sha512-" + rand_b64(88)


def val_content_hash():
    return rand_hex(random.randint(24, 32))


ENTROPY_FP_GENS = [
    ("uuid", val_uuid, ["REQUEST_ID", "correlation_id", "trace_id"]),
    ("commit_sha", val_sha1, ["build_commit", "git_sha", "revision"]),
    ("file_checksum", val_sha256, ["file_checksum", "content_digest", "sri_hash"]),
    ("npm_integrity", val_npm_integrity, ["integrity"]),
    ("asset_hash", val_content_hash, ["asset_hash", "cache_key", "etag"]),
]

# Comentarios que sugieren ejemplo/documentación (señal de contexto)
SAMPLE_COMMENTS = [
    "# ejemplo de la documentación",
    "# sample value, do not use in prod",
    "# fixture for unit tests",
    "# mock credentials",
]

CLEAN_LINES = [
    "def process_request(payload):", "    return json.dumps(payload)",
    "import os, sys, logging", "logger = logging.getLogger(__name__)",
    "for item in items:", "    total += item.price",
    "# TODO: refactor this module", "class UserService:",
    "    def __init__(self, db):", "        self.db = db",
    "MAX_RETRIES = 3", "TIMEOUT_SECONDS = 30",
    "response = requests.get(url, timeout=10)", "if not user.is_authenticated:",
    "df = pd.read_csv('data.csv')", "results = model.predict(X_test)",
]


def make_assignment(var, value, quote=True):
    return f'{var} = "{value}"' if quote else f"{var} = {value}"


def build_units(n_secrets, n_fps, noise=0.05):
    """Crea la lista de instancias con etiqueta y contexto correlacionado-ruidoso."""
    units = []

    # ---- SECRETOS REALES ----
    n_format_secrets = int(n_secrets * 0.6)     # con formato de proveedor
    n_generic_secrets = n_secrets - n_format_secrets  # solo entropía, var de credencial

    for _ in range(n_format_secrets):
        rule, gen, var = random.choice(FORMAT_VALUE_GENS)
        value = gen()
        # Real -> mayoritariamente en prod, pero con ruido acaba en test
        role = "test" if random.random() < noise else "prod"
        comment = random.choice(SAMPLE_COMMENTS) if random.random() < 0.05 else None
        units.append(dict(kind="secret", rule=rule, value=value,
                          line=make_assignment(var, value), role=role, comment=comment))

    for _ in range(n_generic_secrets):
        var = random.choice(SECRET_VAR_NAMES)
        value = rand_str(random.randint(28, 44))   # aleatorio, alta entropía, sin prefijo
        role = "test" if random.random() < noise else "prod"
        units.append(dict(kind="secret", rule="Generic Secret", value=value,
                          line=make_assignment(var, value), role=role, comment=None))

    # ---- FALSOS POSITIVOS ----
    n_format_fp = int(n_fps * 0.5)     # formato válido pero NO real (ejemplos/test)
    n_entropy_fp = n_fps - n_format_fp  # alta entropía, no secretos (uuid/sha/...)

    for _ in range(n_format_fp):
        rule, gen, var = random.choice(FORMAT_VALUE_GENS)
        value = gen()
        # FP de formato -> mayoritariamente en test/docs, con ruido en prod
        role = "prod" if random.random() < noise else "test"
        comment = random.choice(SAMPLE_COMMENTS) if random.random() < 0.75 else None
        units.append(dict(kind="false_positive", rule=rule, value=value,
                          line=make_assignment(var, value), role=role, comment=comment))

    for _ in range(n_entropy_fp):
        cat, gen, varnames = random.choice(ENTROPY_FP_GENS)
        value = gen()
        var = random.choice(varnames)
        role = "prod" if random.random() < 0.7 else "test"
        units.append(dict(kind="false_positive", rule=cat, value=value,
                          line=make_assignment(var, value), role=role, comment=None))

    random.shuffle(units)
    return units


def build_corpus(out_dir, n_secrets, n_fps, n_files, seed):
    random.seed(seed)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    units = build_units(n_secrets, n_fps)

    # Nombres de fichero según rol (prod vs test/docs) — señal de contexto
    def fname(role, i):
        return f"test_{i:03d}.txt" if role == "test" else f"file_{i:03d}.txt"

    ground_truth = []
    files_content = {}
    for idx, unit in enumerate(units):
        fi = idx % n_files
        fn = fname(unit["role"], fi)
        buf = files_content.setdefault(fn, [f"# module {fn}", ""])
        for _ in range(random.randint(0, 3)):
            buf.append(random.choice(CLEAN_LINES))
        if unit["comment"]:
            buf.append(unit["comment"])
        start_line = len(buf) + 1
        buf.append(unit["line"])
        ground_truth.append(dict(file=fn, line=start_line, kind=unit["kind"],
                                 rule=unit["rule"], value=unit["value"], role=unit["role"]))

    for fn, lines in files_content.items():
        (out / fn).write_text("\n".join(lines + ["", random.choice(CLEAN_LINES)]) + "\n",
                              encoding="utf-8")

    (out / "ground_truth.json").write_text(
        json.dumps(ground_truth, ensure_ascii=False, indent=2), encoding="utf-8")

    n_sec = sum(1 for g in ground_truth if g["kind"] == "secret")
    n_fp = sum(1 for g in ground_truth if g["kind"] == "false_positive")
    n_sec_test = sum(1 for g in ground_truth if g["kind"] == "secret" and g["role"] == "test")
    n_fp_prod = sum(1 for g in ground_truth if g["kind"] == "false_positive" and g["role"] == "prod")
    print(f"[OK] Corpus generado en {out}")
    print(f"     Ficheros:            {len(files_content)}")
    print(f"     Secretos reales:     {n_sec}  (de ellos {n_sec_test} en ficheros de test = ruido)")
    print(f"     Falsos positivos:    {n_fp}  (de ellos {n_fp_prod} en prod = ruido)")
    print(f"     Total instancias:    {len(ground_truth)}")


def main():
    ap = argparse.ArgumentParser(description="Generador de corpus etiquetado de secretos (TFM Plan B)")
    ap.add_argument("--out", default="../data/corpus")
    ap.add_argument("--secrets", type=int, default=400)
    ap.add_argument("--fps", type=int, default=500)
    ap.add_argument("--files", type=int, default=50)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    build_corpus(args.out, args.secrets, args.fps, args.files, args.seed)


if __name__ == "__main__":
    main()
