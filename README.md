# Secret Scanner TFM — Detección Híbrida de Secretos en Código y Pipelines

**Trabajo de Fin de Máster · Máster en IA Aplicada a la Ciberseguridad**  
Rubén Jiménez Ormad · Tutor: Fran Ramírez · Agosto 2026

---

## Descripción

Sistema híbrido de detección de credenciales accidentalmente expuestas en código fuente y pipelines CI/CD. Combina dos niveles complementarios:

- **Nivel 1 (N1):** 19 expresiones regulares para formatos de proveedores conocidos (AWS, GitHub, Stripe, OpenAI…) + análisis de entropía de Shannon ≥ 4,5 bits
- **Nivel 2 (N2):** clasificador Random Forest sobre 17 características contextuales, con el objetivo específico de reducir falsos positivos sin sacrificar cobertura

| Sistema | Precision | Recall | F1-score |
|---|:---:|:---:|:---:|
| TruffleHog v3.96 | 0,48 | 0,20 | 0,28 |
| GitLeaks v8.30 | 0,65 | 0,76 | 0,70 |
| **N1** (regex + entropía) | 0,57 | **0,99** | 0,72 |
| **N2** (N1 + Random Forest) | **0,98** | 0,93 | **0,95** |

Validación en repositorios reales: **Precision = 1,00 · Recall = 1,00** sobre secretos de alta confianza en [`trufflesecurity/test_keys`](https://github.com/trufflesecurity/test_keys).

---

## Requisitos del entorno

- Python **3.12** (o superior)
- pip 24+
- Sistema operativo: Linux / macOS / WSL2

Dependencias Python:

```
pandas>=2.0
numpy>=1.26
scikit-learn>=1.4
matplotlib>=3.8
seaborn>=0.13
joblib>=1.3
```

---

## Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/Ruben1386/secret-scanner-tfm.git
cd secret-scanner-tfm

# 2. Crear entorno virtual
python3.12 -m venv .venv
source .venv/bin/activate        # Linux / macOS / WSL
# .venv\Scripts\activate.bat     # Windows CMD

# 3. Instalar dependencias
pip install pandas numpy scikit-learn matplotlib seaborn joblib
```

---

## Ejecución — reproducción completa de resultados

```bash
# Paso 1: Generar corpus etiquetado (reproducible)
python src/corpus_generator.py --out data/corpus --seed 42
# Resultado: 100 ficheros + data/corpus/ground_truth.json (900 instancias)

# Paso 2: Ejecutar Nivel 1 (regex + entropía)
python src/tier1_baseline.py --corpus data/corpus --out results/
# Resultado: results/tier1_metrics.json + results/tier1_candidates.jsonl

# Paso 3: Entrenar y evaluar Nivel 2 (Random Forest)
python src/tier2_classifier.py --candidates results/tier1_candidates.jsonl --out results/
# Resultado: results/tier2_metrics.json + results/tier2_model.joblib

# Paso 4: Generar figuras
python src/generate_figures.py --results results/ --out results/figures/
# Resultado: 3 figuras PNG 300 dpi en results/figures/
```

**Tiempo estimado de ejecución completa: < 2 minutos** en cualquier CPU de 4 núcleos.

### Comparativa con GitLeaks y TruffleHog (opcional)

Requiere los binarios de [GitLeaks](https://github.com/gitleaks/gitleaks/releases) y [TruffleHog](https://github.com/trufflesecurity/trufflehog/releases) en `tools/`:

```bash
python src/evaluate_tools.py \
  --gt  data/corpus/ground_truth.json \
  --gl  /tmp/gitleaks_out.json \
  --th  /tmp/trufflehog_out.jsonl \
  --out results/
```

---

## Estructura de carpetas

```
secret-scanner-tfm/
├── data/
│   ├── corpus/                  # Corpus propio generado (seed=42)
│   │   ├── file_NNN.txt         # Ficheros de producción (60 ficheros)
│   │   ├── test_NNN.txt         # Ficheros de test (40 ficheros)
│   │   └── ground_truth.json    # Etiquetas canónicas (900 instancias)
│   └── real_repos/              # Repositorios reales clonados para validación
│
├── src/
│   ├── corpus_generator.py      # Generador de corpus reproducible
│   ├── tier1_baseline.py        # Detector N1: regex + entropía + features
│   ├── tier2_classifier.py      # Clasificador N2: Random Forest
│   ├── evaluate_tools.py        # Comparativa vs GitLeaks y TruffleHog
│   ├── validate_real_repos.py   # Validación sobre repos reales públicos
│   └── generate_figures.py      # Figuras para el documento (300 dpi)
│
├── results/
│   ├── tier1_metrics.json       # Métricas N1 (P/R/F1/TP/FP/FN/TN)
│   ├── tier2_metrics.json       # Métricas N2 (CV 5-fold + held-out)
│   ├── comparison_table.json    # Tabla comparativa 4 sistemas
│   ├── real_world_validation.json # Resultados repos reales
│   ├── tier1_candidates.jsonl   # Candidatos etiquetados (dataset N2)
│   ├── tier2_model.joblib       # Modelo N2 serializado
│   └── figures/
│       ├── fig1_comparison_bar.png      # Comparativa P/R/F1
│       ├── fig2_confusion_matrix.png    # Matrices de confusión N1 vs N2
│       └── fig3_feature_importance.png  # Importancias Random Forest
│
├── tools/                       # Binarios GitLeaks y TruffleHog (no incluidos)
│
├── doc/
│   ├── tfm_documento.html       # Documento técnico completo
│   ├── slides_tfm.html          # Presentación (6 slides, reveal.js)
│   └── style.css                # Estilos del documento
│
└── README.md                    # Este fichero
```

---

## Relación con trabajo previo (Módulo 6 Tarea 2)

El Nivel 1 extiende el detector desarrollado en el [Módulo 6 Tarea 2](https://github.com/Ruben1386/secret-scanner-master-m6-) del máster, al que se añadieron:

- Extracción del vector de 17 características de contexto por candidato
- Evaluación cuantitativa P/R/F1 contra ground truth
- Soporte completo de marcadores inline (`# pragma: allowlist`, `# IGNORE`, etc.)

El Nivel 2 (clasificador de reducción de falsos positivos) es una aportación nueva del TFM.

---

## Licencia

MIT License — uso académico y educativo.
