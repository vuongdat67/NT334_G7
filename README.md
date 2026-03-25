# volGPT Reproduction and Improvement (Course Project)

This repository starts a fresh implementation inspired by the paper:
volGPT: Evaluation on triaging ransomware process in memory forensics with Large Language Model (FSI:DI, 2024).

## 1) Project Goal

Build a reproducible memory-forensics triage pipeline:

1. Memory dump input
2. Volatility 3 plugins (`windows.pslist`, `windows.vadinfo`, `windows.malfind`)
3. Structured JSON artifacts
4. Prompt-based LLM triage (majority voting, 3 runs)
5. Evaluation with Accuracy, Precision, Recall, F1, and Triage Efficiency
6. Hallucination-oriented error analysis

This implementation follows your selected scope:

- Reproduce first, then improve
- Phase 1 dataset: Arfeen 2020 only
- API budget target: <= 20 USD

## 2) Safety Rules (Mandatory)

- Do not execute ransomware binaries on host OS.
- Use memory dumps only for Phase 1.
- Keep analysis inside WSL2 Ubuntu or isolated VM/container.
- Never commit API keys, memory dumps, or sensitive outputs.

## 3) Current Structure

- `src/`: core modules
- `config/`: prompt template and decision rules
- `scripts/`: CLI entry points
- `results/`: output artifacts
- `docs/`: design notes and experiment notes
- `tests/`: test stubs

## 4) Quick Start (WSL2 Ubuntu)

### 4.1 Create Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 4.2 Environment variables

Copy and edit `.env.example`:

```bash
cp .env.example .env
```

Set your model key (at least one provider):

- `OPENAI_API_KEY`
- `GEMINI_API_KEY` (optional, later comparison)

### 4.3 Configure project

Copy and edit config:

```bash
cp config/config.example.json config/config.local.json
```

Update:

- `volatility_script_path`
- `memory_dump_path`
- `openai_model`

### 4.4 Run pipeline

```bash
python scripts/run_pipeline.py --config config/config.local.json
```

Outputs:

- `results/triage_report.json`
- `results/triage_votes.json`

### 4.5 Run evaluation

```bash
python scripts/evaluate.py \
  --pred results/triage_report.json \
  --labels results/labels_example.json
```

## 5) Phase Plan

- Phase A: Environment + Volatility 3 validation
- Phase B: Data + labeling prep
- Phase C: Baseline reproduction pipeline
- Phase D: Metrics + family-level analysis
- Phase E: Hallucination reduction (prompt hardening)
- Phase F: Optional ML baseline (XGBoost)

## 6) Next Immediate Tasks

1. Connect Volatility 3 command on your machine and validate plugin outputs.
2. Place 1 sample memory dump and run end-to-end once.
3. Replace mock labels with real Arfeen labels.
4. Add prompt v2 and compare FP/FN changes.
