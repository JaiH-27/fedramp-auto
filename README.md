# FedRAMP-Auto

Automated FedRAMP 20x compliance engine. Point it at your Terraform, get back a gap report and OSCAL package — no consulting firm required.

**Runs 100% locally.** Your infrastructure code never leaves your machine.

---

## How it works

```
Your .tf files
     │
     ▼
Local CLI agent          ← strips secrets/PII before anything else runs
     │
     ▼
Mistral 7B (Ollama)      ← maps resources to NIST 800-53 controls
     │
     ▼
KSI gap detector         ← compares against 56 (Low) / 61 (Moderate) FedRAMP KSIs
     │
     ▼
Remediation advisor      ← plain-English fixes + Terraform snippets per gap
     │
     ▼
OSCAL SSP (JSON)         ← RFC-0024 compliant, ready for FedRAMP submission
```

---

## 5-minute quickstart

### Prerequisites

- Python 3.11+
- [Poetry](https://python-poetry.org/docs/#installation)
- [Ollama](https://ollama.com) with Mistral 7B (see setup below)

### 1. Install Ollama + Mistral 7B

```bash
# macOS / Linux — run the setup script included in this repo
chmod +x scripts/setup_ollama.sh
./scripts/setup_ollama.sh
```

This installs Ollama, starts the local server, and pulls Mistral 7B (~4 GB).

### 2. Install FedRAMP-Auto

```bash
git clone https://github.com/yourorg/fedramp-auto
cd fedramp-auto
poetry install
```

### 3. Configure

```bash
cp .env.example .env
# Edit .env if you need non-default settings (baseline, output dir, etc.)
```

### 4. Run your first scan

```bash
poetry run fedramp-auto scan ./path/to/your/terraform --baseline low --output ./output
```

Output:

```
  FedRAMP-Auto · scan
    Directory : /your/infra
    Baseline  : LOW
    Model     : mistral
    Output    : ./output

  FedRAMP 20x LOW baseline gap report
    KSI coverage : 18/32 (56.3%)
    Critical gaps: 4
    High gaps    : 6
    Total gaps   : 14

  Results saved:
    ./output/scan_result.json
    ./output/report.md
```

### 5. View the gap report

```bash
# Terminal summary
poetry run fedramp-auto report ./output/scan_result.json

# With remediation Terraform snippets
poetry run fedramp-auto report ./output/scan_result.json --remediations

# Full markdown report
open ./output/report.md
```

### 6. Validate an OSCAL SSP

```bash
poetry run fedramp-auto validate ./output/ssp.json
```

---

## CLI reference

### `fedramp-auto scan`

```
fedramp-auto scan INFRA_DIR [OPTIONS]

Arguments:
  INFRA_DIR   Directory of .tf files (searched recursively)

Options:
  --baseline  -b   low | moderate            [default: low]
  --output    -o   Output directory           [default: ./output]
  --model     -m   Ollama model name          [default: mistral]
  --ollama-url     Ollama API URL             [default: http://localhost:11434]
  --no-llm         Static rules only, no LLM
  --verbose   -v   Debug logging
```

Exit codes: `0` = no critical gaps, `2` = critical gaps found (useful in CI).

### `fedramp-auto report`

```
fedramp-auto report RESULT_FILE [OPTIONS]

Options:
  --remediations  -r   Print Terraform remediation snippets
```

### `fedramp-auto validate`

```
fedramp-auto validate SSP_FILE [OPTIONS]

Options:
  --verbose  -v   Debug logging
```

---

## CI/CD integration

Add to your GitHub Actions workflow to block PRs that introduce critical compliance gaps:

```yaml
- name: FedRAMP compliance scan
  run: |
    pip install fedramp-auto
    fedramp-auto scan ./infra --baseline low --no-llm --output ./fedramp-output
  # Exit code 2 = critical gaps found → PR blocked
```

---

## Architecture

| Module | Purpose |
|--------|---------|
| `fedramp_auto.parser.terraform` | Parses .tf files via `python-hcl2`, strips secrets |
| `fedramp_auto.mapper.control_mapper` | Static rules + Mistral 7B → NIST 800-53 controls |
| `fedramp_auto.gaps.detector` | 56/61 KSI gap analysis |
| `fedramp_auto.advisor.remediation` | Per-gap fix guidance + Terraform snippets |
| `fedramp_auto.oscal` | OSCAL SSP generation via `compliance-trestle` |
| `fedramp_auto.cli.main` | Typer CLI (scan / report / validate) |

---

## Privacy model

- Raw `.tf` files **never leave your machine**.
- The parser strips string values matching secret patterns before any processing.
- Mistral 7B runs locally via Ollama — no data sent to any cloud API.
- Only sanitized resource *type* and *attribute name* data is passed to the model.

---

## Roadmap

- [x] Phase 1: Terraform parser + project scaffold
- [x] Phase 2: Control mapper + KSI gap detector + remediation advisor
- [x] Phase 4: CLI (scan / report / validate)
- [ ] Phase 3: OSCAL SSP generator (compliance-trestle integration)
- [ ] Azure ARM template support
- [ ] AWS CDK support
- [ ] GitHub App for automated PR comments
- [ ] Web dashboard

---

## License

MIT
