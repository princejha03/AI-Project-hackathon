# TrueSignal: Complete Project Guide

## 1. What This Project Is

TrueSignal is a self-tuning SAST triage agent for Java applications. It helps an AppSec team teach a static-analysis system about security-relevant functions that are specific to a customer codebase.

The project focuses on a common SAST problem: a scanner can report a vulnerability because it does not recognize a custom sanitizer, or fail to report a vulnerability because it does not recognize a custom source or sink. TrueSignal learns those meanings from source code, existing scan findings, and past human triage decisions.

The result is a controlled feedback loop that can:

- Reduce repeated manual false-positive triage.
- Recognize customer-specific sanitizers, taint sources, and sinks.
- Generate Checkmarx CxQL query overrides.
- Re-scan the project and show the impact of each learning decision.
- Make newly visible vulnerabilities easier to find.
- Preserve evidence, history, and rollback capability for every change.

The central safety principle is:

> Nothing is applied on the LLM's word alone.

The AI proposes a classification. Deterministic code evidence and existing triage history decide whether that proposal can be approved automatically. Human review is available whenever the evidence is incomplete.

## 2. The Problem Demonstrated by the Built-In Example

The primary demo is a deliberately vulnerable Java webshop:

- `InputCleaner.sanitize()` and `sanitizeNumeric()` are real in-house sanitizers.
- The SAST baseline does not know those methods are sanitizers, so seven safe flows are reported as high-severity SQL injection findings.
- `LegacyRequest.getParam()` wraps a request parameter accessor but is not known as a taint source.
- One SQL injection through that wrapper is therefore invisible in the baseline.
- TrueSignal learns the sanitizer and source semantics, applies overrides, and simulates a re-scan.

The expected demo result is:

- Seven false positives are downgraded to not exploitable.
- One previously hidden critical SQL injection becomes visible.
- The genuine existing true positive remains a live finding.
- A second run is idempotent and does not re-learn already-applied functions.

Two additional demo repositories show that the web scanner supports command injection, path traversal, XSS, SSRF, and LDAP injection patterns as well.

## 3. End-to-End Workflow

```text
Java source + baseline scan + triage history
                    |
                    v
             Index the code
                    |
                    v
          Select useful candidates
                    |
                    v
       Classify with AI or mock logic
                    |
                    v
       Verify with deterministic gate
                    |
        +-----------+-----------+
        |                       |
     Reject                Human review
        |                       |
        +-----------+-----------+
                    v
          Generate CxQL overrides
                    |
                    v
       Apply approved overrides safely
                    |
                    v
                Re-scan
                    |
                    v
 Compare baseline and rescan results
                    |
                    v
 Append ledger, feedback, and summary
```

The CLI and Flask web application share the same core Python pipeline. They differ mainly in how projects and scan results are supplied:

- **CLI:** Uses the Checkmarx client abstraction. Mock mode reads bundled fixtures; live mode calls Checkmarx One.
- **Web UI:** Creates projects from uploaded Java ZIP files and uses a local stand-in scanner when no live Checkmarx scan is connected.

## 4. Architecture

### Core pipeline

`truesignal/pipeline.py` coordinates the major stages:

1. `run_ingest()` indexes Java methods, loads scan results and triage history, selects candidates, and writes `ingest_bundle.json`.
2. `run_learn()` classifies each candidate and sends the result through the verification gate. It writes `semantics.json`.
3. `run_apply()` converts approved verdicts into overrides, applies them one at a time, and records each successful application in the ledger.
4. `diff_results()` compares the baseline and re-scan to identify downgraded findings and newly surfaced findings.

The application is intentionally idempotent. The ledger tracks the latest state for each learned function, so already-applied functions are skipped and rolled-back functions can be learned again.

### Main modules

| Module | Responsibility |
|---|---|
| `config.py` | Loads environment settings, paths, providers, and verification thresholds. |
| `code_indexer.py` | Regex-based Java indexer. Extracts methods, calls, source hints, sink hints, and relationships. |
| `candidate_selector.py` | Chooses methods worth classifying from indexed code, findings, and triage history. |
| `llm_classifier.py` | Provides one classification contract and Mock, Anthropic, OpenAI, and Ollama backends. |
| `verifier.py` | Applies the fixed evidence gate. Produces `APPROVED`, `NEEDS_REVIEW`, or `REJECTED`. |
| `feedback.py` | Applies bounded, explainable confidence calibration based on audit outcomes. |
| `override_generator.py` | Converts verified roles into deterministic CxQL overrides and maintains the audit ledger. |
| `checkmarx_client.py` | Defines the client interface plus live Checkmarx One and fixture-backed mock implementations. |
| `summarizer.py` | Creates and stores plain-English summaries of analysis runs and run history. |
| `triage_advisor.py` | Suggests finding audit outcomes using explainable rules. Suggestions do not make decisions. |
| `pattern_library.py` | Reuses currently applied patterns across projects as advisory, deterministic matches. |
| `training_store.py` | Holds pending, approved, and discarded examples for human-verified fine-tuning. |
| `jsonstore.py` | Reads and writes the local JSON state files. |
| `cli.py` | Implements the `truesignal` command-line interface. |

## 5. The Verification and Safety Model

The verifier is the most important control in the project. It prevents a plausible-looking AI answer from directly changing scan behavior.

### Sanitizers

Sanitizers receive the strictest treatment because a false sanitizer classification can hide a real vulnerability. Automatic approval requires all of the following:

- Effective confidence at or above the configured threshold.
- At least the configured number of supporting dismissal decisions.
- Concrete code reasons from the classifier.

Code evidence without enough triage support becomes `NEEDS_REVIEW` instead of being applied automatically.

### Sources and sinks

Automatic source approval requires both adequate confidence and independent indexer confirmation that the method wraps a known source. Automatic sink approval uses the equivalent check for known sinks.

### Confidence calibration

Feedback changes confidence through bounded counters, not hidden model training:

- Approved: `+0.01`.
- Rejected: `-0.03`.
- Rolled back: `-0.06`.
- Maximum adjustment: `+/-0.10`.

The raw confidence, adjustment, and effective confidence are all retained in the evidence bundle. This keeps the decision explainable and makes clear that the mechanism is calibration, not reinforcement learning.

### Human-verified training loop

Reviewer actions can create pending correction examples when:

- A classification is rejected.
- An applied override is rolled back.
- A finding is confirmed even though a sanitizer override affected its path.

An administrator must curate these examples before they are exported as fine-tuning JSONL. Manual administrator-created examples are approved immediately because the administrator is the verification step.

## 6. AI Backends

Every backend returns the same structured result:

```json
{
  "role": "sanitizer | source | sink | none",
  "confidence": 0.0,
  "attack_classes": ["sql_injection"],
  "code_reasons": ["concrete explanation"],
  "notes": "additional context"
}
```

Supported providers are:

- **Mock:** Deterministic heuristics for offline demos and tests.
- **Anthropic:** Claude Messages API.
- **OpenAI:** Chat Completions API with JSON response format.
- **Ollama:** Local Ollama chat API, requiring no cloud API key.

Live classifications use temperature `0` for repeatability. Network or malformed-response failures for one candidate are converted into a visible low-evidence verdict so the rest of a learning run can continue.

## 7. Checkmarx Integration

### Live mode

The live client can:

- Find the latest completed scan.
- Retrieve SAST results and taint nodes.
- Retrieve triage predicate history.
- Upload project-level CxQL query overrides.
- Start a new scan and poll for completion.

Authentication uses the Checkmarx One tenant and API refresh token configured through environment variables. Transient connection failures and HTTP `429`/`5xx` responses are retried; invalid authentication or request errors fail promptly.

### Mock mode

Mock mode is the default and needs no credentials or network access. It reads:

- `fixtures/baseline_scan.json`
- `fixtures/triage_history.json`

The mock client models the planted webshop ground truth, including seven sanitizer-related false positives and the hidden SQL injection that appears after learning the source wrapper.

## 8. CxQL Override Generation

The AI never writes executable CxQL directly. `override_generator.py` uses fixed templates for three roles:

- Sanitizer: removes flows influenced by the custom sanitizer from the base query result.
- Source: adds flows originating from the custom source wrapper.
- Sink: adds flows reaching the custom sink.

The attack class selects the base query. Supported metadata includes SQL injection, command injection, path traversal, XSS, SSRF, and LDAP injection.

Each generated override contains its function, role, language, query name, attack class, CxQL text, confidence, and evidence. This record is also what is stored in the ledger.

## 9. Web Application

The web application is a Flask UI started by `python run.py` or `truesignal-ui`.

### Typical user journey

1. Log in.
2. Select a built-in project or upload a Java ZIP.
3. Inspect project metrics and scan findings.
4. Search and filter findings by severity or state.
5. Open a finding to view its taint path and triage suggestion.
6. Audit findings individually or in bulk.
7. Start analysis to see proposed learnings.
8. Review and approve proposed overrides.
9. Apply approved overrides and inspect the re-scan diff.
10. Review the ledger, export results, or roll back an override.
11. Administrators curate training examples at `/training`.

### UI routes and capabilities

- `/` - Landing page.
- `/login`, `/logout` - Session authentication.
- `/app` - Cross-project dashboard.
- `/projects/new` - Java ZIP upload.
- `/projects/<pid>` - Project overview and impact metrics.
- `/projects/<pid>/findings` - Findings grid, filters, search, and bulk audit.
- `/projects/<pid>/findings/<fid>/audit` - Individual finding audit.
- `/projects/<pid>/analyze` - Learn, review, apply, re-scan, and compare.
- `/projects/<pid>/ledger` - Applied override history and rollback.
- `/projects/<pid>/settings` - Per-project thresholds and calibration trends.
- `/projects/<pid>/export/findings.json` - Findings export.
- `/projects/<pid>/export/ledger.json` - Ledger export.
- `/activity` - Cross-project audit, ledger, and run-summary activity.
- `/analytics` - Analytics view.
- `/help` - Help and API documentation.
- `/training` - Admin-only training-data curation.

The UI includes responsive layouts, severity/state charts, search palette support, dark/light theme persistence, role-based access, and friendly error pages. Mutating actions use POST requests, and analysis always lands on a review step before applying changes.

## 10. Web Upload and Stand-In Scanner

`webapp/store.py` manages uploaded projects, project metadata, baseline scans, triage decisions, and applied overrides. ZIP extraction has both compressed upload and uncompressed disk-size protections.

`webapp/scanner.py` provides a deterministic local scanner for uploaded Java projects. It indexes method call sequences and traces a known source followed by a known sink inside the same method. Learned source wrappers can then make previously invisible flows appear on the next scan.

The stand-in scanner is useful for a self-contained demonstration, but it is not a replacement for a production SAST engine. It intentionally uses lightweight pattern matching and does not perform full Java parsing or whole-program data-flow analysis.

## 11. Local State and Data Files

The project does not use a database. Runtime state is JSON on disk:

- `.truesignal/` - CLI ingest bundles, semantics, ledger, feedback, and run history.
- `.truesignal_ui/` - Web project metadata, scans, triage, and UI activity.
- `fixtures/` - Committed mock scan and triage inputs.
- `training_data.jsonl` - Optional exported approved fine-tuning dataset.

Runtime directories, secrets, caches, build artifacts, and local environment files are git-ignored. The ledger is append-only; its latest event per function determines whether an override is currently applied.

## 12. Installation and Running

Requirements: Python 3.10 or newer.

```bash
python -m venv venv
venv\Scripts\activate
pip install -e ".[web,test]"
python run.py
```

`python run.py` starts the web UI at `http://127.0.0.1:5000` and opens a browser. Flask is installed automatically by the launcher if necessary.

Default demo accounts are:

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `checkmarx` |
| AppSec | `appsec` | `checkmarx` |

For the command-line demonstration:

```bash
python run.py full
```

This regenerates fixtures, runs tests, analyzes the webshop in mock mode, and prints the ledger.

## 13. CLI Commands

After `pip install -e .`, the commands are available through `truesignal`:

```bash
truesignal ingest --project webshop
truesignal learn --project webshop
truesignal analyze --project webshop
truesignal analyze --project webshop --yes
truesignal analyze --project webshop --dry-run
truesignal ledger
truesignal feedback
truesignal history
truesignal export-training-data
```

The same commands can be run without installation using `python -m truesignal.cli <command>`.

- `ingest` builds the evidence bundle.
- `learn` classifies and verifies without applying changes.
- `analyze` runs the complete learning, review, apply, re-scan, and diff loop.
- `--yes` auto-approves eligible review items for CI or demos.
- `--dry-run` prevents all override application.
- `ledger` displays applied and rolled-back changes.
- `feedback` displays calibration history.
- `history` displays AI-authored run summaries.
- `export-training-data` writes administrator-approved corrections as JSONL.

## 14. Configuration

Mock mode is the default:

```text
TRUESIGNAL_MODE=mock
TRUESIGNAL_LLM=mock
```

Live Checkmarx and AI providers can be selected with `.env` or environment variables:

```text
TRUESIGNAL_MODE=live
TRUESIGNAL_LLM=anthropic
ANTHROPIC_API_KEY=...
CX_BASE_URL=https://ast.checkmarx.net
CX_TENANT=...
CX_API_KEY=...
```

Other supported values are `TRUESIGNAL_LLM=openai` and `TRUESIGNAL_LLM=ollama`. Ollama uses `OLLAMA_BASE_URL` and `OLLAMA_MODEL` and requires a locally running Ollama server.

Important options include:

- `TRUESIGNAL_MIN_CONF` - automatic approval confidence threshold; default `0.85`.
- `TRUESIGNAL_MIN_TRIAGE` - sanitizer dismissal support threshold; default `3`.
- `TRUESIGNAL_REPO` - CLI repository path override.
- `TRUESIGNAL_STATE` - CLI state directory override.
- `TRUESIGNAL_SECRET_KEY` - Flask session secret.
- `TRUESIGNAL_MAX_UPLOAD_MB` - web upload limit; default `50` MB.
- `TRUESIGNAL_ADMIN_USER` and `TRUESIGNAL_ADMIN_PASSWORD` - admin credentials.
- `TRUESIGNAL_APPSEC_USER` and `TRUESIGNAL_APPSEC_PASSWORD` - AppSec credentials.

Default demo credentials are for local demonstration only and must be changed before exposing the UI.

## 15. Testing and CI

Run the test suite with:

```bash
python -m pytest -q
```

The tests cover JSON persistence, pattern matching, client behavior, pipeline correctness, triage advice, feedback calibration, rollback behavior, and training-data curation. The end-to-end pipeline tests verify the planted webshop outcomes, including exact downgraded and newly surfaced finding counts and idempotence.

The GitHub Actions workflow in `.github/workflows/truesignal.yml` runs the test suite on pushes and then exercises the mock analysis workflow.

## 16. Demo Repositories

- `demos/demo-repo` - SQL injection, custom sanitizers, and a wrapped request source.
- `demos/demo-repo-cmdi` - command injection example.
- `demos/demo-repo-toolbox` - path traversal, XSS, SSRF, and LDAP injection examples.

These repositories are intentionally vulnerable teaching fixtures. They exist to demonstrate detection and triage behavior, not to represent secure production code.

## 17. Current Boundaries and Future Improvements

TrueSignal is a hackathon-quality prototype with a strong audit and safety story. Its current boundaries are important:

- The Java indexer is regex-based rather than a full Java parser.
- The web scanner traces calls within one method and does not perform complete whole-program data-flow analysis.
- Live Checkmarx API endpoint details may need adjustment for a tenant or region.
- The local JSON stores are simple and appropriate for a demo or single-user workflow, not concurrent production-scale operation.
- Default credentials and development-style session behavior require hardening for deployment.
- AI classifications remain suggestions until the deterministic gate and, where needed, a human approve them.

Natural next steps would be a proper Java AST/indexing layer, richer interprocedural analysis, production database and concurrency controls, stronger deployment authentication, broader Checkmarx API integration tests, and more extensive benchmark projects.

## 18. One-Sentence Summary

TrueSignal is an explainable, reversible bridge between AI-assisted code-semantics discovery and Checkmarx SAST triage: it learns what customer-specific Java functions do, proves those claims with evidence, lets humans control the change, and shows exactly how the scan results improve.
