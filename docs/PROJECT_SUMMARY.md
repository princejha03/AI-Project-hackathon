# TrueSignal Project Summary

## 1. Project Overview

TrueSignal is a self-tuning SAST triage agent for Java projects. It works with Checkmarx One scan results, identifies useful code semantics such as sanitizers, taint sources, and sinks, verifies AI classifications against deterministic code evidence, and generates Checkmarx CxQL query overrides.

The central safety rule is:

> Nothing is applied on the LLM's word alone.

Every proposed classification passes through a fixed verification gate. Human review is required before a proposed learning is applied, and every applied override is recorded in an append-only ledger that supports rollback.

## 2. Problem Solved

Traditional SAST tools can produce large numbers of findings, including findings that are not exploitable because a project-specific sanitizer or wrapper was not recognized. TrueSignal helps security teams:

- Reduce repeated manual triage.
- Learn the security meaning of customer-specific functions.
- Distinguish likely false positives from real vulnerabilities.
- Surface vulnerabilities that were previously hidden by incomplete taint knowledge.
- Keep every decision explainable, reviewable, and reversible.

## 3. End-to-End Workflow

```text
Scan results + Java source code
        |
        v
Code indexing
        |
        v
Candidate selection
        |
        v
LLM or mock classification
        |
        v
Deterministic evidence verification gate
        |
        v
Human review and approval
        |
        v
CxQL override generation
        |
        v
Apply override and re-scan
        |
        v
Diff results: downgraded findings and newly surfaced findings
        |
        v
Append audit ledger, feedback, and run summary
```

The CLI and web UI use the same core pipeline.

## 4. Core Safety Model

### Evidence-gated classification

The verifier uses different rules for each role:

- **Sanitizer:** Auto-approval requires sufficient confidence, enough supporting triage decisions, and concrete code reasons. Code evidence without enough triage support goes to human review.
- **Source:** Auto-approval requires sufficient confidence and independent confirmation that the indexed method wraps a known source.
- **Sink:** Auto-approval requires sufficient confidence and independent confirmation that the indexed method touches a known sink.
- **None or weak evidence:** Rejected or sent to review.

The default gate thresholds are:

- Minimum confidence: `0.85`
- Minimum triage support: `3` decisions

Both values are configurable globally and per project.

### Explainable feedback calibration

`FeedbackStore` adjusts confidence by role and attack class using bounded counters rather than machine-learning weights:

- Approved: `+0.01`
- Rejected: `-0.03`
- Rolled back: `-0.06`
- Maximum adjustment: `+/-0.10`

The adjustment is visible in the evidence bundle as raw confidence, calibration adjustment, and effective confidence. It can be reset by removing the feedback state file.

This is deliberately not reinforcement learning. There are no gradients, reward models, policies, or opaque model weights.

### Human-verified fine-tuning loop

The local Ollama classifier has a separate two-gate training-data process:

1. A reviewer action creates a pending correction candidate when a classification is rejected, an override is rolled back, or a finding is confirmed despite a sanitizer override.
2. An administrator reviews, edits, approves, or discards the candidate.

Only approved examples are exported as fine-tuning JSONL. Manual examples created by an administrator are approved immediately because the administrator is the verification step.

## 5. Main Components

### Core Python modules

- `pipeline.py` - Orchestrates ingest, learning, application, rescanning, and diffing.
- `candidate_selector.py` - Selects methods worth classifying from indexed code, findings, and triage history.
- `code_indexer.py` - Regex-based Java indexer that extracts methods, calls, source hints, sink hints, and method relationships.
- `llm_classifier.py` - Shared classification schema and four backends: Anthropic, OpenAI, Ollama, and deterministic mock mode.
- `verifier.py` - Fixed evidence gate that produces approved, needs-review, or rejected verdicts.
- `feedback.py` - Bounded confidence calibration from audit outcomes.
- `training_store.py` - Pending, approved, and discarded fine-tuning example store.
- `override_generator.py` - Deterministically creates CxQL overrides for sanitizers, sources, and sinks.
- `checkmarx_client.py` - Live Checkmarx One REST client and offline fixture-backed mock client.
- `summarizer.py` - Stores AI-authored run summaries and run history.
- `triage_advisor.py` - Provides explainable suggestions for individual finding audits.
- `config.py` - Loads environment configuration and verification thresholds.
- `cli.py` - Command-line interface.

### Web application modules

- `truesignal/webapp/server.py` - Flask application, authentication, UI routes, API routes, analysis workflow, and error handlers.
- `truesignal/webapp/store.py` - Project metadata, scans, triage decisions, settings, activity, search, and project state management.
- `truesignal/webapp/scanner.py` - Stand-in scanner for uploaded Java repositories when no live SAST scan is available.
- `truesignal/webapp/static/style.css` - Application styling, responsive layout, themes, charts, and UI states.
- `truesignal/webapp/static/charts.js` - Client-side chart rendering.
- `truesignal/webapp/static/palette.js` - Theme palette support.
- `truesignal/webapp/templates/` - Landing, login, dashboard, project, findings, audit, analysis, results, ledger, settings, activity, training, analytics, help, and error pages.

## 6. AI and Classification Backends

All classifiers return the same JSON shape:

```json
{
  "role": "sanitizer | source | sink | none",
  "confidence": 0.0,
  "attack_classes": ["sql_injection"],
  "code_reasons": ["concrete explanation"],
  "notes": "additional context"
}
```

Supported providers:

- **Mock:** Deterministic heuristics for offline demonstrations and tests.
- **Anthropic:** Claude Messages API.
- **OpenAI:** Chat Completions API with JSON response format.
- **Ollama:** Local model through the Ollama chat API; no cloud API key required.

Live calls use temperature `0` so classifications are reproducible. The classifier is conservative because an incorrect sanitizer can create a false negative.

## 7. Vulnerability Classes

The shared override metadata and web scanner support these attack classes:

- SQL injection
- Command injection
- Path traversal
- Cross-site scripting (XSS)
- Server-side request forgery (SSRF)
- LDAP injection

The built-in web scanner recognizes common Java and Spring-style sink names, including SQL execution methods, command execution, file reads, HTML rendering, remote fetches, and directory searches. It traces source-to-sink flows within an indexed method's own call sequence.

## 8. Checkmarx Integration

### Live mode

`CheckmarxClient` communicates with Checkmarx One to:

- Find the latest completed scan.
- Retrieve SAST results and taint nodes.
- Retrieve triage predicate history.
- Upload project-level CxQL query overrides.
- Start a new scan and poll until results are available.

### Mock mode

`MockCheckmarxClient` uses bundled fixtures and simulates rescans. It models the demo ground truth, including:

- Sanitizer overrides downgrading planted false positives.
- A learned source wrapper making a previously hidden SQL injection visible.

Mock mode is deterministic and is the default, so the project can run without credentials or network access.

## 9. Web UI

### Authentication and roles

The Flask UI uses session authentication with two configurable demo accounts:

| Role | Default username | Default password |
|---|---|---|
| Admin | `admin` | `checkmarx` |
| AppSec | `appsec` | `checkmarx` |

The Admin role can curate training data, upload projects, apply overrides, and roll back the ledger. AppSec users can audit findings but do not control admin-only training curation.

Change credentials with environment variables before exposing the application outside a local demo.

### Main UI routes

- `/` - Landing page.
- `/login` and `/logout` - Session authentication.
- `/app` - Project dashboard.
- `/projects/new` - Upload a Java ZIP project.
- `/projects/<pid>` - Project overview and impact metrics.
- `/projects/<pid>/findings` - Findings grid, filters, search, and bulk audit.
- `/projects/<pid>/findings/<fid>/audit` - Individual finding audit with taint path and suggestion.
- `/projects/<pid>/analyze` - Learn, review, approve, apply, rescan, and compare.
- `/projects/<pid>/ledger` - Applied override history and rollback actions.
- `/projects/<pid>/settings` - Confidence and triage gate settings plus calibration trends.
- `/projects/<pid>/export/findings.json` - Basic findings export.
- `/projects/<pid>/export/ledger.json` - Ledger export.
- `/activity` - Cross-project audit, ledger, and run-summary activity feed.
- `/analytics` - Analytics view.
- `/help` - Public help and API documentation.
- `/training` - Admin-only training-data curation.

### UI capabilities

- Project cards and live impact metrics.
- Severity and state charts.
- Search palette backed by `/api/search-index`.
- Finding search and severity/state filters.
- Single and bulk audit actions.
- AI suggestions displayed as suggestions, never as decisions.
- Analysis approval screen before changes are applied.
- Rollback from the ledger.
- Dark/light theme toggle saved in browser local storage.
- Responsive layouts for smaller screens.
- Friendly 404, 403, and 500 error pages.

## 10. JSON API

All protected API routes require a logged-in session in the web application.

### Read APIs

- `GET /api/projects` - List projects.
- `GET /api/search-index` - Return projects, findings, and overrides for the command palette.
- `GET /api/projects/<pid>/statistics` - Severity, state, query, impact, and override statistics.
- `GET /api/projects/<pid>/findings/export` - JSON or CSV findings export with severity/state filters.
- `GET /api/search/findings?q=<query>` - Search findings across projects, limited to 50 results.
- `GET /api/projects/compare` - Compare findings, critical/high counts, overrides, downgraded findings, and surfaced findings across projects.

### Existing project exports

- `GET /projects/<pid>/export/findings.json`
- `GET /projects/<pid>/export/ledger.json`

### Write API

- `POST /api/projects/<pid>/bulk-operations` - Validates a bulk operation request and currently supports a `change_state` response scaffold.

Important limitation: the current API bulk-operation handler reports a successful requested count but does not persist the state changes. The browser findings page uses the separate form-based `/projects/<pid>/findings/bulk-audit` route for actual persisted bulk audits.

## 11. CLI

Install the project with `pip install -e .` to use the `truesignal` console command. Without installation, use `python -m truesignal.cli`.

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

Command meanings:

- `ingest` indexes code, retrieves scan/triage data, selects candidates, and writes an ingest bundle.
- `learn` classifies and verifies candidates without applying overrides.
- `analyze` runs the complete learn, review, apply, rescan, diff, and summary workflow.
- `--yes` auto-approves the CLI review step; use carefully.
- `--dry-run` never applies overrides.
- `ledger` prints the append-only applied/rollback history.
- `feedback` prints calibration learned from prior audit actions.
- `history` prints stored run summaries.
- `export-training-data` exports only administrator-approved fine-tuning examples.

`python run.py full` runs fixture generation, the project test runner, a mock `webshop` analysis, and the ledger command. `python run.py` or `python run.py ui` launches the web UI.

## 12. Configuration

Configuration is environment-driven. The default behavior is offline mock mode:

```env
TRUESIGNAL_MODE=mock
TRUESIGNAL_LLM=mock
TRUESIGNAL_MIN_CONF=0.85
TRUESIGNAL_MIN_TRIAGE=3
```

Live Checkmarx mode:

```env
TRUESIGNAL_MODE=live
CX_BASE_URL=https://ast.checkmarx.net
CX_TENANT=your-tenant
CX_API_KEY=your-api-refresh-token
```

Live LLM options:

```env
TRUESIGNAL_LLM=anthropic
ANTHROPIC_API_KEY=...

TRUESIGNAL_LLM=openai
OPENAI_API_KEY=...

TRUESIGNAL_LLM=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1
```

Web settings include:

- `TRUESIGNAL_SECRET_KEY`
- `TRUESIGNAL_SESSION_SECURE`
- `TRUESIGNAL_PORT`
- `TRUESIGNAL_ADMIN_USER`
- `TRUESIGNAL_ADMIN_PASSWORD`
- `TRUESIGNAL_APPSEC_USER`
- `TRUESIGNAL_APPSEC_PASSWORD`

Paths can be customized with `TRUESIGNAL_REPO` and `TRUESIGNAL_STATE`.

## 13. Storage and Auditability

TrueSignal does not require a database. State is stored as JSON under git-ignored directories:

- `.truesignal/` - Core pipeline state, ledger, feedback, run history, and training examples.
- `.truesignal_ui/` - Web UI project data and uploaded project state.
- `fixtures/` - Baseline scan and triage data used by mock mode.

Important append-only or history-oriented records include:

- `ledger.json` - Applied and rolled-back overrides.
- `feedback.json` - Human approval, rejection, and rollback calibration events.
- `training_examples.json` - Pending, approved, and discarded fine-tuning examples.
- Run history JSON - AI-authored summaries of completed analysis runs.
- Per-project `triage.json` - Audit decisions and reviewer comments.

## 14. Demo Projects

The repository includes three intentionally vulnerable Java demo projects:

- `webshop` - SQL injection and sanitizer/source learning scenarios.
- `cmdi-demo` - Command injection examples.
- `toolbox-demo` - Path traversal, XSS, SSRF, and LDAP injection examples.

The web UI seeds these projects automatically. The CLI demo primarily operates on `webshop` and its fixtures.

## 15. Installation and Running

Requirements:

- Python 3.10 or newer.
- Flask and Waitress for the optional web UI.
- Pytest for the test suite.
- Requests for Checkmarx and LLM HTTP clients.

Recommended setup:

```bash
python -m venv venv
venv\Scripts\activate
pip install -e ".[web,test]"
copy .env.example .env
```

Run the web UI:

```bash
python run.py
```

The launcher checks Python version, ensures Flask is available, starts the Flask server on `127.0.0.1:5000`, and opens a browser. The server port can be changed with `TRUESIGNAL_PORT`.

Run tests:

```bash
python -m pytest -q
```

The repository also includes Windows launchers: `run.bat` and `run_ui.bat`.

## 16. Testing and CI

The current suite contains 25 tests:

- 12 pipeline tests in `tests/test_pipeline.py`.
- 5 triage-advisor tests in `tests/test_triage_advisor.py`.
- 8 training-store tests in `tests/test_training_store.py`.

The tests cover:

- Ground-truth learning.
- False-learning prevention.
- End-to-end apply and rescan behavior.
- Idempotent repeated runs.
- Stability across multiple runs.
- Feedback bounds and trends.
- Rollback lowering confidence.
- Evidence-gate safety.
- Run-history persistence.
- Triage suggestions and unresolved paths.
- Training approval, editing, discarding, and export gates.

GitHub Actions runs the test suite on pushes and then runs a live demo analysis according to `.github/workflows/truesignal.yml`.

## 17. Package and Dependencies

The project is packaged as `truesignal` version `0.1.0` and requires Python `>=3.10`.

Core dependency:

- `requests>=2.28`

Optional dependencies:

- Web: `flask>=3`, `waitress>=2`.
- Tests: `pytest>=7`.
- Fine-tuning: `torch`, `transformers`, `peft`, `trl`, and `datasets`.

Console scripts:

- `truesignal = truesignal.cli:main`
- `truesignal-ui = truesignal.webapp.server:main`

## 18. Security and Deployment Notes

Before using the UI beyond a local demo:

- Change both default passwords through environment variables.
- Set a stable, secret `TRUESIGNAL_SECRET_KEY`.
- Use HTTPS and set `TRUESIGNAL_SESSION_SECURE=true` when appropriate.
- Protect Checkmarx and LLM credentials in a secret manager or environment configuration.
- Back up the JSON state directories because they contain audit and learning history.
- Keep the human review step enabled for production workflows.
- Review generated CxQL before applying it to a live tenant.

The application is an internal Checkmarx project and is not currently licensed for external distribution.

## 19. Known Limitations

- The Java indexer is regex-based rather than a full Java parser.
- The built-in web scanner traces flows within a method's own call sequence and is a stand-in for live SAST.
- The live Checkmarx API paths may need adjustment for tenant or regional API differences.
- The API bulk-operation endpoint is currently a validation/reporting scaffold and does not persist state changes.
- Default demo credentials are intentionally simple and must not be used in a real deployment.
- The root README is the operational source of truth; older documents in `docs/` may describe previous behavior.

## 20. Repository Map

```text
true signal/
├── truesignal/                 Core Python package
│   ├── pipeline.py             Main orchestration
│   ├── code_indexer.py         Java indexing
│   ├── candidate_selector.py   Candidate selection
│   ├── llm_classifier.py       AI and mock classifiers
│   ├── verifier.py             Evidence gate
│   ├── feedback.py             Confidence calibration
│   ├── training_store.py       Fine-tuning curation
│   ├── override_generator.py   CxQL generation and ledger
│   ├── checkmarx_client.py     Live and mock Checkmarx clients
│   ├── triage_advisor.py       Finding suggestions
│   ├── summarizer.py           Run summaries and history
│   ├── config.py               Environment configuration
│   ├── cli.py                  CLI commands
│   └── webapp/                 Flask application and templates
├── demos/                      Vulnerable Java demo repositories
├── fixtures/                   Mock scans and triage history
├── tests/                      25-test pytest suite
├── scripts/                    Fixture, test, and fine-tuning scripts
├── docs/                       Supplementary and historical documents
├── run.py                      Main launcher
├── run.bat                     Windows full launcher
├── run_ui.bat                  Windows UI launcher
├── pyproject.toml              Package metadata and dependencies
├── .env.example                Configuration template
└── README.md                   Current operational README
```

## 21. Project Status

TrueSignal is a working prototype/demo with:

- A complete offline mock workflow.
- Optional live Checkmarx One integration.
- Multiple LLM backends.
- Web and CLI interfaces.
- Human review and rollback controls.
- Admin-gated fine-tuning data curation.
- A passing 25-test suite.

The most important production-hardening work remaining is tightening deployment security, replacing or supplementing regex indexing with a stronger parser, validating live Checkmarx API behavior per tenant, and completing persistence for the JSON bulk-operation endpoint.

---

**Current source of truth:** `README.md`, source code under `truesignal/`, configuration in `.env.example`, and tests under `tests/`.
