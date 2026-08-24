# TrueSignal — Demo Video Script (~13 minutes)

**Audience:** competition judges — assume security/engineering background, zero prior context on this specific tool.
**Format:** screen share + voiceover. `**[SCREEN: ...]**` = what to click/show. Everything else is narration — read it naturally, don't recite it robotically.

**Before you hit record:**
- Run `python run.py` from the project root. Wait for the browser to open to `http://127.0.0.1:5000`.
- Have two browser profiles/windows ready if you want to show both roles (Admin / AppSec) without logging out on camera.
- Demo logins: `admin` / `checkmarx` (full access) and `appsec` / `checkmarx` (read-only on settings/rollback, no access to analyze/upload/training).
- The three seeded demo projects: **WebShop** (SQL injection), **ReportServlet/cmdi-demo** (Command injection), **SecureApp/toolbox-demo** (Path traversal, XSS, SSRF, LDAP injection).

---

## 0:00 – 0:40 — The problem (hook)

**[SCREEN: title slide or blank browser tab — don't open the app yet]**

> Every SAST tool has the same trust problem. You scan a codebase, you get hundreds of findings, and most of them are noise — false positives that pass through some custom sanitizer the scanner doesn't understand. Security teams spend hours re-proving the same thing over and over: "yes, this one's fine, it goes through our input cleaner." And because that knowledge never gets fed back into the scanner, next month's scan flags the exact same false positive again. Meanwhile, the findings that *do* matter are buried in that noise, and worse — sometimes a vulnerability is completely invisible because the scanner doesn't recognize a wrapper function as a real taint source.

> That's the problem TrueSignal solves. It's a self-tuning triage agent that sits on top of Checkmarx One. It watches how your team actually triages findings, learns your codebase's real sanitizers, sources, and sinks, and turns that into permanent scanner overrides — so the same false positive never has to be re-triaged again, and hidden vulnerabilities get surfaced instead of staying invisible.

---

## 0:40 – 1:20 — The core promise, up front

**[SCREEN: open http://127.0.0.1:5000 — the landing page]**

> Before I show you anything, I want to state the one rule this entire project is built around, because it's the thing that makes this safe to actually use: **nothing is ever applied on the AI's word alone.** Every single classification the LLM proposes passes through a fixed, deterministic evidence gate before it can auto-apply. If the evidence isn't strong enough, it doesn't get silently approved — it goes to a human review screen instead. And every override that *does* get applied is logged in an append-only ledger and can be rolled back with one click. So this isn't "trust the AI" — it's "the AI proposes, a fixed rule plus a human decides."

> Let's see it in action.

---

## 1:20 – 2:30 — Architecture, at a glance

**[SCREEN: stay on landing page, scroll to the "how it works" section, or just narrate over it]**

> The pipeline is five steps:

> **One** — index the code. A lightweight Java indexer walks the repo and extracts every method: its source, what it calls, and whether it touches a known source like `getParameter` or a known sink like `executeQuery`.

> **Two** — classify candidates. Functions worth looking at — because they sit on a taint path, or wrap a known source, or touch a known sink — get sent to an LLM with a shared prompt. It comes back with a role: sanitizer, source, sink, or none, plus a confidence score and concrete code reasons.

> **Three** — verify. This is the safety gate. A sanitizer only auto-approves if the confidence clears a threshold *and* there's independent triage support — real humans who already dismissed findings citing that function. A source or sink needs the code indexer to independently confirm it actually wraps a source or touches a sink. Anything short of that goes to human review, not auto-reject, not auto-approve.

> **Four** — apply. Approved classifications become CxQL query overrides — actual Checkmarx query language, one template per role, generated deterministically, not by the LLM.

> **Five** — re-scan and diff. Run the scan again with the override applied, and show exactly what changed: which false positives got downgraded, and — this is the interesting part — whether anything that was previously invisible just became visible.

> Let's walk through a real run.

---

## 2:30 – 3:15 — Login and the dashboard

**[SCREEN: click "Get Started" → log in as `admin` / `checkmarx`]**

> I'm logging in as an admin. There's a second role, AppSec, that can triage and audit findings but can't upload projects, run analysis, change settings, or roll back the ledger — I'll come back to that permission boundary later, because it's not just cosmetic.

**[SCREEN: the /app dashboard]**

> This is the cross-project dashboard. Three projects here, each with a different vulnerability class — SQL injection, command injection, and a mix of path traversal, XSS, SSRF, and LDAP injection. Every number here is re-derived live from the ledger and the current scan state — nothing is cached, so what you're looking at is exactly what the system currently believes about these projects.

> Notice the "noise eliminated" gauge — that's not a cosmetic percentage, it's downgraded findings divided by total findings, computed fresh on every page load.

---

## 3:15 – 7:30 — The core workflow: WebShop

**[SCREEN: click into the WebShop project]**

> Let's go into WebShop. This project has a SQL injection scenario: a `Statement.executeQuery` sink, and a homegrown input-cleaning function called `InputCleaner.sanitize` that the scanner has no way of knowing is safe.

**[SCREEN: click "Findings & audit"]**

> Here's the findings grid — this is meant to feel like a normal Checkmarx audit pass. Eight — soon nine — findings, all flagged HIGH, all going through the same taint path pattern: `getParameter` into `InputCleaner.sanitize` into a database query.

> Let's audit a few of these the way a real reviewer would. I'll open one up.

**[SCREEN: click "Audit" on one finding, e.g. CX-1002]**

> This is the per-finding audit screen. You get the full taint path with the actual source code at each step, and — this is a nice touch — a *suggestion*, not a decision. It's telling me this path passes through something that looks like a strict allow-list filter, so it's probably safe, but it's explicitly labeled "not a decision, you choose." I'll mark it Not Exploitable and note why.

**[SCREEN: fill in decision=Not Exploitable, comment="goes through InputCleaner.sanitize, safe", submit]**

> I could do this one at a time, or select several and bulk-audit them — there's a bulk-audit bar at the bottom of the findings grid for exactly that. In this project, that triage history already exists — several reviewers have independently dismissed findings citing this same function. That's the evidence the verifier is going to ask for in a second.

**[SCREEN: go back to project overview, click "Run TrueSignal analysis"]**

> Now let's run analysis. This is the "learn" step — the LLM looks at candidates and proposes classifications, but nothing is applied yet. This screen is the human review gate.

**[SCREEN: the learn.html review screen — point out the candidates]**

> `InputCleaner.sanitize` — proposed as a sanitizer, with concrete code reasons: it's a strict allow-list, quotes and SQL metacharacters can't pass through, output is length-capped. And notice the triage count — that's the number of independent dismissals backing this up. This is what clears the evidence gate: high confidence *and* real triage support.

> There's also a source candidate here — `LegacyRequest.getParam`. This is the interesting one. It's a wrapper around `getParameter` that the scanner doesn't recognize as a source *at all* right now — which means whatever SQL injection flows through it is currently completely invisible.

**[SCREEN: select the candidates, submit "confirm"]**

> I'll approve both and confirm.

**[SCREEN: the results/diff screen]**

> And here's the payoff. Seven findings just got downgraded to Not Exploitable — those are the real false positives, confirmed safe, and now permanently marked that way. And this one — a brand new CRITICAL finding just appeared. That's the SQL injection that was flowing through `LegacyRequest.getParam` the whole time, invisible until the scanner learned that this wrapper is a real taint source. That's the core value proposition in one screen: fewer false positives *and* a previously-hidden vulnerability surfaced, from the exact same learning step.

**[SCREEN: click into the ledger]**

> Every one of those overrides is recorded here, append-only, with a timestamp, the confidence it was approved at, and the triage support behind it. And if a learning turns out to be wrong — say, a reviewer later confirms a real exploit that passed through something we trusted as a sanitizer — one click rolls it back, and the finding goes right back to its pre-override state.

---

## 7:30 – 8:45 — Why this is actually safe: the verifier and feedback calibration

**[SCREEN: optional — open truesignal/verifier.py in an editor, or just narrate]**

> I want to spend a minute on the mechanics, because "AI-assisted" tools live or die on whether the safety claims are real or just marketing.

> The verifier has different rules per role, and they're deliberately asymmetric. A sanitizer gets the *strictest* treatment, because a wrong sanitizer manufactures a real false negative — you'd be telling the scanner to ignore a genuine vulnerability. So a sanitizer only auto-approves with high confidence *and* at least three independent triage decisions backing it. Code evidence alone, no matter how confident the model is, goes to human review. A source or sink needs the code indexer to *independently* confirm the behavior — the LLM's opinion alone is never enough.

**[SCREEN: settings page for a project — show the calibration chart]**

> There's also a feedback loop, and I want to be precise about what this is *not*. It's not reinforcement learning. There's no reward model, no gradient updates, no policy network. It's bounded counters: an approval nudges a signature's effective confidence up by a tiny amount, a rejection nudges it down more, a rollback — the worst outcome, since it means a bad override was live in production — nudges it down the most. The total adjustment is capped at plus or minus ten percent, and it's fully visible: every verdict shows the raw confidence, the calibration adjustment, and the effective confidence that was actually compared against the threshold. Delete one file and it resets to zero. Nothing about this is a black box.

---

## 8:45 – 9:45 — Cross-project pattern library

**[SCREEN: navigate to the toolbox-demo or cmdi-demo project overview page]**

> Here's a feature that comes almost for free once you have real applied overrides: cross-project pattern matching. `InputCleaner.sanitize` in WebShop is now a *proven, applied* sanitizer. This is a completely different project — command injection, not SQL injection — and it has its own hand-written cleaning function that nobody has classified yet.

**[SCREEN: point to the "Cross-project patterns" card]**

> The system compared this unclassified function's code shape — not just its name — against every proven pattern in every other project, using plain string similarity, no embeddings, no extra LLM call. And it found a fifty-four percent match. Same "keep only allow-listed characters" shape, different project. One click sends this straight into the training-curation queue as a suggested sanitizer. It's advisory only — it never applies anything by itself — but it means the second time your team solves the same kind of problem, the system already has a hunch.

---

## 9:45 – 10:45 — The admin dashboard

**[SCREEN: navigate to /activity — the Activity page]**

> This page is admin-only — I'll show why that matters in a second. It's a proper filterable dashboard: date range, reviewer, and a minimum-triage-count threshold, and every tile on the page — the KPIs, the bar chart of decisions per reviewer, the resolution breakdown, the daily volume trend, the leaderboard — all react to the same filter set together, not independently.

**[SCREEN: set a filter, e.g. pick a reviewer from the dropdown, show the whole page update]**

> And this leaderboard is doing something most dashboards get wrong — when reviewers are genuinely tied, it says so, instead of arbitrarily crowning whoever happens to sort first.

**[SCREEN: log out, log in as appsec, try to visit /activity]**

> And here's why the role boundary is real, not decorative. If I log in as the AppSec account and try to hit this same URL directly... 403. This isn't just a hidden nav link — it's enforced on every route that mutates state: uploading a project, applying overrides, rolling back the ledger, changing gate thresholds. AppSec can view settings — read-only, exactly as advertised on the login screen — but can't submit a change. That boundary used to not be enforced at all; it is now, and it's tested.

---

## 10:45 – 12:00 — The human-verified fine-tuning loop

**[SCREEN: log back in as admin, navigate to /training]**

> This is the piece that closes the loop for teams running a local model instead of a cloud API. Every time a reviewer rejects a proposed classification, rolls back an override, or confirms a finding that a "sanitizer" claimed was safe, that's a real signal that the model got something wrong — and it becomes a *pending* correction here.

**[SCREEN: show a pending example, or the manual-add form]**

> Nothing here reaches a training set automatically. An admin has to review each one — approve it, optionally edit the corrected role first, or discard it. Only approved rows ever get exported. It's the same two-gate philosophy as the main pipeline: a signal from the field is a candidate, not a fact, until a human signs off.

> Once you've curated enough examples, `truesignal export-training-data` writes them out as a fine-tune JSONL, and there's a companion script that walks through LoRA-finetuning a local model and registering it back with Ollama — so the loop is genuinely closed: production corrections train the next version of the model that made the mistake.

---

## 12:00 – 13:00 — Under the hood: CLI, modes, and production-readiness

**[SCREEN: switch to a terminal]**

> Everything I just showed you in the browser is also a CLI, and it's the exact same pipeline code underneath — not a separate reimplementation.

```bash
truesignal ingest  --project webshop
truesignal learn   --project webshop
truesignal analyze --project webshop --yes
truesignal ledger
truesignal feedback
```

> It defaults to mock mode — deterministic fixtures standing in for both the LLM and Checkmarx One, so this entire demo runs offline with zero API keys. Flip three environment variables and it talks to a real Checkmarx One tenant and Anthropic, OpenAI, or a local Ollama model instead — same code path, same safety gate.

> A few things I want to call out that don't show up in a feature list but matter for whether this is actually production-safe: every piece of state — the ledger, feedback history, triage decisions — is written atomically now, temp-file-then-rename, so a crash mid-write can't corrupt this project's entire audit trail. Applying a batch of overrides against a live tenant ledgers each one immediately after it succeeds, not after the whole batch, so a failure partway through never leaves an override live on the real system with no local record of it. And the live Checkmarx client retries transient network failures with backoff instead of taking down an entire analysis run over one dropped connection.

**[SCREEN: run `python -m pytest -q`]**

> 46 tests, covering the evidence gate, the feedback bounds, idempotency, the atomic-write guarantees, and the retry logic — all passing.

---

## 13:00 – 13:30 — Close

**[SCREEN: back to the dashboard]**

> So, to sum it up: TrueSignal turns your team's existing triage work into permanent scanner intelligence. Every false positive your team dismisses once, it never has to dismiss again. Every hidden vulnerability behind an unrecognized wrapper function gets a chance to surface. And every single step of that — the classification, the calibration, the fine-tuning — passes through a fixed, explainable, human-reviewable gate before it can touch anything real. Nothing here is a black box, and nothing here is applied on the AI's word alone.

> Thanks for watching.

---

## Cutting it down (if you need shorter)

- **To ~8 minutes:** drop the "Under the hood" CLI section and the fine-tuning loop section entirely; compress the WebShop walkthrough to skip the individual audit screen and go straight to bulk-audit → analyze → diff.
- **To ~5–6 minutes:** keep only 0:00–7:30 (problem → core workflow) and the close. Cut verifier internals, pattern library, admin dashboard, training loop, and CLI — mention them in one sentence each ("there's also cross-project pattern matching, an admin analytics dashboard, and a fine-tuning loop, happy to go deeper in Q&A") instead of demoing them.

## If judges ask hard questions (have answers ready)

- **"What stops the LLM from just being wrong confidently?"** → The evidence gate doesn't trust confidence alone; sanitizers need independent triage support, sources/sinks need independent code-indexer confirmation. Point back to `verifier.py`.
- **"Is the fine-tuning loop actually RL?"** → No, explicitly not — bounded counters, capped at ±10%, fully visible, resettable. Point to `feedback.py`'s docstring.
- **"What happens if this crashes mid-write?"** → Atomic writes via temp-file-then-rename; show `jsonstore.py` if asked.
- **"What if Checkmarx times out applying 10 overrides?"** → Per-override ledgering, not batch-then-ledger; the ledger never claims more than what actually succeeded.
- **"Does this scale past a demo repo?"** → Be honest: the indexer is regex-based, not a full AST parser — that's the known limitation, tree-sitter is the stated upgrade path.
