"""TrueSignal Web UI.

An optional Flask front end over the same pipeline the CLI uses
(candidate_selector, llm_classifier, verifier, override_generator,
pipeline). It adds the one piece the CLI demo doesn't need: a way to get
SAST findings for a project that has no real Checkmarx scan behind it yet
(scanner.py), plus screens to upload a project, audit/triage its findings,
and watch false positives get downgraded and hidden findings surface after
learning.

Requires Flask (`pip install flask`) — not a dependency of the core
package, so `truesignal.cli` and the test suite stay stdlib-only.
"""
