"""Regenerate fixtures/baseline_scan.json and fixtures/triage_history.json (seeded)."""
import json
import random
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "fixtures"
OUT.mkdir(exist_ok=True)
SRC = "src/main/java/com/webshop"
random.seed(42)

fp_flows = [
    ("OrderServlet.searchByProduct",  "product", "findByProduct", 28, "sanitize"),
    ("OrderServlet.searchByEmail",    "email",   "findByEmail",   34, "sanitize"),
    ("OrderServlet.searchSanitizedRef","ref",    "query",         40, "sanitize"),
    ("ProfileServlet.ordersForUser",  "user",    "query",         17, "sanitize"),
    ("ProfileServlet.ordersForAccount","account","query",         23, "sanitizeNumeric"),
    ("ProfileServlet.searchHistory",  "q",       "findByProduct", 29, "sanitize"),
    ("ProfileServlet.contactLookup",  "mail",    "findByEmail",   35, "sanitize"),
]
findings = []
for i, (method, param, sink, line, san) in enumerate(fp_flows, start=1):
    cls = method.split(".")[0]
    findings.append({
        "id": f"CX-{1000+i}", "queryName": "SQL_Injection", "severity": "HIGH",
        "state": "TO_VERIFY",
        "sourceFile": f"{SRC}/web/{cls}.java", "sourceLine": line,
        "sinkFile": f"{SRC}/dao/OrderDao.java",
        "taintPath": [
            {"node": f"HttpServletRequest.getParameter(\"{param}\")",
             "file": f"{SRC}/web/{cls}.java", "line": line, "role": "source"},
            {"node": f"InputCleaner.{san}()",
             "file": f"{SRC}/security/InputCleaner.java",
             "line": 21 if san == "sanitize" else 38, "role": "passthrough"},
            {"node": f"OrderDao.{sink}()", "file": f"{SRC}/dao/OrderDao.java",
             "line": 26, "role": "sink"},
        ],
    })
findings.append({
    "id": "CX-1008", "queryName": "SQL_Injection", "severity": "HIGH",
    "state": "TO_VERIFY",
    "sourceFile": f"{SRC}/web/OrderServlet.java", "sourceLine": 62,
    "sinkFile": f"{SRC}/dao/OrderDao.java",
    "taintPath": [
        {"node": "HttpServletRequest.getParameter(\"ref\")",
         "file": f"{SRC}/web/OrderServlet.java", "line": 62, "role": "source"},
        {"node": "OrderDao.query()", "file": f"{SRC}/dao/OrderDao.java",
         "line": 26, "role": "sink"},
    ],
})
(OUT / "baseline_scan.json").write_text(json.dumps(
    {"projectId": "webshop", "scanId": "scan-baseline-001", "results": findings}, indent=2))

reasons = [
    "goes through InputCleaner, safe",
    "sanitized by InputCleaner.sanitize before the query",
    "not exploitable - allow-list sanitizer strips quotes",
    "same as previous sprints: InputCleaner path, dismissing",
    "verified safe, custom sanitizer neutralizes SQLi chars",
    "FP - InputCleaner.sanitize on the taint path",
]
users = ["dana.k", "yossi.b", "maria.p", "tomer.l"]
history, n = [], 0
for scan in range(1, 8):
    for i, (method, param, sink, line, san) in enumerate(fp_flows, start=1):
        if n >= 41:
            break
        n += 1
        history.append({
            "findingId": f"CX-{1000+i}", "scanId": f"scan-past-{scan:03d}",
            "action": "DISMISS", "resolution": "NOT_EXPLOITABLE",
            "comment": random.choice(reasons), "user": random.choice(users),
            "sanitizerOnPath": f"InputCleaner.{san}",
            "date": f"2026-0{min(scan,7)}-{random.randint(1,28):02d}",
        })
for scan in (6, 7):
    history.append({
        "findingId": "CX-1008", "scanId": f"scan-past-{scan:03d}",
        "action": "CONFIRM", "resolution": "CONFIRMED",
        "comment": "raw parameter straight into query - real issue",
        "user": "dana.k", "sanitizerOnPath": None, "date": f"2026-0{scan}-15",
    })
(OUT / "triage_history.json").write_text(json.dumps(
    {"projectId": "webshop", "decisions": history}, indent=2))
print(f"fixtures written: {len(findings)} findings, {len(history)} decisions ({n} dismissals)")
