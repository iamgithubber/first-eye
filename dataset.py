#!/usr/bin/env python3
"""
build_xss_dataset.py

Creates xss_dataset.jsonl (sample high-quality dataset for XSS detection)
and validates each record against a JSON schema.
"""
import json, uuid, datetime, sys
from pathlib import Path
from jsonschema import validate, ValidationError

OUT = Path("xss_dataset.jsonl")
SCHEMA_PATH = Path("xss_schema.json")

# JSON Schema used for validation (kept compact but strict)
XSS_SCHEMA = {
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "artifact_id": {"type": "string"},
    "source": {"type": "string"},
    "vuln_type": {"type": "string", "enum": ["reflected", "stored", "dom", "none"]},
    "label": {"type": "boolean"},
    "url": {"type": "string"},
    "method": {"type": "string"},
    "params": {"type": "object"},
    "request_headers": {"type": "object"},
    "response_headers": {"type": "object"},
    "response_body_snippet": {"type": "string"},
    "evidence": {
      "anyOf": [
        {"type": "null"},
        {
          "type": "object",
          "properties": {
            "payload": {"type": "string"},
            "where": {"type": "string"},
            "snippet": {"type": "string"}
          },
          "required": ["payload","where","snippet"]
        }
      ]
    },
    "confidence": {"type":"number","minimum":0.0,"maximum":1.0},
    "created_at": {"type":"string"},
    "notes": {"type":"string"}
  },
  "required": ["artifact_id","source","vuln_type","label","url","method","params","response_body_snippet","evidence","confidence","created_at"]
}

# Example dataset: mix of positives and negatives
# Positive samples use simple, canonical payloads in evidence (safe / canonical examples)
# Note: Evidence snippets are redacted to short snippets and do not contain secrets.
SAMPLES = [
  # Reflected XSS (GET param reflected unescaped)
  {
    "source": "synthetic",
    "vuln_type": "reflected",
    "label": True,
    "url": "https://example.test/search?q=<script>alert(1)</script>",
    "method": "GET",
    "params": {"q":"<script>alert(1)</script>"},
    "request_headers": {"User-Agent":"curl/7.x"},
    "response_headers": {"Content-Type":"text/html; charset=utf-8"},
    "response_body_snippet": "<div>Search results for: <script>alert(1)</script></div>",
    "evidence": {"payload":"<script>alert(1)</script>","where":"response_body","snippet":"<script>alert(1)</script>"},
    "confidence": 0.98,
    "notes":"Canonical reflected XSS example"
  },
  # Reflected but HTML-escaped -> negative
  {
    "source": "synthetic",
    "vuln_type": "none",
    "label": False,
    "url": "https://example.test/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "method": "GET",
    "params": {"q":"%3Cscript%3Ealert(1)%3C%2Fscript%3E"},
    "request_headers": {"User-Agent":"curl/7.x"},
    "response_headers": {"Content-Type":"text/html; charset=utf-8"},
    "response_body_snippet": "<div>Search results for: &lt;script&gt;alert(1)&lt;/script&gt;</div>",
    "evidence": None,
    "confidence": 0.95,
    "notes":"Escaped payload; not vulnerable"
  },
  # DOM XSS: payload reflected in JS context (document.write)
  {
    "source": "juice-shop",
    "vuln_type": "dom",
    "label": True,
    "url": "https://juice-shop.example/#/search?q=\"><script>alert(1)</script>",
    "method": "GET",
    "params": {"q":"\"><script>alert(1)</script>"},
    "request_headers": {"Referer":"https://juice-shop.example/"},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "document.write('Search: ' + location.hash.substring(9));",
    "evidence": {"payload":"\"><script>alert(1)</script>","where":"dom","snippet":"document.write('Search: ' + location.hash.substring(9))"},
    "confidence": 0.9,
    "notes":"DOM sink in document.write"
  },
  # Stored XSS: stored comment shows up in subsequent page
  {
    "source": "synthetic",
    "vuln_type": "stored",
    "label": True,
    "url": "https://blog.example/post/42/comments",
    "method": "POST",
    "params": {"comment":"<script>console.log('poc')</script>"},
    "request_headers": {"Content-Type":"application/x-www-form-urlencoded"},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "<div class=\"comment\">&lt;script&gt;console.log('poc')&lt;/script&gt;</div>",
    "evidence": {"payload":"<script>console.log('poc')</script>","where":"stored","snippet":"&lt;script&gt;console.log('poc')&lt;/script&gt;"},
    "confidence": 0.92,
    "notes":"Stored XSS present in comments (example kept redacted)"
  },
  # Non-XSS: parameter echoed inside attribute but properly sanitized
  {
    "source": "synthetic",
    "vuln_type": "none",
    "label": False,
    "url": "https://app.example/profile?name=Alice%20%3Cimg%20src=x%20onerror=alert(1)%3E",
    "method": "GET",
    "params": {"name":"Alice <img src=x onerror=alert(1)>"},
    "request_headers": {"User-Agent":"Mozilla/5.0"},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "<input value=\"Alice &lt;img src=x onerror=alert(1)&gt;\"/>",
    "evidence": None,
    "confidence": 0.95,
    "notes":"Proper attribute escaping"
  },
  # Reflected XSS with URL-encoded payload (positive)
  {
    "source": "synthetic",
    "vuln_type": "reflected",
    "label": True,
    "url": "https://example.test/echo?msg=%3Cscript%3Ealert('x')%3C%2Fscript%3E",
    "method": "GET",
    "params": {"msg":"%3Cscript%3Ealert('x')%3C%2Fscript%3E"},
    "request_headers": {"Accept":"text/html"},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "<span id=\"echo\">%3Cscript%3Ealert('x')%3C%2Fscript%3E</span>",
    "evidence": {"payload":"%3Cscript%3Ealert('x')%3C%2Fscript%3E","where":"response_body","snippet":"%3Cscript%3Ealert('x')%3C%2Fscript%3E"},
    "confidence": 0.88,
    "notes":"Decoded reflect may occur on client-side; flagged for review"
  },
  # False positive like pattern in log text (negative)
  {
    "source": "public-report",
    "vuln_type": "none",
    "label": False,
    "url": "https://status.example/logs?entry=123",
    "method": "GET",
    "params": {"entry":"123"},
    "request_headers": {"User-Agent":"monitor"},
    "response_headers": {"Content-Type":"text/plain"},
    "response_body_snippet": "Error: script failed at <script> tag in parser",
    "evidence": None,
    "confidence": 0.9,
    "notes":"Log contains literal string '<script>' but not executed"
  },
  # reflected XSS inside <title> tag (positive)
  {
    "source": "synthetic",
    "vuln_type": "reflected",
    "label": True,
    "url": "https://example.test/page?title=<script>alert(1)</script>",
    "method": "GET",
    "params": {"title":"<script>alert(1)</script>"},
    "request_headers": {"User-Agent":"curl/7.x"},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "<title><script>alert(1)</script></title>",
    "evidence": {"payload":"<script>alert(1)</script>","where":"response_body","snippet":"<title><script>alert(1)</script></title>"},
    "confidence": 0.98,
    "notes":"Title tag reflected unsafely"
  },
  # reflected but attribute context encoded (negative)
  {
    "source": "synthetic",
    "vuln_type": "none",
    "label": False,
    "url": "https://example.test/page?title=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "method": "GET",
    "params": {"title":"\">&lt;script&gt;alert(1)&lt;/script&gt;"},
    "request_headers": {"User-Agent":"curl/7.x"},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "<h1 title=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\">Header</h1>",
    "evidence": None,
    "confidence": 0.96,
    "notes":"Properly quoted attribute"
  },
  # reflected XSS via JSON endpoint reflecting parameter into JS variable (positive)
  {
    "source": "synthetic",
    "vuln_type": "dom",
    "label": True,
    "url": "https://api.example/ui-config?name=<script>alert(1)</script>",
    "method": "GET",
    "params": {"name":"<script>alert(1)</script>"},
    "request_headers": {"Accept":"application/json"},
    "response_headers": {"Content-Type":"application/json"},
    "response_body_snippet": "\"greeting\":\"<script>alert(1)</script>\"",
    "evidence": {"payload":"<script>alert(1)</script>","where":"response_body","snippet":"\"greeting\":\"<script>alert(1)</script>\""},
    "confidence": 0.9,
    "notes":"Client-side JS may eval this JSON value unsafely"
  },
  # benign JSON API returning escaped strings (negative)
  {
    "source": "public-report",
    "vuln_type": "none",
    "label": False,
    "url": "https://api.example/users?q=%3Cscript%3E",
    "method": "GET",
    "params": {"q":"%3Cscript%3E"},
    "request_headers": {"Accept":"application/json"},
    "response_headers": {"Content-Type":"application/json"},
    "response_body_snippet": "{\"result\":\"&lt;script&gt;\"}",
    "evidence": None,
    "confidence": 0.95,
    "notes":"JSON value safely encoded"
  },
  # reflected XSS via location.hash used unsafely (DOM) - positive
  {
    "source": "synthetic",
    "vuln_type": "dom",
    "label": True,
    "url": "https://app.example/#/item/<script>1</script>",
    "method": "GET",
    "params": {},
    "request_headers": {"User-Agent":"Mozilla/5.0"},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "var id = location.hash.substring(7); document.getElementById('out').innerHTML = id;",
    "evidence": {"payload":"<script>1</script>","where":"dom","snippet":"document.getElementById('out').innerHTML = id;"},
    "confidence": 0.87,
    "notes":"Client-side innerHTML sink"
  },
  # reflected safe because inserted as textContent (negative)
  {
    "source": "synthetic",
    "vuln_type": "none",
    "label": False,
    "url": "https://app.example/#/item/safe",
    "method": "GET",
    "params": {},
    "request_headers": {"User-Agent":"Mozilla/5.0"},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "document.getElementById('out').textContent = id;",
    "evidence": None,
    "confidence": 0.95,
    "notes":"textContent used; safe"
  },
  # Reflected XSS through reflected HTTP header into page (positive)
  {
    "source": "public-report",
    "vuln_type": "reflected",
    "label": True,
    "url": "https://example.test/welcome",
    "method": "GET",
    "params": {},
    "request_headers": {"X-User":"<script>alert(1)</script>"},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "<div>Welcome <script>alert(1)</script></div>",
    "evidence": {"payload":"<script>alert(1)</script>","where":"response_body","snippet":"<div>Welcome <script>alert(1)</script></div>"},
    "confidence": 0.9,
    "notes":"Header reflected unsafely"
  },
  # Negative: parameter only appears in comment or inside <pre> (safe)
  {
    "source": "synthetic",
    "vuln_type": "none",
    "label": False,
    "url": "https://example.test/debug?msg=<script>alert(1)</script>",
    "method": "GET",
    "params": {"msg":"<script>alert(1)</script>"},
    "request_headers": {},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "<!-- user input: <script>alert(1)</script> -->",
    "evidence": None,
    "confidence": 0.96,
    "notes":"Appears only in HTML comment"
  },
  # reflected but sanitized via CSP preventing inline scripts (negative auto, but mark low confidence)
  {
    "source": "public-report",
    "vuln_type": "none",
    "label": False,
    "url": "https://example.csp/page?x=<script>alert(1)</script>",
    "method": "GET",
    "params": {"x":"<script>alert(1)</script>"},
    "request_headers": {},
    "response_headers": {"Content-Security-Policy":"default-src 'self'; script-src 'self'"},
    "response_body_snippet": "<div>Value: <script>alert(1)</script></div>",
    "evidence": None,
    "confidence": 0.7,
    "notes":"CSP prevents inline script execution; include in dataset for nuance"
  },
  # stored XSS where stored value is HTML-encoded but later rendered raw in admin UI (positive)
  {
    "source": "hackerone",
    "vuln_type": "stored",
    "label": True,
    "url": "https://example.app/admin/comments",
    "method": "GET",
    "params": {},
    "request_headers": {"Cookie":"session=..."},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "<td>Comment: <script>alert('admin')</script></td>",
    "evidence": {"payload":"<script>alert('admin')</script>","where":"stored","snippet":"<td>Comment: <script>alert('admin')</script></td>"},
    "confidence": 0.96,
    "notes":"Stored XSS surfaced in admin view"
  },
  # false positive: stored text displayed inside code block <pre> (negative)
  {
    "source": "synthetic",
    "vuln_type": "none",
    "label": False,
    "url": "https://example.app/snippets?id=5",
    "method": "GET",
    "params": {"id":"5"},
    "request_headers": {},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "<pre>&lt;script&gt;not executed&lt;/script&gt;</pre>",
    "evidence": None,
    "confidence": 0.97,
    "notes":"Safe because inside <pre> escaped"
  },
  # DOM XSS: innerHTML used after JSON parse (positive)
  {
    "source": "synthetic",
    "vuln_type": "dom",
    "label": True,
    "url": "https://app.example/page#comment=<img src=x onerror=alert(1)>",
    "method": "GET",
    "params": {},
    "request_headers": {},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "var c = JSON.parse(decodeURIComponent(location.hash.substring(9))); container.innerHTML = c.text;",
    "evidence": {"payload":"<img src=x onerror=alert(1)>","where":"dom","snippet":"container.innerHTML = c.text;"},
    "confidence": 0.9,
    "notes":"DOM innerHTML sink"
  },
  # Negative: server returns sanitized text with entity encoding (common)
  {
    "source": "synthetic",
    "vuln_type": "none",
    "label": False,
    "url": "https://example.org/comment?c=<img%20src=x%20onerror=alert(1)>",
    "method": "GET",
    "params": {"c":"<img src=x onerror=alert(1)>"},
    "request_headers": {},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "<div>Comment: &lt;img src=x onerror=alert(1)&gt;</div>",
    "evidence": None,
    "confidence": 0.95,
    "notes":"Escaped; safe"
  },
  # positive: reflected in JS template literal without sanitization (positive)
  {
    "source": "synthetic",
    "vuln_type": "reflected",
    "label": True,
    "url": "https://example.site/render?name=${alert(1)}",
    "method": "GET",
    "params": {"name":"${alert(1)}"},
    "request_headers": {},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "<script>var user = `${alert(1)}`;</script>",
    "evidence": {"payload":"${alert(1)}","where":"response_body","snippet":"var user = `${alert(1)}`;"},
    "confidence": 0.85,
    "notes":"Template literal injection"
  },
  # negative: presence of string 'alert(' in static JS file (not produced by input)
  {
    "source": "public-report",
    "vuln_type": "none",
    "label": False,
    "url": "https://cdn.example/static/app.js",
    "method": "GET",
    "params": {},
    "request_headers": {},
    "response_headers": {"Content-Type":"application/javascript"},
    "response_body_snippet": "function notify() { alert('hello'); }",
    "evidence": None,
    "confidence": 0.92,
    "notes":"Static JS contains alert but not from user input"
  },
  # positive: reflected inside onclick attribute unescaped (positive)
  {
    "source": "synthetic",
    "vuln_type": "reflected",
    "label": True,
    "url": "https://example.site/button?label=OK%22%20onclick%3Dalert(1)%20%3E",
    "method": "GET",
    "params": {"label":"OK\" onclick=alert(1) >"},
    "request_headers": {},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "<button onclick=alert(1) >OK</button>",
    "evidence": {"payload":"\" onclick=alert(1) >","where":"response_body","snippet":"<button onclick=alert(1) >OK</button>"},
    "confidence": 0.9,
    "notes":"Attribute injection leading to JS execution"
  },
  # negative: parameter reflected only in server-side log snippet (safe)
  {
    "source": "synthetic",
    "vuln_type": "none",
    "label": False,
    "url": "https://example.site/log?id=abc",
    "method": "GET",
    "params": {"id":"abc"},
    "request_headers": {},
    "response_headers": {"Content-Type":"text/plain"},
    "response_body_snippet": "Request processed: id=abc",
    "evidence": None,
    "confidence": 0.95,
    "notes":"Reflected only in plaintext logs"
  },
  # negative: input appears in stylesheet (safe)
  {
    "source": "synthetic",
    "vuln_type": "none",
    "label": False,
    "url": "https://theme.example/?color=%3Cscript%3E",
    "method": "GET",
    "params": {"color":"<script>"},
    "request_headers": {},
    "response_headers": {"Content-Type":"text/css"},
    "response_body_snippet": "body::after { content: \"&lt;script&gt;\"; }",
    "evidence": None,
    "confidence": 0.95,
    "notes":"Escaped in CSS content()"
  },
  # positive: reflected via filename parameter into <script src=> (positive)
  {
    "source": "exploit-db",
    "vuln_type": "reflected",
    "label": True,
    "url": "https://cdn.example/load?file=malicious.js",
    "method": "GET",
    "params": {"file":"malicious.js"},
    "request_headers": {},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "<script src=\"/uploads/malicious.js\"></script>",
    "evidence": {"payload":"malicious.js","where":"response_body","snippet":"<script src=\"/uploads/malicious.js\"></script>"},
    "confidence": 0.88,
    "notes":"User-controllable script src"
  },
  # negative: file parameter sanitized, only basename allowed
  {
    "source": "synthetic",
    "vuln_type": "none",
    "label": False,
    "url": "https://cdn.example/load?file=logo.png",
    "method": "GET",
    "params": {"file":"logo.png"},
    "request_headers": {},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "<script src=\"/assets/logo.png\"></script>",
    "evidence": None,
    "confidence": 0.95,
    "notes":"Controlled asset loading; benign"
  },
  # positive: reflected into SVG inline where scriptable (positive)
  {
    "source": "public-report",
    "vuln_type": "reflected",
    "label": True,
    "url": "https://svg.example/view?img=<svg%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E%3C%2Fsvg%3E",
    "method": "GET",
    "params": {"img":"<svg><script>alert(1)</script></svg>"},
    "request_headers": {},
    "response_headers": {"Content-Type":"image/svg+xml"},
    "response_body_snippet": "<svg><script>alert(1)</script></svg>",
    "evidence": {"payload":"<script>alert(1)</script>","where":"response_body","snippet":"<svg><script>alert(1)</script></svg>"},
    "confidence": 0.9,
    "notes":"SVG script execution sink"
  },
  # negative: parameter shows up in alt attribute (safe)
  {
    "source": "synthetic",
    "vuln_type": "none",
    "label": False,
    "url": "https://site.example/image?alt=<script>",
    "method": "GET",
    "params": {"alt":"<script>"},
    "request_headers": {},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "<img alt=\"&lt;script&gt;\" src=\"/img.png\"/>",
    "evidence": None,
    "confidence": 0.96,
    "notes":"Escaped alt attribute"
  },
  # positive: open redirect leading to JS URI (flag as relevant even though it's not XSS)
  {
    "source": "synthetic",
    "vuln_type": "none",
    "label": False,
    "url": "https://redirect.example/?to=javascript:alert(1)",
    "method": "GET",
    "params": {"to":"javascript:alert(1)"},
    "request_headers": {},
    "response_headers": {"Location":"javascript:alert(1)"},
    "response_body_snippet": "",
    "evidence": None,
    "confidence": 0.7,
    "notes":"Open redirect to javascript: URI (security issue but not classic XSS). Keep for nuance."
  },
  # positive: reflected after improper HTML attribute unquoting (positive)
  {
    "source": "synthetic",
    "vuln_type": "reflected",
    "label": True,
    "url": "https://example.test/button?lbl=OK%22%20onclick%3Dalert(1)%3E",
    "method": "GET",
    "params": {"lbl":"OK\" onclick=alert(1)>"},
    "request_headers": {},
    "response_headers": {"Content-Type":"text/html"},
    "response_body_snippet": "<button onclick=alert(1)>OK</button>",
    "evidence": {"payload":"\" onclick=alert(1)>","where":"response_body","snippet":"<button onclick=alert(1)>OK</button>"},
    "confidence": 0.9,
    "notes":"Attribute unquoting leading to execution"
  }
]

# Fill artifact ids and timestamps
def mk_record(base):
    r = dict(base)
    r["artifact_id"] = "xss-" + uuid.uuid4().hex[:8]
    r["created_at"] = datetime.datetime.utcnow().isoformat() + "Z"
    # ensure all required keys exist
    r.setdefault("method","GET")
    r.setdefault("request_headers",{})
    r.setdefault("response_headers",{})
    r.setdefault("params",{})
    r.setdefault("notes","")
    return r

def main():
    records = [mk_record(s) for s in SAMPLES]
    # write schema to file
    with open(SCHEMA_PATH, "w", encoding="utf-8") as fh:
        json.dump(XSS_SCHEMA, fh, indent=2)
    # validate & write JSONL
    errs = 0
    with open(OUT, "w", encoding="utf-8") as fh:
        for r in records:
            try:
                validate(instance=r, schema=XSS_SCHEMA)
            except ValidationError as e:
                print("Validation error for record:", r.get("artifact_id"), e, file=sys.stderr)
                errs += 1
                continue
            fh.write(json.dumps(r, ensure_ascii=False) + "\\n")
    print(f"Wrote {len(records)-errs} records to {OUT}. {errs} validation errors.")
    if errs:
        sys.exit(1)

if __name__ == "__main__":
    main()
