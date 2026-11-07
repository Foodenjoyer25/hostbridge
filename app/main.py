"""HostBridge - manage Nginx Proxy Manager hosts and AdGuard Home DNS rewrites together."""
import asyncio
import hashlib
import hmac
import re
import time
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .adguard import AdGuardClient
from .config import settings
from .errors import UpstreamError
from .npm import NPMClient

STATIC = Path(__file__).parent / "static"
DOMAIN_RE = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
COOKIE = "hostbridge_session"

app = FastAPI(title="HostBridge", docs_url="/api/docs", openapi_url="/api/openapi.json")
npm = NPMClient(settings.npm_url, settings.npm_email, settings.npm_password, settings.verify_tls)
adguards = [AdGuardClient(i, settings.verify_tls) for i in settings.adguard]


# --------------------------------------------------------------------------- auth
def _sign(exp: int) -> str:
    return hmac.new(settings.secret_key.encode(), str(exp).encode(), hashlib.sha256).hexdigest()


def _valid_session(token: str | None) -> bool:
    if not token or "." not in token:
        return False
    exp, sig = token.split(".", 1)
    return exp.isdigit() and int(exp) > time.time() and hmac.compare_digest(sig, _sign(int(exp)))


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if (
        settings.app_password
        and path.startswith("/api/")
        and path not in ("/api/login", "/api/session", "/api/health")
        and not _valid_session(request.cookies.get(COOKIE))
    ):
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    return await call_next(request)


class LoginIn(BaseModel):
    password: str


@app.post("/api/login")
async def login(body: LoginIn, response: Response):
    if not settings.app_password:
        return {"ok": True}
    if not hmac.compare_digest(body.password.encode(), settings.app_password.encode()):
        await asyncio.sleep(1)
        raise HTTPException(401, "Wrong password")
    exp = int(time.time()) + settings.session_hours * 3600
    response.set_cookie(
        COOKIE, f"{exp}.{_sign(exp)}", max_age=settings.session_hours * 3600,
        httponly=True, samesite="strict", secure=settings.secure_cookie,
    )
    return {"ok": True}


@app.post("/api/logout")
async def logout(response: Response):
    response.delete_cookie(COOKIE)
    return {"ok": True}


@app.get("/api/session")
async def session(request: Request):
    return {
        "auth_required": bool(settings.app_password),
        "authenticated": not settings.app_password or _valid_session(request.cookies.get(COOKIE)),
    }


@app.get("/api/health")
async def health():
    return {"ok": True}


@app.exception_handler(UpstreamError)
async def upstream_handler(_: Request, exc: UpstreamError):
    return JSONResponse({"detail": str(exc)}, status_code=502)


# --------------------------------------------------------------------------- helpers
def normalize_domain(raw: str) -> str:
    d = raw.strip().lower().rstrip(".")
    if settings.default_domain_suffix and "." not in d:
        d = f"{d}.{settings.default_domain_suffix}"
    if not DOMAIN_RE.match(d):
        raise ValueError(f"Invalid domain: {raw!r}")
    return d


def wildcard_match(pattern: str, domain: str) -> bool:
    return pattern.startswith("*.") and domain.endswith(pattern[1:]) and domain != pattern[2:]


async def gather_rewrites() -> list[dict]:
    """Rewrites for every AdGuard instance; failures are reported, not raised."""
    results = await asyncio.gather(*(a.list_rewrites() for a in adguards), return_exceptions=True)
    out = []
    for a, res in zip(adguards, results):
        if isinstance(res, Exception):
            out.append({"name": a.name, "ok": False, "error": str(res), "rewrites": []})
        else:
            out.append({"name": a.name, "ok": True, "error": None, "rewrites": res})
    return out


def dns_status(domain: str, instances: list[dict]) -> list[dict]:
    status = []
    for inst in instances:
        exact = [r["answer"] for r in inst["rewrites"] if r["domain"].lower() == domain]
        wild = next((r for r in inst["rewrites"] if wildcard_match(r["domain"].lower(), domain)), None)
        status.append({
            "instance": inst["name"],
            "ok": inst["ok"],
            "answers": exact,
            "wildcard": {"domain": wild["domain"], "answer": wild["answer"]} if wild and not exact else None,
        })
    return status


async def ensure_dns(domains: list[str], answer: str) -> None:
    for a in adguards:
        for d in domains:
            await a.ensure_rewrite(d, answer)


async def remove_dns(domains: list[str], only_answer: str | None = None) -> None:
    for a in adguards:
        for d in domains:
            await a.remove_domain(d, only_answer)


async def preflight_dns() -> None:
    await asyncio.gather(*(a.list_rewrites() for a in adguards))


# --------------------------------------------------------------------------- models
class HostIn(BaseModel):
    domains: list[str] = Field(min_length=1)
    forward_scheme: Literal["http", "https"] = "http"
    forward_host: str = Field(min_length=1)
    forward_port: int = Field(ge=1, le=65535)
    certificate_id: int | Literal["new"] = 0
    ssl_forced: bool = False
    http2_support: bool = False
    hsts_enabled: bool = False
    hsts_subdomains: bool = False
    block_exploits: bool = True
    caching_enabled: bool = False
    allow_websocket_upgrade: bool = True
    access_list_id: int = 0
    advanced_config: str = ""
    manage_dns: bool = True
    dns_answer: str | None = None
    letsencrypt_email: str | None = None

    @field_validator("domains")
    @classmethod
    def _domains(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for d in v:
            if d.strip():
                n = normalize_domain(d)
                if n not in out:
                    out.append(n)
        if not out:
            raise ValueError("At least one domain is required")
        return out

    @field_validator("forward_host")
    @classmethod
    def _fh(cls, v: str) -> str:
        return v.strip()

    def answer(self) -> str:
        ans = (self.dns_answer or settings.default_dns_answer).strip()
        if self.manage_dns and not ans:
            raise HTTPException(400, "A DNS answer (IP) is required - set one or configure DEFAULT_DNS_ANSWER")
        return ans

    def npm_payload(self, existing: dict | None = None) -> dict:
        meta = dict((existing or {}).get("meta") or {})
        meta.setdefault("letsencrypt_agree", False)
        meta.setdefault("dns_challenge", False)
        if self.certificate_id == "new":
            email = self.letsencrypt_email or settings.letsencrypt_email
            if not email:
                raise HTTPException(400, "A Let's Encrypt email is required to request a new certificate")
            meta.update(letsencrypt_email=email, letsencrypt_agree=True, dns_challenge=False)
        meta.pop("nginx_online", None)
        meta.pop("nginx_err", None)
        return {
            "domain_names": self.domains,
            "forward_scheme": self.forward_scheme,
            "forward_host": self.forward_host,
            "forward_port": self.forward_port,
            "certificate_id": self.certificate_id,
            "ssl_forced": self.ssl_forced,
            "http2_support": self.http2_support,
            "hsts_enabled": self.hsts_enabled,
            "hsts_subdomains": self.hsts_subdomains,
            "block_exploits": self.block_exploits,
            "caching_enabled": self.caching_enabled,
            "allow_websocket_upgrade": self.allow_websocket_upgrade,
            "access_list_id": self.access_list_id,
            "advanced_config": self.advanced_config,
            "meta": meta,
            "locations": (existing or {}).get("locations") or [],
        }


class DnsIn(BaseModel):
    domain: str
    answer: str | None = None

    @field_validator("domain")
    @classmethod
    def _d(cls, v: str) -> str:
        return normalize_domain(v)


# --------------------------------------------------------------------------- routes
@app.get("/api/config")
async def get_config():
    return {
        "npm_url": settings.npm_url,
        "adguard": [{"name": a.name, "url": a.inst.url} for a in adguards],
        "default_dns_answer": settings.default_dns_answer,
        "default_domain_suffix": settings.default_domain_suffix,
        "letsencrypt_email": settings.letsencrypt_email,
    }


@app.get("/api/status")
async def get_status():
    async def check(coro):
        try:
            await coro
            return {"ok": True, "error": None}
        except UpstreamError as e:
            return {"ok": False, "error": str(e)}

    npm_res, *ag_res = await asyncio.gather(check(npm.list_certificates()), *(check(a.status()) for a in adguards))
    return {
        "npm": {"url": settings.npm_url, **npm_res},
        "adguard": [{"name": a.name, "url": a.inst.url, **r} for a, r in zip(adguards, ag_res)],
    }


@app.get("/api/hosts")
async def list_hosts():
    hosts, instances = await asyncio.gather(npm.list_proxy_hosts(), gather_rewrites())
    proxied: set[str] = set()
    rows = []
    for h in hosts:
        domains = [d.lower() for d in h.get("domain_names", [])]
        proxied.update(domains)
        cert = h.get("certificate") or {}
        meta = h.get("meta") or {}
        rows.append({
            "id": h["id"],
            "enabled": bool(h.get("enabled", True)),
            "online": meta.get("nginx_online", True),
            "error": meta.get("nginx_err"),
            "domains": [{"name": d, "dns": dns_status(d, instances)} for d in domains],
            "forward_scheme": h.get("forward_scheme"),
            "forward_host": h.get("forward_host"),
            "forward_port": h.get("forward_port"),
            "certificate_id": h.get("certificate_id") or 0,
            "certificate_name": cert.get("nice_name") if isinstance(cert, dict) else None,
            "ssl_forced": bool(h.get("ssl_forced")),
            "http2_support": bool(h.get("http2_support")),
            "hsts_enabled": bool(h.get("hsts_enabled")),
            "hsts_subdomains": bool(h.get("hsts_subdomains")),
            "block_exploits": bool(h.get("block_exploits")),
            "caching_enabled": bool(h.get("caching_enabled")),
            "allow_websocket_upgrade": bool(h.get("allow_websocket_upgrade")),
            "access_list_id": h.get("access_list_id") or 0,
            "advanced_config": h.get("advanced_config") or "",
            "has_locations": bool(h.get("locations")),
        })
    # DNS rewrites that have no matching proxy host
    orphans: dict[str, dict] = {}
    for inst in instances:
        for r in inst["rewrites"]:
            d = r["domain"].lower()
            if d not in proxied and d not in orphans:
                orphans[d] = {"domain": d, "dns": dns_status(d, instances), "wildcard": d.startswith("*.")}
    return {
        "hosts": sorted(rows, key=lambda r: r["domains"][0]["name"] if r["domains"] else ""),
        "dns_only": sorted(orphans.values(), key=lambda o: o["domain"]),
        "instances": [{"name": i["name"], "ok": i["ok"], "error": i["error"]} for i in instances],
    }


@app.get("/api/certificates")
async def certificates():
    return [
        {"id": c["id"], "name": c.get("nice_name") or ", ".join(c.get("domain_names", [])),
         "domains": c.get("domain_names", []), "provider": c.get("provider"), "expires_on": c.get("expires_on")}
        for c in await npm.list_certificates()
    ]


@app.get("/api/access-lists")
async def access_lists():
    return [{"id": a["id"], "name": a.get("name")} for a in await npm.list_access_lists()]


@app.post("/api/hosts", status_code=201)
async def create_host(body: HostIn):
    answer = body.answer()
    payload = body.npm_payload()
    if body.manage_dns:
        await preflight_dns()  # fail fast before touching NPM
    created = await npm.create_proxy_host(payload)
    if body.manage_dns:
        try:
            await ensure_dns(body.domains, answer)
        except UpstreamError as e:
            try:
                await npm.delete_proxy_host(created["id"])
            except UpstreamError:
                pass
            raise HTTPException(502, f"DNS rewrite failed, proxy host rolled back. {e}")
    return {"id": created["id"], "domains": body.domains}


@app.put("/api/hosts/{host_id}")
async def update_host(host_id: int, body: HostIn):
    answer = body.answer()
    existing = await npm.get_proxy_host(host_id)
    old_domains = [d.lower() for d in existing.get("domain_names", [])]
    if body.manage_dns:
        await preflight_dns()
    await npm.update_proxy_host(host_id, body.npm_payload(existing))
    if body.manage_dns:
        removed = [d for d in old_domains if d not in body.domains]
        await remove_dns(removed)
        await ensure_dns(body.domains, answer)
    return {"id": host_id, "domains": body.domains}


@app.delete("/api/hosts/{host_id}")
async def delete_host(host_id: int, dns: bool = True):
    existing = await npm.get_proxy_host(host_id)
    await npm.delete_proxy_host(host_id)
    if dns:
        await remove_dns([d.lower() for d in existing.get("domain_names", [])])
    return {"ok": True}


@app.post("/api/hosts/{host_id}/enabled")
async def toggle_host(host_id: int, enabled: bool):
    await npm.set_enabled(host_id, enabled)
    return {"ok": True}


@app.post("/api/dns")
async def ensure_dns_route(body: DnsIn):
    """Create / fix a rewrite on every AdGuard instance."""
    answer = (body.answer or settings.default_dns_answer).strip()
    if not answer:
        raise HTTPException(400, "No DNS answer given and DEFAULT_DNS_ANSWER is not set")
    await ensure_dns([body.domain], answer)
    return {"ok": True}


@app.post("/api/dns/delete")
async def delete_dns_route(body: DnsIn):
    await remove_dns([body.domain], body.answer)
    return {"ok": True}


# --------------------------------------------------------------------------- UI
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/{_path:path}", include_in_schema=False)
async def index(_path: str):
    if _path.startswith("api/"):
        raise HTTPException(404)
    return FileResponse(STATIC / "index.html")
