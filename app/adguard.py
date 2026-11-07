"""Minimal async client for the AdGuard Home DNS rewrite API."""
import ipaddress
from typing import Any

import httpx

from .config import AdGuardInstance
from .errors import UpstreamError


class AdGuardClient:
    def __init__(self, inst: AdGuardInstance, verify: bool = True):
        self.inst = inst
        self.verify = verify

    @property
    def name(self) -> str:
        return self.inst.name

    async def _request(self, method: str, path: str, json: Any = None) -> Any:
        label = f"AdGuard Home ({self.name})"
        auth = (self.inst.username, self.inst.password) if self.inst.username else None
        try:
            async with httpx.AsyncClient(verify=self.verify, timeout=20, auth=auth) as client:
                r = await client.request(method, f"{self.inst.url}/control{path}", json=json)
        except httpx.HTTPError as e:
            raise UpstreamError(label, f"unreachable ({e.__class__.__name__})")
        if r.status_code >= 400:
            msg = "invalid credentials" if r.status_code in (401, 403) else (r.text.strip()[:200] or f"HTTP {r.status_code}")
            raise UpstreamError(label, msg, r.status_code)
        if not r.content:
            return None
        try:
            return r.json()
        except ValueError:
            return r.text

    async def status(self) -> dict:
        return await self._request("GET", "/status")

    async def list_rewrites(self) -> list[dict]:
        return await self._request("GET", "/rewrite/list") or []

    async def add_rewrite(self, domain: str, answer: str) -> None:
        await self._request("POST", "/rewrite/add", {"domain": domain, "answer": answer})

    async def delete_rewrite(self, domain: str, answer: str) -> None:
        await self._request("POST", "/rewrite/delete", {"domain": domain, "answer": answer})

    async def ensure_rewrite(self, domain: str, answer: str) -> None:
        """Make `domain` resolve to `answer`, replacing rewrites of the same kind
        (IPv4 / IPv6 / CNAME) for that exact domain. Other kinds are kept."""
        kind = answer_kind(answer)
        existing = [r for r in await self.list_rewrites() if r["domain"].lower() == domain]
        if any(r["answer"] == answer for r in existing):
            return
        for r in existing:
            if answer_kind(r["answer"]) == kind:
                await self.delete_rewrite(r["domain"], r["answer"])
        await self.add_rewrite(domain, answer)

    async def remove_domain(self, domain: str, only_answer: str | None = None) -> None:
        for r in await self.list_rewrites():
            if r["domain"].lower() == domain and (only_answer is None or r["answer"] == only_answer):
                await self.delete_rewrite(r["domain"], r["answer"])


def answer_kind(answer: str) -> str:
    try:
        return "ipv%d" % ipaddress.ip_address(answer).version
    except ValueError:
        return "cname"
