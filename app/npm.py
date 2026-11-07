"""Minimal async client for the Nginx Proxy Manager API."""
import time
from typing import Any

import httpx

from .errors import UpstreamError


class NPMClient:
    def __init__(self, url: str, email: str, password: str, verify: bool = True):
        self.url = url
        self.email = email
        self.password = password
        self.verify = verify
        self._token: str | None = None
        self._token_exp = 0.0

    async def _login(self, client: httpx.AsyncClient) -> None:
        try:
            r = await client.post(
                f"{self.url}/api/tokens",
                json={"identity": self.email, "secret": self.password},
            )
        except httpx.HTTPError as e:
            raise UpstreamError("Nginx Proxy Manager", f"unreachable ({e.__class__.__name__})")
        if r.status_code >= 400:
            raise UpstreamError("Nginx Proxy Manager", f"login failed: {_err(r)}", r.status_code)
        self._token = r.json()["token"]
        self._token_exp = time.time() + 12 * 3600  # NPM tokens last 1 day by default

    async def _request(self, method: str, path: str, **kw: Any) -> Any:
        async with httpx.AsyncClient(verify=self.verify, timeout=30) as client:
            if not self._token or time.time() > self._token_exp:
                await self._login(client)
            for attempt in range(2):
                try:
                    r = await client.request(
                        method,
                        f"{self.url}/api{path}",
                        headers={"Authorization": f"Bearer {self._token}"},
                        **kw,
                    )
                except httpx.HTTPError as e:
                    raise UpstreamError("Nginx Proxy Manager", f"unreachable ({e.__class__.__name__})")
                if r.status_code == 401 and attempt == 0:
                    await self._login(client)
                    continue
                break
            if r.status_code >= 400:
                raise UpstreamError("Nginx Proxy Manager", _err(r), r.status_code)
            return r.json() if r.content else None

    async def list_proxy_hosts(self) -> list[dict]:
        return await self._request("GET", "/nginx/proxy-hosts", params={"expand": "certificate,access_list"})

    async def get_proxy_host(self, host_id: int) -> dict:
        return await self._request("GET", f"/nginx/proxy-hosts/{host_id}")

    async def create_proxy_host(self, payload: dict) -> dict:
        return await self._request("POST", "/nginx/proxy-hosts", json=payload)

    async def update_proxy_host(self, host_id: int, payload: dict) -> dict:
        return await self._request("PUT", f"/nginx/proxy-hosts/{host_id}", json=payload)

    async def delete_proxy_host(self, host_id: int) -> None:
        await self._request("DELETE", f"/nginx/proxy-hosts/{host_id}")

    async def set_enabled(self, host_id: int, enabled: bool) -> None:
        await self._request("POST", f"/nginx/proxy-hosts/{host_id}/{'enable' if enabled else 'disable'}")

    async def list_certificates(self) -> list[dict]:
        return await self._request("GET", "/nginx/certificates")

    async def list_access_lists(self) -> list[dict]:
        return await self._request("GET", "/nginx/access-lists")


def _err(r: httpx.Response) -> str:
    try:
        data = r.json()
        if isinstance(data, dict):
            err = data.get("error")
            if isinstance(err, dict) and err.get("message"):
                return str(err["message"])
            if data.get("message"):
                return str(data["message"])
    except ValueError:
        pass
    return f"HTTP {r.status_code}: {r.text[:200]}"
