"""Configuration, read from environment variables."""
import os
import secrets
from dataclasses import dataclass
from urllib.parse import urlparse


def _split(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class AdGuardInstance:
    name: str
    url: str
    username: str
    password: str


class Settings:
    def __init__(self) -> None:
        self.npm_url = os.getenv("NPM_URL", "http://nginx-proxy-manager:81").rstrip("/")
        self.npm_email = os.getenv("NPM_EMAIL", "")
        self.npm_password = os.getenv("NPM_PASSWORD", "")

        # One or more AdGuard Home instances (comma-separated). Credentials may be
        # a single value shared by all instances or one value per instance.
        urls = _split(os.getenv("ADGUARD_URL", "http://adguardhome:3000"))
        users = _split(os.getenv("ADGUARD_USERNAME", ""))
        pwds = [p for p in os.getenv("ADGUARD_PASSWORD", "").split(",")]
        names = _split(os.getenv("ADGUARD_NAMES", ""))
        self.adguard: list[AdGuardInstance] = []
        for i, url in enumerate(urls):
            pick = lambda lst: (lst[i] if i < len(lst) else (lst[0] if lst else ""))
            self.adguard.append(
                AdGuardInstance(
                    name=names[i] if i < len(names) else (urlparse(url).hostname or f"adguard-{i + 1}"),
                    url=url.rstrip("/"),
                    username=pick(users),
                    password=pick(pwds).strip(),
                )
            )

        # IP (or hostname) that new DNS rewrites should point to - usually the
        # machine running Nginx Proxy Manager.
        self.default_dns_answer = os.getenv("DEFAULT_DNS_ANSWER", "")
        # If set, "jellyfin" is expanded to "jellyfin.<suffix>".
        self.default_domain_suffix = os.getenv("DEFAULT_DOMAIN_SUFFIX", "").strip(".").lower()
        self.letsencrypt_email = os.getenv("LETSENCRYPT_EMAIL", "")
        self.verify_tls = _bool(os.getenv("VERIFY_TLS"), True)

        # Protect the UI with a password (strongly recommended).
        self.app_password = os.getenv("APP_PASSWORD", "")
        self.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)
        self.session_hours = int(os.getenv("SESSION_HOURS", "168"))
        self.secure_cookie = _bool(os.getenv("SECURE_COOKIE"), False)


settings = Settings()
