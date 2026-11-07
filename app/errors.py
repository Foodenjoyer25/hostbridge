class UpstreamError(Exception):
    """Raised when NPM or AdGuard Home returns an error or is unreachable."""

    def __init__(self, service: str, message: str, status: int | None = None):
        self.service = service
        self.status = status
        super().__init__(f"{service}: {message}")
