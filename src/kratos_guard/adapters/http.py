"""Read-only HTTP observations."""

from urllib.error import URLError
from urllib.request import Request, urlopen


def get_status(url: str, timeout: float = 1.0) -> tuple[int | None, str]:
    request = Request(url, method="GET", headers={"User-Agent": "kratos-agent-guard/0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, response.headers.get("content-type", "")
    except (OSError, URLError):
        return None, ""
