"""
Trend Vision One API client.
Handles authentication, pagination, and rate-limit retries.
"""

import os
import re
from typing import Any, Generator
from urllib.parse import urljoin, urlparse

import httpx
from dotenv import load_dotenv
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

load_dotenv()

_API_KEY = os.getenv("TVOne_API_KEY", "")
_BASE_URL = os.getenv("TVOne_BASE_URL", "https://api.xdr.trendmicro.com").rstrip("/")


def _is_rate_limited(exc: BaseException) -> bool:
    return isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 429


class TrendVisionOneClient:
    """Synchronous Trend Vision One REST API client."""

    def __init__(self, api_key: str = _API_KEY, base_url: str = _BASE_URL):
        if not api_key:
            raise ValueError(
                "API key is required. Set TVOne_API_KEY in your .env file."
            )
        self._base_url = base_url
        self._client = httpx.Client(
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @retry(
        retry=retry_if_exception(_is_rate_limited),
        wait=wait_exponential(multiplier=1, min=5, max=60),
        stop=stop_after_attempt(5),
    )
    def get(self, path: str, params: dict | None = None) -> dict:
        """Perform a GET request and return the parsed JSON response."""
        url = urljoin(self._base_url + "/", path.lstrip("/"))
        response = self._client.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def paginate(
        self,
        path: str,
        params: dict | None = None,
        items_key: str = "items",
        limit: int = 200,
    ) -> Generator[dict, None, None]:
        """
        Iterate over all pages of a paginated endpoint.
        Trend Vision One uses a `nextLink` field for cursor-based pagination.
        """
        params = dict(params or {})
        params.setdefault("top", limit)

        next_url: str | None = path
        _base_parsed = urlparse(self._base_url)
        while next_url:
            if next_url.startswith("http"):
                # Validate nextLink stays on the same host to prevent SSRF
                # and API key leakage to third-party hosts
                _next_parsed = urlparse(next_url)
                if (
                    _next_parsed.netloc != _base_parsed.netloc
                    or _next_parsed.scheme != "https"
                ):
                    break  # stop pagination rather than follow untrusted URL
                response = self._client.get(next_url)
                response.raise_for_status()
                data = response.json()
            else:
                data = self.get(next_url, params)
                params = {}  # params are encoded in nextLink on subsequent pages

            for item in data.get(items_key, []):
                yield item

            next_url = data.get("nextLink")
