import pytest


@pytest.fixture(autouse=True)
def _no_retry_sleeps(monkeypatch):
    """P2.4: retry backoff must never slow down the test suite.

    Identity modules read RETRY_* knobs at call time via _retry_settings(),
    so patching the env here makes every backoff a no-op while keeping the
    retry loop itself fully exercised.
    """
    monkeypatch.setenv("RETRY_BACKOFF", "0")
    monkeypatch.setenv("RETRY_MAX_SLEEP", "0")


class FakeResponse:
    """Minimal stand-in for requests.Response with the fields modules read."""

    def __init__(self, status_code=200, json_data=None, text="", headers=None):
        self.status_code = status_code
        self._json = json_data
        self.text = text
        self.headers = headers or {}
        self.content = text.encode("utf-8")

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            from requests.exceptions import HTTPError

            raise HTTPError(
                f"HTTPError {self.status_code} for {self.url}", response=self
            )

    def iter_content(self, chunk_size=16384):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i : i + chunk_size]

    def close(self):
        pass
