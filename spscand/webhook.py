"""POST scanner events to a URL in order, HMAC-signed, with retries."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import queue
import threading
import time
import urllib.error
import urllib.request

log = logging.getLogger("spscand")

RETRY_DELAYS = (1, 5, 15, 60, 300)


class Webhook:
    def __init__(self, url: str, network: str, *, secret: str = "", timeout: float = 15) -> None:
        self.url = url
        self.network = network
        self.secret = secret.encode()
        self.timeout = timeout
        self._queue: queue.Queue = queue.Queue()
        self._thread = threading.Thread(target=self._run, name="webhook", daemon=True)
        self._thread.start()

    def __call__(self, event: str, data: dict) -> None:
        body = json.dumps(
            {"event": event, "network": self.network, "time": int(time.time()), "data": data},
            sort_keys=True,
        ).encode()
        self._queue.put(body)

    def close(self, timeout: float = 10) -> None:
        self._queue.put(None)
        self._thread.join(timeout)

    def _post(self, body: bytes) -> None:
        headers = {"Content-Type": "application/json", "User-Agent": "spscand"}
        if self.secret:
            digest = hmac.new(self.secret, body, hashlib.sha256).hexdigest()
            headers["X-Spscand-Signature"] = f"sha256={digest}"
        request = urllib.request.Request(self.url, data=body, headers=headers)
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            response.read()

    def _run(self) -> None:
        while (body := self._queue.get()) is not None:
            for delay in (*RETRY_DELAYS, None):
                try:
                    self._post(body)
                    break
                except (urllib.error.URLError, OSError) as exc:
                    if delay is None:
                        log.error("webhook delivery failed, event dropped: %s", exc)
                        break
                    log.warning("webhook delivery failed (%s); retrying in %ds", exc, delay)
                    time.sleep(delay)
