"""Browser guard for the L1 gVisor lab: its own sandbox, beside the browser's.

In L2 (smolvm) the guard ran inside the browser VM. Here keeper, guard, and
browser each get a gVisor sandbox. The guard is the only one with a keeper
channel key and a route to the keeper; the browser has neither. The guard
reaches the browser over DevTools on a second network (the browser's relay)
to fill session material into a page, which is the path a real fill takes.

This module reuses ``guard_svc.Guard`` unchanged and adds control commands:

    browser            DevTools /json/version through the relay
    canary TEXT        open a page holding TEXT (a scan's positive control)
    tab MIB            open a page that holds MIB of JS memory
    close TARGET       close a page; ok only once the target is gone
    fill               put the held session into a login page
    page_fill_matches  whether a page's fill is the held grant and token
                       (booleans only; nothing secret in the reply)
    redeem_from_page   read a filled session back from the browser, redeem it
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hmac
import json
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict

import guard_svc
from cdp import Cdp, version
from kkrpc import parse_address

LOGIN_PAGE = (
    "<!doctype html><title>login.example.test</title>"
    "<form><input id=user value=lab><input id=pw type=password></form>"
)

TAB_PAGE = """<!doctype html><body><script>
const held = [];
for (let i = 0; i < %d; i++) {
  const block = new Uint8Array(4 << 20);
  for (let j = 0; j < block.length; j += 4096) block[j] = 1;
  held.push(block);
}
window.__held = held;
document.body.textContent = "tab held " + held.length * 4 + " MiB";
</script></body>"""


def _data_url(html: str) -> str:
    return "data:text/html," + urllib.parse.quote(html)


class GvGuard(guard_svc.Guard):
    """``guard_svc.Guard`` plus the DevTools fill path."""

    def __init__(self, run: Path, disk: Path, keeper: str) -> None:
        """Read the browser relay address the launcher installed."""
        super().__init__(run, disk, keeper)
        self.browser = parse_address((run / "browser.addr").read_text("utf-8").strip())

    def _cdp(self) -> Cdp:
        return Cdp(self.browser)

    def _wait_text(self, cdp: Cdp, session: str, prefix: str) -> str:
        return cdp.evaluate(
            session,
            "new Promise(r => { const t = () => (document.body && document.body.textContent"
            f".startsWith({json.dumps(prefix)})) ? r(document.body.textContent) : "
            "setTimeout(t, 50); t(); })",
        )

    def dispatch(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Run one control command; unknown ones go to ``guard_svc.Guard``."""
        cmd = request.get("cmd")
        try:
            if cmd == "browser":
                return {"code": "ok", "browser": version(self.browser)["Browser"]}
            if cmd == "canary":
                text = str(request["text"])
                with self._cdp() as cdp:
                    target, session = cdp.open_page(_data_url(f"<body>{text}</body>"))
                    self._wait_text(cdp, session, text[:8])
                return {"code": "ok", "target": target}
            if cmd == "tab":
                mib = int(request.get("mib", 256))
                with self._cdp() as cdp:
                    target, session = cdp.open_page(_data_url(TAB_PAGE % (mib // 4)))
                    text = self._wait_text(cdp, session, "tab held")
                ok = text == f"tab held {mib // 4 * 4} MiB"
                return {
                    "code": "ok" if ok else "tab_incomplete",
                    "target": target,
                    "text": text,
                }
            if cmd == "close":
                target = str(request["target"])
                with self._cdp() as cdp:
                    cdp.call("Target.closeTarget", {"targetId": target})
                    deadline = time.monotonic() + 10
                    while any(p["targetId"] == target for p in cdp.pages()):
                        if time.monotonic() > deadline:
                            return {"code": "still_open"}
                        time.sleep(0.1)
                return {"code": "ok"}
            if cmd == "fill":
                return self._fill()
            if cmd == "page_fill_matches":
                return self._page_fill_matches()
            if cmd == "redeem_from_page":
                return self._redeem_from_page()
        except (OSError, ConnectionError, RuntimeError, KeyError, ValueError) as exc:
            return {"code": "browser_error", "message": f"{type(exc).__name__}: {exc}"}
        return super().dispatch(request)

    def _fill(self) -> Dict[str, Any]:
        with self._lock:
            held = dict(self.held) if self.held else None
        if held is None:
            return {"code": "nothing_held"}
        fill = json.dumps({"g": held["grant_ref"], "t": held["token"]})
        with self._cdp() as cdp:
            target, session = cdp.open_page(_data_url(LOGIN_PAGE))
            self._wait_text(cdp, session, "")
            done = cdp.evaluate(
                session,
                f"(() => {{ const f = {fill}; document.getElementById('pw').value = f.t; "
                "window.__eggomiFill = f; return document.getElementById('pw').value.length; })()",
            )
        return {"code": "ok" if done else "fill_failed", "target": target}

    def _page_fill(self) -> Dict[str, Any] | None:
        """Return the first page's ``window.__eggomiFill``, or ``None``."""
        with self._cdp() as cdp:
            for page in cdp.pages():
                session = cdp.call(
                    "Target.attachToTarget",
                    {"targetId": page["targetId"], "flatten": True},
                )["sessionId"]
                raw = cdp.evaluate(
                    session,
                    "window.__eggomiFill ? JSON.stringify(window.__eggomiFill) : null",
                )
                if raw:
                    return json.loads(raw)
        return None

    def _page_fill_matches(self) -> Dict[str, Any]:
        with self._lock:
            held = dict(self.held) if self.held else None
        fill = self._page_fill()
        if held is None or fill is None:
            return {"code": "nothing_held" if held is None else "nothing_filled"}
        return {
            "code": "ok",
            "grant_match": hmac.compare_digest(str(fill.get("g")), held["grant_ref"]),
            "token_match": hmac.compare_digest(str(fill.get("t")), held["token"]),
        }

    def _redeem_from_page(self) -> Dict[str, Any]:
        fill = self._page_fill()
        if fill is None:
            return {"code": "nothing_filled"}
        reply = self._call("Redeem", {"grant_ref": fill["g"], "token": fill["t"]})
        if "error" in reply:
            return {"code": reply["error"]["code"]}
        return {"code": "ok"}


if __name__ == "__main__":
    guard_svc.Guard = GvGuard  # serve() builds the guard by this name
    raise SystemExit(guard_svc.main())
