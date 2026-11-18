"""Hooks into the Home Assistant login flow and records every attempt.

Home Assistant only logs a generic warning for a failed login (no username)
and nothing at all for a successful one. This module wraps two internal
methods to emit one structured line per attempt:

* ``HassLoginFlow.async_step_init`` - to remember which username was typed
  in a given login flow (the password is never touched).
* ``LoginFlowBaseView._async_flow_result_to_response`` - the single place
  where HA turns a login flow step into an HTTP response, so it sees every
  outcome together with the HTTP request (client IP, host, user agent).

Both are internal APIs: they are patched defensively and restored on unload.

Requests rejected for invalid authentication outside the login flow (a
revoked token on the websocket or the REST API, a bad refresh token) only
produce http.ban's warning: a logging filter on that logger turns them into
AUTH_AUDIT lines too (result=invalid_auth / banned), with no extra patching.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
import logging
import re
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResultType

from .const import EVENT_LOGIN, LOG_TAG

_LOGGER = logging.getLogger(__package__)

# Usernames typed in flows still in progress, keyed by flow_id.
_MAX_TRACKED_FLOWS = 256
_flow_usernames: OrderedDict[str, str] = OrderedDict()

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_FAIL_ERRORS = {"invalid_auth": "failed", "invalid_code": "failed_mfa"}


def _clean(value: Any, max_len: int = 128) -> str:
    """Make attacker-controlled text safe for a single logfmt value."""
    if value is None:
        return ""
    text = _CONTROL_CHARS.sub("?", str(value))
    return text[:max_len]


def _logfmt(fields: dict[str, Any]) -> str:
    parts = []
    for key, value in fields.items():
        text = _clean(value, 256 if key == "ua" else 128)
        if text == "" or re.search(r'[\s"=\\]', text):
            text = '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
        parts.append(f"{key}={text}")
    return " ".join(parts)


def _remember_username(flow_id: str | None, username: Any) -> None:
    if not flow_id or not isinstance(username, str):
        return
    _flow_usernames[flow_id] = username
    _flow_usernames.move_to_end(flow_id)
    while len(_flow_usernames) > _MAX_TRACKED_FLOWS:
        _flow_usernames.popitem(last=False)


class AuthAuditor:
    """Installs and removes the login flow hooks."""

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass
        self._restore: list[Callable[[], None]] = []

    @callback
    def install(self) -> None:
        """Patch the login flow. Raises if HA internals changed."""
        # Imported here: the auth component must be loaded first.
        from homeassistant.auth.providers.homeassistant import HassLoginFlow
        from homeassistant.components.auth.login_flow import LoginFlowBaseView

        orig_step_init = HassLoginFlow.async_step_init
        orig_to_response = LoginFlowBaseView._async_flow_result_to_response

        async def step_init(flow, user_input=None):  # type: ignore[no-untyped-def]
            if user_input is not None:
                _remember_username(flow.flow_id, user_input.get("username"))
            return await orig_step_init(flow, user_input)

        auditor = self

        async def to_response(view, request, client_id, result):  # type: ignore[no-untyped-def]
            # The original pops keys from result, so read what we need first.
            try:
                pending = auditor._classify(result)
            except Exception:  # never break a login because of auditing
                _LOGGER.exception("auth_audit: could not read login result")
                pending = None

            response = await orig_to_response(view, request, client_id, result)

            if pending is not None:
                try:
                    await auditor._record(pending, request, client_id, response)
                except Exception:
                    _LOGGER.exception("auth_audit: could not record login attempt")
            return response

        HassLoginFlow.async_step_init = step_init  # type: ignore[method-assign]
        LoginFlowBaseView._async_flow_result_to_response = to_response  # type: ignore[method-assign]

        def restore() -> None:
            HassLoginFlow.async_step_init = orig_step_init  # type: ignore[method-assign]
            LoginFlowBaseView._async_flow_result_to_response = orig_to_response  # type: ignore[method-assign]

        self._restore.append(restore)

        # Everything else HA rejects (invalid or revoked tokens on the API or
        # the websocket, bad refresh tokens...) only reaches http.ban's
        # warning. Listen to that logger instead of patching more internals.
        ban_logger = logging.getLogger(_BAN_LOGGER)
        ban_filter = _BanLogFilter(self)
        ban_logger.addFilter(ban_filter)
        self._restore.append(lambda: ban_logger.removeFilter(ban_filter))

    def emit(self, fields: dict[str, Any], user_id: str | None = None) -> None:
        """Write one AUTH_AUDIT line and fire the matching event."""
        fields = {k: v for k, v in fields.items() if v not in (None, "")}
        _LOGGER.warning("%s %s", LOG_TAG, _logfmt(fields))
        event = {k: _clean(v, 256) for k, v in fields.items()}
        if user_id:
            event["user_id"] = user_id
        self.hass.loop.call_soon_threadsafe(
            self.hass.bus.async_fire, EVENT_LOGIN, event
        )

    @callback
    def uninstall(self) -> None:
        """Put the original methods back."""
        while self._restore:
            self._restore.pop()()
        _flow_usernames.clear()

    def _classify(self, result: dict[str, Any]) -> dict[str, Any] | None:
        """Decide whether this flow step is worth recording."""
        flow_id = result.get("flow_id")
        handler = result.get("handler") or (None, None)
        base = {
            "flow_id": flow_id,
            "provider": handler[0] if handler else None,
            "step": result.get("step_id"),
        }
        rtype = result.get("type")

        if rtype is FlowResultType.CREATE_ENTRY:
            base["outcome"] = "success"
            base["credentials"] = result.get("result")
            base["username"] = _flow_usernames.pop(flow_id, None)
            return base

        if rtype is FlowResultType.FORM:
            error = (result.get("errors") or {}).get("base")
            if error not in _FAIL_ERRORS:
                return None  # first form shown, nothing attempted yet
            base["outcome"] = _FAIL_ERRORS[error]
            base["username"] = _flow_usernames.get(flow_id)
            return base

        if rtype is FlowResultType.ABORT:
            username = _flow_usernames.pop(flow_id, None)
            # An abort without a typed username is e.g. trusted_networks
            # refusing an IP before anything was attempted: still useful.
            base["outcome"] = "aborted"
            base["reason"] = result.get("reason")
            base["username"] = username
            return base

        return None

    async def _record(
        self,
        pending: dict[str, Any],
        request: Any,
        client_id: str,
        response: Any,
    ) -> None:
        outcome = pending["outcome"]
        user_name = user_id = None

        credentials = pending.pop("credentials", None)
        if credentials is not None:
            if not pending.get("username"):
                pending["username"] = credentials.data.get("username")
            user = await self.hass.auth.async_get_user_by_credentials(credentials)
            if user is not None:
                user_name, user_id = user.name, user.id
            # HA can still refuse a valid login (bad redirect, user inactive).
            if getattr(response, "status", 200) >= 400:
                outcome = "blocked"

        fields = {
            "result": outcome,
            "user": pending.get("username"),
            "user_name": user_name,
            "ip": request.remote,
            "provider": pending.get("provider"),
            "step": pending.get("step"),
            "reason": pending.get("reason"),
            "client": client_id,
            "host": request.host,
            "ua": request.headers.get("user-agent"),
        }
        self.emit(fields, user_id)


_BAN_LOGGER = "homeassistant.components.http.ban"
_INVALID_AUTH_RE = re.compile(
    r"^Login attempt or request with invalid authentication from "
    r"(?P<rdns>.*) \((?P<ip>[^()\s]+)\)\. Requested URL: '(?P<url>[^']*)'\. "
    r"\((?P<ua>.*)\)$",
    re.DOTALL,
)
_BANNED_RE = re.compile(r"^Banned IP (?P<ip>\S+) for too many login attempts$")


class _BanLogFilter(logging.Filter):
    """Turn http.ban's warnings into AUTH_AUDIT lines; never drops a record."""

    def __init__(self, auditor: AuthAuditor) -> None:
        super().__init__()
        self._auditor = auditor

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            self._handle(record.getMessage())
        except Exception:  # never break HA logging because of auditing
            _LOGGER.debug("auth_audit: could not parse %s", _BAN_LOGGER, exc_info=True)
        return True

    def _handle(self, message: str) -> None:
        if match := _INVALID_AUTH_RE.match(message):
            path = match["url"].split("?", 1)[0]  # query strings can hold secrets
            if path.startswith("/auth/login_flow"):
                return  # already recorded, with the username, by the flow hook
            fields: dict[str, Any] = {
                "result": "invalid_auth",
                "ip": match["ip"],
                "path": path,
            }
            if match["rdns"] != match["ip"]:
                fields["rdns"] = match["rdns"]
            fields["ua"] = None if match["ua"] == "None" else match["ua"]
            self._auditor.emit(fields)
        elif match := _BANNED_RE.match(message):
            self._auditor.emit({"result": "banned", "ip": match["ip"]})
