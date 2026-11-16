"""Auth Audit: log every Home Assistant login attempt with username and IP."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .audit import AuthAuditor

_LOGGER = logging.getLogger(__name__)

type AuthAuditConfigEntry = ConfigEntry[AuthAuditor]


async def async_setup_entry(hass: HomeAssistant, entry: AuthAuditConfigEntry) -> bool:
    """Install the login flow hooks."""
    auditor = AuthAuditor(hass)
    try:
        auditor.install()
    except (ImportError, AttributeError) as err:
        # The internals we hook into moved in this HA release.
        raise ConfigEntryNotReady(
            f"Home Assistant login internals not found, update Auth Audit: {err}"
        ) from err
    entry.runtime_data = auditor
    _LOGGER.info("Auth Audit active: login attempts are logged as AUTH_AUDIT")
    return True


async def async_unload_entry(hass: HomeAssistant, entry: AuthAuditConfigEntry) -> bool:
    """Remove the hooks."""
    entry.runtime_data.uninstall()
    return True
