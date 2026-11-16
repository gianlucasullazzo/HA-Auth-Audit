"""Config flow for Auth Audit (single instance, no options)."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult

from .const import DOMAIN


class AuthAuditConfigFlow(ConfigFlow, domain=DOMAIN):
    """Add Auth Audit from the UI."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm and create the single entry."""
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()
        if user_input is not None:
            return self.async_create_entry(title="Auth Audit", data={})
        return self.async_show_form(step_id="user")
