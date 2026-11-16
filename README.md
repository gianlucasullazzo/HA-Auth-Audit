# Auth Audit for Home Assistant

Home Assistant logs a failed login only as a generic warning (IP, no username) and
does not log successful logins at all. **Auth Audit** writes one structured line for
every interactive login attempt and fires an event, so you can build a login history
in Grafana/Loki or react to it in automations.

```
AUTH_AUDIT result=failed user=admin ip=203.0.113.7 provider=homeassistant step=init client=https://home.example.com/ host=home.example.com ua="Mozilla/5.0 ..."
AUTH_AUDIT result=success user=gianluca user_name="Gianluca" ip=192.168.2.50 provider=homeassistant client=https://home.example.com/ host=home.example.com ua="..."
```

| Field | Meaning |
|---|---|
| `result` | `success`, `failed` (wrong username/password), `failed_mfa` (wrong 2FA code), `blocked` (valid credentials refused by HA, e.g. inactive user), `aborted` (flow ended, e.g. too many 2FA retries; see `reason`) |
| `user` | Username typed in the login form (attacker-controlled, sanitized) |
| `user_name` | Display name of the matched HA user (success only) |
| `ip` | Client IP as Home Assistant sees it (honours `trusted_proxies`) |
| `provider` / `step` | Auth provider and flow step (`init`, `mfa`, ...) |
| `client` / `host` / `ua` | OAuth client id, requested host, user agent |

The same data is fired as the `auth_audit_login` event (plus `user_id` on success).

Lines are logged at **WARNING** level by the logger `custom_components.auth_audit`,
so they pass the default log level. The password is never read or logged.

## What it does not see

Only interactive logins (username + password through the login page or the
companion app's login screen). Refresh tokens, long-lived access tokens and
already logged-in apps never go through a login flow, so they are not logged.
Invalid tokens are still logged by Home Assistant's own `http.ban` warning.

## Install

HACS: add this repository as a custom repository (type *Integration*), install
**Auth Audit**, restart, then *Settings → Devices & services → Add integration →
Auth Audit*.

Manual: copy `custom_components/auth_audit` into your `config/custom_components`,
restart, then add the integration from the UI.

## How it works

It wraps two internal methods of the Home Assistant auth code
(`HassLoginFlow.async_step_init` to remember the typed username, and
`LoginFlowBaseView._async_flow_result_to_response` to see the outcome together
with the HTTP request). They are internal APIs: if a Home Assistant release
changes them, the integration fails to load with a clear error instead of
breaking the login. Removing the integration restores the original methods.

Tested with Home Assistant 2026.11.

## Development

```
pip install -r requirements_test.txt
pytest
```
