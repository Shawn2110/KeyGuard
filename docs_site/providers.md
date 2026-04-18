# Provider matrix

v1 ships with three providers. Each implements four methods:
`test_key`, `create_key`, `revoke_key`, `list_keys`.

| Provider | `test_key` endpoint | Auth | Admin endpoints |
|----------|---------------------|------|------------------|
| **OpenAI** | `GET /v1/models` | Bearer | `/organization/admin/api_keys` |
| **Anthropic** | `GET /v1/models` | Bearer | `/v1/organizations/default/api_keys` |
| **Stripe** | `GET /v1/account` | Basic (key as user) | `/v1/api_keys` + `/expire` to revoke |

Rotation creates a new key, verifies it works via `test_key`, walks
the user through updating each tracked deployment, and only then
revokes the old key. If the new key fails verification the flow
rolls back — old key stays active.

Adding a new provider means subclassing `Provider`, decorating with
`@register`, and pointing the class's `key_pattern` regex at the
provider's token format. See
[`core/providers/openai.py`](https://github.com/Shawn2110/KeyGuard/blob/main/src/keyguard/core/providers/openai.py)
for the smallest working example.
