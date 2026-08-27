# Authentication failure

Use this when login, logout, session inspection, or organization selection fails for operators or users. Do not paste passwords, session cookies, CSRF tokens, or PHC strings into tickets or chat.

## Symptoms

- `POST /auth/login` returns `401` with `Invalid email or password.`
- `POST /auth/login` returns `429` (`Too many login attempts. Try again later.`) or `503` (`Login is temporarily unavailable.`)
- Authenticated `GET /auth/session` or `GET /auth/organizations` returns `401`
- `POST /auth/select-organization` returns `404` (`Organization not found.`)
- Browser login from an unexpected origin returns `403`
- Web `/session-expired` after an authenticated request returns `401`
- Web `/access-denied` after organization selection is forbidden or not found

## Immediate checks

1. Confirm PostgreSQL is reachable (`GET /health/ready`). Sessions are stored in PostgreSQL, not Redis.
2. Confirm Redis is reachable if login is `503`. Login is **fail-closed** when the limiter cannot decide. Logout and session reads must not require Redis.
3. Confirm `CORS_ALLOWED_ORIGINS` matches the browser Origin exactly. Login, logout (with a live cookie), and select-organization reject other origins.
4. Confirm production cookies use `__Host-patchpilot.sid` with Secure, HttpOnly, SameSite=Lax, Path=/, and no Domain. Restart after fixing `AUTH_COOKIE_NAME` / `AUTH_COOKIE_SECURE`; do not change cookie flags in the running process.

## Recovery

- **Wrong password / unknown user:** same public `401`. Do not confirm whether the email exists.
- **Rate limited:** wait for the configured windows; do not raise limits in production to “test.”
- **Redis down:** restore Redis, then retry login. Existing sessions remain valid until idle or absolute expiry or logout.
- **Stolen session:** log out on that browser. Disable the user to invalidate remaining sessions on the next request.
- **Unexpected audit gap:** do not update or delete audit rows. File an [audit integrity](audit-integrity-failure.md) follow-up.

## Related

- [ADR 0019](../adr/0019-local-password-sessions.md)
- [Local infrastructure failure](local-infrastructure-failure.md)
- [Audit integrity failure](audit-integrity-failure.md)
