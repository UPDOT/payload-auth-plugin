---
"payload-auth-plugin": patch
---

Make issued sessions authenticate against Payload 3.90+

Payload 3.90 hardened its JWT handling in two ways that reject every cookie this plugin issues:

- the signed protected header must carry `authVersion`, which is now set (read from Payload when available, falling back to the literal so the `^3.0.0` peer range is unaffected — older versions ignore the extra field)
- claim shapes are validated, and a `sid` that is present but not a string drops the whole token. `OAuthAuthentication` signs `sid: useSessions ? uuid() : null`, so a null reaches the signer whenever sessions are disabled. Empty claims are now omitted.

Either one alone leaves the user unauthenticated on every request after a successful sign-in.
