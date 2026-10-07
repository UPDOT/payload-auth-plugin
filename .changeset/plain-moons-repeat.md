---
"payload-auth-plugin": patch
---

Include `authVersion` in the JWT protected header so sessions authenticate against Payload 3.90+

Payload 3.90 added a version marker to its JWT protected header and rejects any token without it, so every session cookie this plugin issues fails to authenticate on that version. The value is read from Payload when available and falls back to the literal, keeping the `^3.0.0` peer range intact — older versions ignore the extra header field.
