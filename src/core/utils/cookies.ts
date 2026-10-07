import * as jwt from "jose"
import {
  getCookieExpiration,
  generateCookie,
} from "payload"
import * as payloadExports from "payload"
import type { SanitizedCollectionConfig } from "payload"

// Payload >= 3.90 requires this in the signed protected header and rejects any
// token without it. It only exports the constant from that version onwards, so
// read it off the namespace and fall back to the literal rather than naming it
// in the import — a named import would break the ^3.0.0 peer range. Earlier
// versions simply ignore the extra header field.
const JWT_AUTH_VERSION: number =
  (payloadExports as { JWT_AUTH_VERSION?: number }).JWT_AUTH_VERSION ?? 1

export async function createSessionCookies(
  name: string,
  secret: string,
  fieldsToSign: Record<string, unknown>,
  expiration?: number,
  collectionAuthConfig?: SanitizedCollectionConfig["auth"] | false,
) {
  const tokenExpiration: number =
    expiration ??
    getCookieExpiration({
      seconds: 7200,
    }).getTime()

  const secretKey = new TextEncoder().encode(secret)
  const issuedAt = Math.floor(Date.now() / 1000)
  const exp = issuedAt + tokenExpiration
  const token = await new jwt.SignJWT(fieldsToSign)
    .setProtectedHeader({ alg: "HS256", authVersion: JWT_AUTH_VERSION, typ: "JWT" })
    .setIssuedAt(issuedAt)
    .setExpirationTime(exp)
    .sign(secretKey)

  const cookies: string[] = []

  if (collectionAuthConfig) {
    const sameSite = typeof collectionAuthConfig.cookies.sameSite === 'string' ? collectionAuthConfig.cookies.sameSite : collectionAuthConfig.cookies.sameSite ? 'Strict' : undefined;
    const cookie =  generateCookie({
      name: name,
      domain: collectionAuthConfig.cookies.domain ?? undefined,
      expires: getCookieExpiration({ seconds: expiration! }),
      httpOnly: true,
      path: '/',
      returnCookieAsObject: false,
      sameSite,
      secure: collectionAuthConfig.cookies.secure,
      value: token
    }) as string;
    
    cookies.push(cookie);
    
  } else {
    cookies.push(
      `${name}=${token};Path=/;HttpOnly;SameSite=lax;Expires=${getCookieExpiration({ seconds: expiration! }).toUTCString()}`,
    )
  }

  return cookies
}

export async function verifySessionCookie(token: string, secret: string) {
  const secretKey = new TextEncoder().encode(secret)
  return await jwt.jwtVerify<{
    id: string
    email: string
    collection: string
    iat: number
    exp: number
  }>(token, secretKey)
}

export function invalidateOAuthCookies(cookies: string[]) {
  const expired = "Thu, 01 Jan 1970 00:00:00 GMT"
  cookies.push(
    `__session-oauth-state=; Path=/; HttpOnly; SameSite=Lax; Expires=${expired}`,
  )
  cookies.push(
    `__session-oauth-nonce=; Path=/; HttpOnly; SameSite=Lax; Expires=${expired}`,
  )
  cookies.push(
    `__session-code-verifier=; Path=/; HttpOnly; SameSite=Lax; Expires=${expired}`,
  )
  cookies.push(
    `__session-webpk-challenge=; Path=/; HttpOnly; SameSite=Lax; Expires=${expired}`,
  )
  return cookies
}

export const invalidateSessionCookies = (name: string, cookies: string[]) => {
  const expired = "Thu, 01 Jan 1970 00:00:00 GMT"
  cookies.push(`${name}=; Path=/; HttpOnly; SameSite=Lax; Expires=${expired}`)
  return cookies
}
