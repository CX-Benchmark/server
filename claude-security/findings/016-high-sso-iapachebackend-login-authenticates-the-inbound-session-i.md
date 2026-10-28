# SSO (IApacheBackend) login authenticates the inbound session ID without rotation (session fixation)

| Field | Value |
|---|---|
| ID | `find_01EKEGhqCk6amqYtuDmM1F9F` |
| Severity | **High** |
| Status | open |
| CWE | CWE-384 — Session fixation |
| Created | 2026-10-27T21:51:46.362441Z |
| Claude Security | https://claude.ai/security/findings/find_01EKEGhqCk6amqYtuDmM1F9F |

## Description

An attacker who can plant cookies in a victim's browser can take over the victim's web session after the victim logs in through single sign-on (SSO). This needs a deployed `IApacheBackend` app such as user_saml, and a cookie-planting position for the Nextcloud host. The cause is `OC_User::loginWithApache()`, which logs the user into the session ID sent by the client and does not issue a new one.

1. **Attacker** obtains a server-issued session ID and passphrase cookie. The attacker gets a valid `<instanceid>=SID_A` and `oc_sessionPassphrase=P_A` from the server without logging in. ([`lib/private/Session/CryptoWrapper.php:47-70`](https://github.com/cx-benchmark/server/blob/6b6317280f8ed50277369c33cee070a643d29654/lib/private/Session/CryptoWrapper.php#L47-L70))
2. **Attacker** plants both cookies in the victim's browser. This needs a cookie-planting position for the host, such as a sibling sub-domain using cookie tossing or a cleartext-HTTP injection. `oc_sessionPassphrase` is a plain host cookie with no `__Host-` prefix, so it can be planted. ([`lib/private/Session/CryptoWrapper.php:47-70`](https://github.com/cx-benchmark/server/blob/6b6317280f8ed50277369c33cee070a643d29654/lib/private/Session/CryptoWrapper.php#L47-L70))
3. **Victim** logs in through the SSO backend. On the victim's next request that is not yet logged in, `OC::handleLogin()` runs `OC_User::handleApacheAuth()` first, which reaches `loginWithApache()`. ([`lib/OC.php:1291-1298`](https://github.com/cx-benchmark/server/blob/6b6317280f8ed50277369c33cee070a643d29654/lib/OC.php#L1291-L1298))
4. **the function `loginWithApache()`** writes `user_id` into the planted session and creates a session token for its ID. `createSessionToken()` keys the token on `$this->session->getId()`, which is the ID that came in with the request cookie. ([`lib/private/User/Session.php:653-677`](https://github.com/cx-benchmark/server/blob/6b6317280f8ed50277369c33cee070a643d29654/lib/private/User/Session.php#L653-L677))
5. **the function `loginWithApache()`** calls `completeLogin()` with `regenerateSessionId` set to false. `Session::completeLogin()` therefore skips `regenerateId()` and the CSRF token refresh, so the planted ID stays the authenticated session. ([`lib/private/User/Session.php:341-352`](https://github.com/cx-benchmark/server/blob/6b6317280f8ed50277369c33cee070a643d29654/lib/private/User/Session.php#L341-L352))
6. **Attacker** sends requests with the planted `SID_A` and `P_A` cookies. `validateSession()` accepts the session because a valid session token exists for that ID, so the attacker is treated as the victim. ([`lib/private/User/Session.php:204-231`](https://github.com/cx-benchmark/server/blob/6b6317280f8ed50277369c33cee070a643d29654/lib/private/User/Session.php#L204-L231))

## Assessment

The attacker is unauthenticated. The attacker needs a cookie-planting position for the Nextcloud host, for example a sibling sub-domain using cookie tossing, or a cleartext-HTTP injection. The instance must use an `IApacheBackend` SSO app such as user_saml, in SAML or environment-variable mode. The victim must log in through it while the planted cookies are in the browser. The finding assumes the SSO app does not rotate the session ID itself, and that PHP keeps the first of duplicate cookie names, as current PHP 8.x releases do. PHP strict session mode would not help, because the attacker can use a server-issued ID.

Impact: The attacker fully takes over the victim's web session. The attacker can read, change and delete the victim's files, shares, calendars and contacts. A `REMEMBER` token keeps the session alive, and nothing ties the token to an IP address or user agent. If the SSO backend supplies no password, the token carries `SCOPE_SKIP_PASSWORD_VALIDATION`, which also opens actions that require password confirmation. An admin victim gives the attacker admin control.

## Recommendation

`OC_User::loginWithApache()` authenticates the user into the session ID supplied by the client instead of a freshly generated one. This breaks the rule that a privilege change must rotate the session identifier.

Fix criteria: After a successful SSO login, the session ID presented in the request never becomes an authenticated session. The server issues a new ID before or while it binds `user_id` and the session token, and the old ID is invalidated. To test, plant a known `<instanceid>` and `oc_sessionPassphrase` pair and complete an SSO login. Requests with the planted cookies must stay unauthenticated. No `authtoken` row may exist for the planted ID.

## Evidence

**https://github.com/cx-benchmark/server**

- [`lib/private/legacy/OC_User.php:128-176`](https://github.com/cx-benchmark/server/blob/6b6317280f8ed50277369c33cee070a643d29654/lib/private/legacy/OC_User.php#L128-L176)
- [`lib/private/User/Session.php:341-352`](https://github.com/cx-benchmark/server/blob/6b6317280f8ed50277369c33cee070a643d29654/lib/private/User/Session.php#L341-L352)
- [`lib/private/User/Session.php:653-677`](https://github.com/cx-benchmark/server/blob/6b6317280f8ed50277369c33cee070a643d29654/lib/private/User/Session.php#L653-L677)
- [`lib/private/User/Session.php:204-231`](https://github.com/cx-benchmark/server/blob/6b6317280f8ed50277369c33cee070a643d29654/lib/private/User/Session.php#L204-L231)
- [`lib/private/Authentication/Login/Chain.php:35-36`](https://github.com/cx-benchmark/server/blob/6b6317280f8ed50277369c33cee070a643d29654/lib/private/Authentication/Login/Chain.php#L35-L36)
- [`lib/OC.php:1291-1298`](https://github.com/cx-benchmark/server/blob/6b6317280f8ed50277369c33cee070a643d29654/lib/OC.php#L1291-L1298)
- [`lib/private/Session/CryptoWrapper.php:47-70`](https://github.com/cx-benchmark/server/blob/6b6317280f8ed50277369c33cee070a643d29654/lib/private/Session/CryptoWrapper.php#L47-L70)

