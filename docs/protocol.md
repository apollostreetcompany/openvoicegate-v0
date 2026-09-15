# A familiar flow. A specific contract.

Use the included helper to complete the exchange on your server.

## The shape of the integration

OpenVoiceGate uses an **OAuth-style authorization-code exchange with S256 PKCE**. PKCE binds a one-use authorization code to the original entry request. This is a custom OpenVoiceGate protocol, not a drop-in OAuth 2.0 or OpenID Connect provider.

1. Your server creates browser-bound state, a nonce, and a PKCE verifier, then stores them in a pending request.
2. The browser navigates to the verifier’s `GET /authorize` with the registered client and callback, state, `request_nonce`, `code_challenge`, and `code_challenge_method=S256`.
3. The verifier asks for consent, checks a fresh voice phrase, resolves a profile, and asks what name to share.
4. The browser returns to the registered callback with `code`, `state`, and `iss`. Private profile data does not belong in that URL.
5. Your server checks the browser binding, state, and issuer, then exchanges the code at `POST /v1/authorize/token`. The client secret stays on the server.
6. The SDK verifies the signed result. Your application atomically consumes the pending request and proof ID, checks moderation, creates or finds the site user, and opens a session.

The successful exchange also supplies an encrypted moderation receipt for the registered client. Store and use it on your server according to the [moderation contract](moderation.md); it is not a public lookup handle.

## A code is not a session

The callback alone does not authorize a visitor. Verification pins issuer, audience, signing key, nonce, policy, and approved model. The site must prevent replay in its own storage and check access on protected reads and writes.

## What is custom?

The authorization request includes `request_nonce`. The token endpoint accepts JSON and returns an OpenVoiceGate voice proof rather than a standard OAuth access token or OIDC ID token. Use the included SDK and reference application; an ordinary OIDC configuration is not sufficient.

## Profile and presentation

The verifier issues a site-specific subject. First visits and returning visits use the same outward flow. Names are optional, self-asserted labels. Hiding names preserves the recognized subject; it does not create a new identity.

## Expiry and retries

The current ceremony deadline is four minutes. An authorization code lasts at most 60 seconds and is single-use. After an ambiguous exchange failure, begin a new ceremony rather than blindly replaying a potentially spent code. Uncertain matching can request up to three attempts and must not fall through to a new account.

## Standards background

The terminology comes from [OAuth’s authorization code grant](https://www.rfc-editor.org/rfc/rfc6749) and [PKCE](https://www.rfc-editor.org/rfc/rfc7636). [OAuth security guidance](https://www.rfc-editor.org/rfc/rfc9700) recommends S256 PKCE for this type of server-side client. These references explain the pattern; they do not certify this implementation.
