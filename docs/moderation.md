# Moderation after voice entry

A site can check and moderate a person who has completed its hosted voice-entry flow. It cannot upload an arbitrary voice, search for people, or browse another site's ban list.

The authorization-code exchange returns `moderation_receipt` and `moderation_receipt_expires_at`. The opaque `mr1.…` receipt is an encrypted, authenticated reference to the profile the verifier resolved. It is bound to the issuing verifier, registered client and site audience. It contains no raw recording or embedding, and it is neither a biometric hash nor a login token. The site stores it server-side alongside its own subject. Possessing it is insufficient without the matching client's credentials.

Receipts contain sensitive linkage information even though their contents are encrypted. Keep them out of browser storage, URLs, analytics and logs. The [Express example](../examples/express-chat/README.md) stores them in its access-restricted database.

## Check before protected actions

Every moderation route is a JSON POST authenticated with the same HTTP Basic client credentials used for authorization-code exchange.

```js
import {createModerationClient} from './packages/node/index.mjs';

const moderation = createModerationClient({issuer, clientId, clientSecret});
const decision = await moderation.check(savedReceipt);
if (decision.banned) {
  // Deny this site's protected action.
}
// A failed or unavailable check must also deny the protected action.
```

`POST /v1/moderation/check` accepts only:

```json
{"receipt":"mr1.…"}
```

The normal response is:

```json
{"banned":false,"expires_at":null,"reputation":{"checked":false}}
```

An active own-site ban returns `banned:true` and its integer Unix expiry. The verifier also checks that ban before hosted preview, completion and code exchange. Existing relying-site sessions still need a fresh check before protected actions; the verifier cannot revoke a site's cookie by itself. A check and a site's later database write are separate operations, so simultaneous moderation can race the boundary.

## Ban or unban the matched user

`POST /v1/moderation/events` accepts:

```json
{
  "receipt":"mr1.…",
  "action":"ban",
  "reason_category":"spam",
  "idempotency_key":"site-operation-001"
}
```

`action` is `ban` or `unban`. Categories are `spam`, `harassment`, `fraud`, `other`. A ban's optional integer `expires_at` defaults to 30 days, capped by receipt expiry; an explicit expiry must be in the future and within both 180 days and receipt expiry. Omit expiry on unban. Reversing an already inactive ban with a new key returns `409 no_active_ban`.

The idempotency key is 16–128 letters, digits, underscores or hyphens. Repeating the same request and key returns the original event; changing that request returns 409. Keep the same key when retrying an ambiguous event submission. Code exchange itself must not be automatically retried.

An accepted event returns its random `event_id`, action, category, creation time and expiry inside `{"event":…}`. Event details are encrypted at rest. This changes only this registered client's own-site ban. It does not create a global sanction.

Server-side curl, with values loaded from your secret store:

```sh
curl --fail-with-body "$OVG_ISSUER/v1/moderation/check" \
  --user "$OVG_CLIENT_ID:$OVG_CLIENT_SECRET" \
  --json "{\"receipt\":\"$OVG_MODERATION_RECEIPT\"}"
```

For the complete site's administrator-facing ban/unban wrapper, see the [example commands](../examples/express-chat/README.md#moderate-a-known-site-user). The site administrator uses that site's token, not a verifier-wide administrator key.

## Read only your own history

`POST /v1/moderation/ledger` accepts `receipt` and optional `limit` (1–100, default 20). It returns the newest own-client events for that profile and `has_more`. There is no list-all endpoint, person search, cross-site event history or arbitrary subject parameter. The response is bounded; v0 does not provide a pagination cursor for older history.

Each client has a 10,000-event bound; the verifier has a 100,000-event bound. Half the ledger capacity is reserved for reversals. Further bans can return 503 at the admission bound, while existing checks continue. Expired ledger entries are cleaned up after at most 180 days; deleting the profile cascades to its associated moderation records.

## Optional advice from other participating sites

The verifier operator may register the exact optional field:

```json
"moderation": {"consume": true, "contribute": false}
```

Both flags default false. **Own-site checks, bans, unbans and ledger access work with both false.**

- `consume` permits a boolean advisory check against other currently registered, contributing sites in this verifier's realm.
- `contribute` permits an own-site ban created using a contribution-authorized receipt to inform that advisory check.

When either flag is enabled, the hosted consent screen explains this before the user agrees. Permissions are captured when that authorization starts and cannot be added retroactively to an older receipt. The relevant permission must also remain enabled in the current registration. Unsupported tenancy configurations leave this feature off.

An authorized consumer receives only:

```json
{"checked":true,"flagged":true}
```

This is the `reputation` field of `/check`, separate from `banned`. It includes no site names, counts, subjects or reasons. The advice does not automatically deny entry. It is a limited within-verifier feature, not federation or a guarantee of abusive behavior. A site's decisions can be wrong; the contributing site can reverse its own ban.

## Expiry, deletion and limits

Receipts last at most 180 days and never beyond their profile's expiry. Ban lifetimes cannot outlive the receipt used to create them. Deleting or expiring the profile invalidates its receipts and removes this matching-based moderation continuity. A different voice match or a false non-match can evade continuity; v0 does not guarantee one-person-one-account or permanent bans.

Unknown profiles, expired/forged receipts and receipts issued to another client fail closed. Extra query fields such as a subject, site or embedding are rejected. Unavailable checks are not equivalent to “not banned.” No successful check proves a person is human or that their messages are human-written.
