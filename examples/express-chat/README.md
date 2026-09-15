# Express page gate and moderation example

This example protects `/chat` with a local session and a current server-to-server moderation check. The browser records on the verifier's origin. The site receives a one-use authorization code, verifies the exchanged proof, and stores the encrypted moderation receipt on its server.

Requires Node **22.13 or later** and an approved client registration from the operator of a hosted verifier. The verifier is operated separately and is not included in this repository. The example explicitly accepts experimental, provisional voice matching. It does not establish human presence or prevent generated messages.

## Connect to an existing verifier

From the repository root:

```sh
npm ci --prefix examples/express-chat --ignore-scripts
cp examples/express-chat/.env.example examples/express-chat/.env
```

Fill the environment file with values from the verifier operator. Register exactly `SITE_ORIGIN/callback`; the issuer and site need **different hostnames**, not merely different ports. `OVG_KID` and `OVG_MODEL` must identify the operator-approved signing key and speaker model. The server pins them; it does not adopt key or model changes automatically.

```sh
node --env-file=examples/express-chat/.env examples/express-chat/server.mjs
```

Open `http://127.0.0.1:8022` for the default local site. For deployment, set `SITE_ORIGIN` to its HTTPS origin, `SITE_BIND_HOST=0.0.0.0` and the platform's `PORT`. Keep a persistent, access-restricted `SITE_DATABASE` path. The database holds sessions and encrypted moderation receipts; never serve it as a static file.

Both moderation registration flags can remain **false**. They control optional cross-site advice, not the site's own ban checks or ledger.

## Moderate a known site user

Set `SITE_ADMIN_TOKEN` to a random 32-byte base64url value to enable `/admin/moderation`. Keep it on the server. Without it, that route returns 404.

An authorized site administrator supplies a known subject from this site's `users` table. The server retrieves its saved receipt; the caller cannot provide a replacement receipt or an arbitrary voice sample.

```sh
curl --fail-with-body "$SITE_ORIGIN/admin/moderation" \
  --header "Authorization: Bearer $SITE_ADMIN_TOKEN" \
  --json '{"subject":"v1_REPLACE_WITH_KNOWN_LOCAL_SUBJECT","action":"ban","reason_category":"spam","idempotency_key":"moderation-action-001"}'
```

Use `action:"unban"` with a new idempotency key to reverse a ban. For that user's history, send only `subject` and `action:"ledger"`. Full contracts and lifetime limits are in [moderation.md](../../docs/moderation.md).

## What the example verifies

The callback validates state, issuer, nonce, model, proof signature and receipt lifetime before a transaction consumes the pending request and proof, upserts the user, saves the receipt and creates a session. Replays fail. Chat reads and writes check current moderation; a failed check returns 503 and grants no access. Site-local session state is checked again after the network call. CSRF protects chat writes and logout.

A remote check and a local write are not a distributed transaction: a concurrent ban can race the check. This example performs the check immediately before each action, with no decision cache. Optional cross-site advice never automatically blocks a user here.

```sh
node --test packages/node/test.mjs examples/express-chat/test.mjs
```

These tests use scripted HTTP responses and temporary databases. They check protocol and session behavior, not real microphone performance.
