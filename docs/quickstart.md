# Gate your first page

A complete server-side example, from an entry button to a protected chat.

**You need a registered client.** You can try the public chat demo without registering a client. Integrating your own site requires credentials and an exact callback registration from the verifier operator. Registration is currently operator-managed, not instant self-service.

## 1. Get the integration kit

Use Node.js 22.13 or newer. The example uses Express and Node’s built-in SQLite module. Run from the repository root:

```sh
git clone https://github.com/apollostreetcompany/openvoicegate-v0.git
cd openvoicegate-v0
npm ci --prefix examples/express-chat --ignore-scripts
```

## 2. Register your site

For the local example, ask the verifier operator to register `http://127.0.0.1:8022` as the site origin and `http://127.0.0.1:8022/callback` as the exact callback. You need an approved issuer origin, client ID, client secret, signing-key ID, and model ID. HTTPS is required for non-loopback sites.

Keep the client secret on your server. The verifier and relying site must use different hostnames; two ports on one hostname do not isolate cookies.

## 3. Configure the example

Create an untracked, private environment file. Fill these values with operator-issued settings. These placeholders are not usable credentials:

```sh
OVG_ISSUER=https://your-approved-issuer.example
SITE_ORIGIN=http://127.0.0.1:8022
OVG_CLIENT_ID=your-registered-client-id
OVG_CLIENT_SECRET=your-server-only-secret
OVG_KID=your-approved-signing-key-id
OVG_MODEL=your-approved-model-id
SITE_DATABASE=/absolute/private/path/chat.sqlite3
```

The database keeps users, pending entry requests, sessions, and messages. Keep it outside the source repository. Follow the [example README](https://github.com/apollostreetcompany/openvoicegate-v0/tree/main/examples/express-chat) for the exact configuration supported by this release.

## 4. Start the complete flow

```sh
node --env-file=/absolute/private/path/rp.env examples/express-chat/server.mjs
```

Open `http://127.0.0.1:8022`. Select Enter Chat, complete the phrase on the verifier’s page, choose what name to share, and return to chat. Sign out and repeat. This example deliberately opts into experimental calibration; successful execution is not a guarantee of accurate identification.

## 5. Protect content on your server

The [runnable server](https://github.com/apollostreetcompany/openvoicegate-v0/blob/main/examples/express-chat/server.mjs) wires `requireVoiceGateCallback` from `packages/node/index.mjs` into `GET /callback`. It validates browser-bound state, exchanges the one-use code, verifies the result, and asks the site’s database to atomically consume the pending request and create a session.

Start from the complete example. The helper needs application-owned pending storage and an atomic redemption callback; pasting a button or verifying a signature alone does not protect a page. Check the session and applicable moderation before returning protected content and before accepting each write.

## 6. Run the integration checks

```sh
node --test packages/node/test.mjs
node --test examples/express-chat/test.mjs
```

These are automated protocol and application checks, not human voice validation. Test your actual HTTPS origins, callback, sign-out, expired sessions, and denied entry before inviting visitors.

Next: [protocol](protocol.md), [client moderation](moderation.md), and [limitations](limitations.md).
