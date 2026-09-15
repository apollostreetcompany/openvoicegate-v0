# OpenVoiceGate

Experimental voice entry for independent chats and forums. Read a fresh phrase, choose an optional name, and enter under a site-specific identity. The goal is fewer throwaway accounts; reliable human verification and ban-evasion prevention are not established.

[Try the live demo](https://openvoicegate.onrender.com/) · [Quickstart](docs/quickstart.md) · [Protocol](docs/protocol.md) · [Moderation](docs/moderation.md) · [Roadmap](ROADMAP.md)

## What is in this release?

- `site/`: public static site, documentation pages, and an introductory post.
- `packages/node/`: server-side integration helper.
- `examples/express-chat/`: a complete relying application with pending-request storage and sessions.
- `docs/`: public integration contracts, capacity, and limitations.

The hosted voice verifier is a separate service. This repository does not currently include its source or a self-hosted verifier package. Do not put client secrets, recordings, biometric templates, or databases in this repository.

## Gate your first page

Use Node.js 22.13 or later. Get a registered client and approved issuer/key/model settings from the verifier operator, then follow the [step-by-step quickstart](docs/quickstart.md) and [runnable Express example](examples/express-chat/README.md).

```sh
npm ci --prefix examples/express-chat --ignore-scripts
node --env-file=/absolute/private/path/rp.env examples/express-chat/server.mjs
```

The environment file must contain your real registered-client configuration; it is not supplied by the command. Client registration is currently operator-managed. A browser button alone does not gate content: your server must check sessions and moderation before protected reads and writes.

## Integration and validation

The exchange is **OAuth-style authorization code with S256 PKCE**, using a custom OpenVoiceGate protocol. It is not a drop-in OAuth/OIDC provider. Start with the complete example, which uses the helper and application-owned transactional storage.

```sh
node --test packages/node/test.mjs
node --test examples/express-chat/test.mjs
```

These commands check the SDK/application paths covered by their tests. They do not establish human presence, biometric accuracy, real-device support, or deployed integration acceptance. See [limitations](docs/limitations.md) and [capacity](docs/capacity.md).

## Preview the public site

```sh
python3 -m http.server 8080 --bind 127.0.0.1 --directory site
```

Open http://127.0.0.1:8080. The site is static and makes no microphone request; its primary link opens the separate live demo. Cloudflare can publish `site/` as static assets. Publishing this folder does not host voice inference.
