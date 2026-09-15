# OpenVoiceGate v0

## Purpose and delivery
A small integration kit and public site for experimental voice entry in independent chats and forums. One entry action leads to hosted voice verification, an optional shared name and a site session. Cloudflare serves the public site; the verifier runs separately on a CPU host.

## Scope and invariants
Treat this as a proof of concept. Never claim proven human presence, dependable ban-evasion prevention or drop-in OAuth/OIDC conformity. Keep client credentials on the server. Check sessions and moderation before protected content or writes; browser UI alone is not an access gate. No recordings, templates, credentials, private research or internal review transcripts belong in this repository.

## Design context
Audience: small independent chat/forum operators and their visitors. Warm white, graphite and green; restrained Apple-inspired typography and spacing. Preserve the established seed 52097633 and one clear primary action per step.

## Layout and workflow
`site/` contains the public Cloudflare site. `packages/node/` contains the integration helper; `examples/` contains a complete relying application. `docs/` contains public contracts and operations guidance. These paths are being prepared; verified commands will be recorded in README.

Use topic branches after bootstrap and reviewed PRs into main. The existing private project tracker remains authoritative during v0 preparation; do not initialize a competing tracker. Public feature priorities live in ROADMAP.md. Release notes must distinguish source inspection, synthetic checks, live HTTP behavior and actual human validation.
