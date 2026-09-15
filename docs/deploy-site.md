# Deploy the public site

The `site/` folder is plain HTML/CSS. Cloudflare Pages serves it without a build step, environment secrets, backend functions, or access to voice data. The voice-entry button opens the separate HTTPS verifier.

After reviewing the changes, from the repository root with a Cloudflare account authorized for Pages:

```sh
wrangler pages deploy site --project-name=openvoicegate-v0 --branch=main
```

For your own copy, create a Pages project first with `wrangler pages project create YOUR-PROJECT --production-branch main`, then use that project name. Upload only `site/`. Do not upload environment files, integration databases, or the private verifier.

Check the landing page, Quickstart, Journal, and live-demo link on the resulting HTTPS URL. The deployment command prints the deployment-specific URL. Pages also maintains the production project URL.

Content is hand-authored. Edit `site/` HTML to change the deployed copy, and keep related Markdown under `docs/` consistent. The site has no microphone permission; recording occurs only on the verifier origin.
