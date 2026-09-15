# Know the edges.

A working experiment, with the unknowns left visible.

## This is a proof of concept

OpenVoiceGate is experimental voice-profile matching. Human presence, resistance to impersonation, dependable ban-evasion prevention, and one-person-one-account uniqueness are not established. Synthetic voices have passed. The microphone spectrum is visual feedback, not a human detector.

## Device support

One human desktop test completed first entry and a return from a private browser. An iPhone recording reached speech recognition but failed the phrase check. Successful real iPhone and Android entry and cross-device recognition remain unverified. Automated Chromium/WebKit checks and mobile-sized screenshots do not establish real-phone microphone performance.

You need HTTPS or localhost, microphone permission, AudioWorklet support, and a foreground page. App switching, hiding the tab, or audio interruption can stop capture. The client resamples device audio before upload.

## Matching makes mistakes

A returning person can be missed; different people can be confused. Uncertain matches request more evidence instead of creating an account. After three unresolved attempts, the demo has no alternative entry path. It is not an authenticator for valuable accounts.

## Privacy is a tradeoff

Audio is sent to the hosted verifier, which stores an encrypted biometric template. This is not on-device-only verification. The verifier can link visits; participating sites receive site-specific identifiers. Playable audio is not retained by default and requires separate consent when enabled.

Hiding a name does not erase a stable subject or previously posted messages. Template deletion removes future voice matching for that profile. Active ban-template retention, if enabled, is disclosed separately in the verifier’s consent screen.

## Entry is not authorship

Someone who signs in can still use an LLM or automate messages. Community rules, reporting, rate limits, and moderation remain necessary.

## Release and test scope

The public repository contains the site, integration helper, and reference application. The hosted verifier is a separate service; its source and self-hosting are not part of this release. Automated SDK/application checks establish their exercised paths, not biometric accuracy or universal browser support.

See the [v1 roadmap](../ROADMAP.md) for the next improvements.
