# Small, on purpose.

Configured limits and historical latency, without turning them into promises.

## Designed for a small pilot

The current verifier runs one native verification at a time, with no inference queue. Busy requests receive HTTP 503 and retry guidance. The default directory holds up to 1,000 active profiles. These are configured bounds, not a claim that a thousand people can sign in at once.

| Control | Current default |
|---|---|
| Voice verification | One active attempt; busy responses request a retry after 3 seconds |
| HTTP concurrency | 32 under the runner; not simultaneous voice verification |
| Active profiles | 1,000; a full directory can recognize but cannot insert |
| Pending tickets / browser records | 128 / 1,024 |
| Entry / challenge / verify rates | Each bucket: 12/IP/minute and 60 globally/minute |
| Recording / demo session | 15–30 seconds / 15 minutes |

The example checks moderation before every protected chat read and write. Current moderation checks are limited to 30 per source IP per minute, 60 per registered client per minute, and 120 globally per minute. Visitors behind one relying server share its source-IP limit, so that server can reach 30 checks per minute across all visitors. When checks are unavailable or rate-limited, the example denies the action; these limits suit a small pilot.

## What has been measured?

An earlier synthetic local workload on an Apple M1 Max with 32 GiB RAM measured median server verification of approximately **0.75–0.85 seconds**, with p95 of **0.78–0.93 seconds**. That excludes the visitor’s recording. Runs used one, two, and four synthetic clients and ending directories of only one to three profiles.

Serial speech synthesis limited the load; this was not a saturation benchmark, public-host measurement, or human accuracy evaluation. No new benchmark is claimed for this release.

## What remains unknown?

Public-host throughput, sustained peak traffic, large-directory latency, and cost per completed entry are unmeasured. A static site serving quickly says nothing about inference capacity. Measure the actual deployment before planning a larger rollout.

## Hosting boundary

The public site is static. Voice verification runs on a separate CPU host with persistent identity storage. The existing deployment uses one web worker and one inference process; 2 GB RAM is a starting recommendation, not a guaranteed minimum. This public release does not provide a self-hosted verifier package.
