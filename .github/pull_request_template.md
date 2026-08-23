<!--
Keep this short. What changed, and why.

If it touches the redemption engine, the audit chain or the mesh protocol, say what
you ran: `gatecrash-sim event -seeds 500` is the check that matters, and a seed that
fails is worth more than a paragraph of description.
-->

## What this changes

## Why

## What you ran

<!--
  go test ./...
  gatecrash-sim event -seeds 500
  gatecrash-sim crowd -sweep
  pnpm -r test
-->

---

- [ ] `go test ./...` and `pnpm -r test` pass
- [ ] A comment explains anything a reader would otherwise have to guess at
- [ ] A changeset if this changes a published package (`pnpm changeset`)
