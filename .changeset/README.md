# Changesets

Version bumps and changelogs, from a note per change rather than from a human remembering.

Add one when you change a published package — `gatecrash-client` or `gatecrash-ui`:

```sh
pnpm changeset
```

Pick the packages, pick `patch`, `minor` or `major`, and write what changed **for somebody
using it**. That text becomes the changelog entry, so "fixed the thing" is a note nobody can act
on a year later; "a retry with the same scan id no longer returns ALREADY_USED" is.

The release workflow runs `changeset publish` on a tag, which is why a release with no changesets
publishes nothing rather than burning a version number.

Nothing else in the repository needs one. The box is a Go binary released by tag, and the three
apps are private and embedded in it.
