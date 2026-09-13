# Releasing

A GitHub Release is published from the reviewed version section committed to
`CHANGELOG.md`. [git-cliff](https://git-cliff.org) supplies a local draft; it
never decides the final release notes, and the release workflow never writes
back to the repository.

## Prepare the release

Start on an up-to-date `main` with no uncommitted work:

```sh
git switch main
git pull --ff-only origin main
git status --short
```

Choose a new valid tag in the form `vX.Y.Z` (optionally with a SemVer prerelease
or build suffix) and make sure it does not already exist:

```sh
VERSION=vX.Y.Z
git fetch origin --tags
git tag -l "$VERSION"
```

Stop if the final command prints the proposed tag. Do not move, reuse, or
force-push an existing release tag.

Generate the changelog draft:

```sh
make changelog VERSION="$VERSION"
```

That command changes `CHANGELOG.md` and refuses to add a duplicate version. It
uses Conventional Commit history as a starting point only. Curate the generated
section before continuing:

- describe the final public behaviour, not an intermediate refactor that a
  later commit replaced;
- group and remove entries as needed, and add the migration or safety context
  that a commit subject cannot express;
- preserve the generated top-level heading. Its displayed version and GitHub
  tag URL must match `VERSION` exactly.

Before v1.0.0, the project makes no compatibility or migration guarantees; see
[DESIGN.md](DESIGN.md#compatibility). That does not remove the need to document
material breaking changes accurately in the curated release notes.

## Preview and verify

Preview the exact Markdown body the release workflow will publish:

```sh
make release-notes VERSION="$VERSION"
```

The command intentionally omits the version heading because GitHub renders the
tag as the release title. It fails when `CHANGELOG.md` does not contain exactly
one nonempty section with the canonical heading for the proposed tag. Treat a
failure as a changelog error; do not tag until it is fixed.

Run the complete local release gate and commit the reviewed entry:

```sh
make check
git add CHANGELOG.md
git commit -m "docs: curate $VERSION changelog"
git push origin main
```

Wait for CI on `main` to pass. Check the actual diff before committing: the
changelog is the source of truth for the GitHub Release body.

## Tag and publish

Create an annotated tag on the verified `main` commit, then push it:

```sh
git tag -a "$VERSION" -m "$VERSION"
git push origin "$VERSION"
```

The tag-triggered **Release** workflow first validates the curated section,
runs `make check`, extracts the same section body with `make release-notes`,
and creates the GitHub Release. It writes only a temporary file on the runner:
it does not regenerate the changelog, make a commit, or push anything to the
repository.

After the workflow is green, inspect the GitHub Release page for the expected
tag and Markdown. If the workflow fails, investigate it before considering a
new release version; do not repair a published release by moving its tag.

## Commit titles and draft quality

`git-cliff` builds its draft from Conventional Commit subjects. The CI job checks
pull-request titles because a squash merge uses the pull-request title as its
commit subject. Use one of these types:

```text
feat fix perf refactor docs test ci build chore style revert
```

Use `!` after the type or scope, or a `BREAKING CHANGE:` footer, for an
incompatible change. The draft deliberately filters most internal
`style`, `refactor`, `test`, `ci`, `build`, and `chore` commits, but breaking
changes are retained. This keeps the draft useful without making it a substitute
for human review.

Prefer squash merges when a pull request should be one release-note unit. A
rebase merge is appropriate only when its individual commits are independently
meaningful release-note units. Avoid merge commits: their generic subjects make
the draft less useful.
