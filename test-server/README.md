# ESDK TestServer integration (aws-crypto-tools-java Language_Repository)

This directory wires the live ESDK Java source into the cross-language
TestServer. It does **not** embed the TestServer; instead it clones the
`Commons_Repository` fresh at a branch head on every run and orchestrates the
TestServer against this repo's working tree as the live Java source.

## `commons-source.json` — the single source of truth for commons coordinates

`commons-source.json` is the **Commons_Source_Config** (Requirement 8.2): the
one place in this Language_Repository that names the `Commons_Repository`
coordinates — its `name`, repository `url`, and the `branch` to clone at head:

```json
{
  "commonsRepository": {
    "name": "aws-crypto-tools-commons",
    "url": "git@github.com:aws/aws-crypto-tools-commons.git",
    "branch": "kessplas/esdk-test-server"
  }
}
```

Both the [`Makefile`](./Makefile) and the CI workflow
[`.github/workflows/esdk-test-server.yml`](../../.github/workflows/esdk-test-server.yml)
**read** these coordinates from this file (parsed with `python3` — no `jq`
dependency) rather than carrying their own hardcoded defaults, so the two never
drift apart.

- The Makefile exposes `COMMONS_REPO` / `COMMONS_BRANCH` whose **defaults** come
  from this file; both stay overridable on the command line
  (`make run COMMONS_BRANCH=some-branch`).
- The CI workflow resolves the branch from this file, unless a non-empty
  `commons_branch` `workflow_dispatch`/`workflow_call` input overrides it.
- If this file is missing or unparseable, both fail fast with an error naming
  it — it is the single source of truth, so its absence is a hard error.

### Branch default note

The design default for `branch` is `main`. Until the ESDK TestServer merges to
commons `main`, this file pins the `kessplas/esdk-test-server` feature branch so
the flow works out of the box. **Once the TestServer merges to commons `main`,
flip `branch` back to `main` here** — no other file needs to change.

## Common targets

Run `make help` for the full list and the resolved commons coordinates.
