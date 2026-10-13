## What this changes

<!-- What behavior is different after this, for whoever runs ponsd, writes a catalog, calls the API, or writes an authorizer. -->

## Why

<!-- The problem it solves. Link the issue if there is one. -->

## Checklist

- [ ] `make` passes locally.
- [ ] A bug fix carries a test that fails without it.
- [ ] No route, record, log line, error or test fixture carries a
      credential's value, and a new route is exercised by the test that
      searches every output for a planted one.
- [ ] Every new outbound request goes through `internal/dial`.
- [ ] A change to the API, the catalog format, a configuration variable,
      or the authorizer's vocabulary or limits is reflected in its spec,
      in `docs/`, and in `api/openapi.yaml` where it applies.
- [ ] A change a person running `ponsd` would notice has a line under
      `## Unreleased` in `CHANGELOG.md`.
