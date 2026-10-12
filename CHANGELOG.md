# Changelog

What changed for whoever runs `ponsd`, calls its API, or builds on the
public packages, one section per release. A `v*` tag without a section
here is refused before it is pushed.

## Unreleased

- Added: the server, `ponsd`, with three commands: `serve`, `check` and
  `version`. It is configured by its environment, every variable named
  `PONS_*`.
