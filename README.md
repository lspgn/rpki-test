# RPKI Validator Comparisons

This project runs daily RPKI validation with multiple relying-party validators and publishes the results to GitHub Pages.

It keeps each validator's raw JSON output, normalizes shared payloads into a common shape, and builds a static dashboard for comparing validators and versions.

## Validators

The matrix is driven by `validators.yml`. Add another pinned version by adding another object to the `validators` list.

Each entry declares:

- `id`: stable artifact and dashboard identifier
- `validator`, `version`, `label`: display and grouping metadata
- `image`: container image pinned by digest
- `payloads`: supported payload classes
- `script`: command run inside the container with `/out` mounted as the result directory

The default entries enable all supported payloads:

- Routinator: ROA/VRP, BGPsec router keys, ASPA
- `rpki-client`: ROA/VRP, BGPsec router keys, ASPA/VAPs
- Fort: ROA/VRP and BGPsec router keys; ASPA is marked unsupported for the pinned version

## GitHub Pages

The workflow publishes:

- `data/manifest.json`: retained run history
- `data/latest.json`: latest run summary
- `data/runs/<run-id>/summary.json`: per-run summary and comparisons
- `data/runs/<run-id>/<validator-id>/normalized.json`: common payload schema
- `data/runs/<run-id>/<validator-id>/raw/*.json.gz`: compressed native validator output
- logs and status metadata for every validator/version

History is retained as long as the generated Pages site stays below the configured size cap. The workflow defaults to `996147200` bytes, leaving headroom under GitHub Pages' 1 GB published-site limit.

## Local Tests

Run the fixture test suite:

```sh
python3 -m unittest
```

Build a fixture-only site through the tests without fetching live RPKI data:

```sh
python3 -m unittest tests.test_project.AggregateTests
```

## Operations

The workflow can be started manually with `workflow_dispatch` or by the daily schedule at `02:17 America/Los_Angeles`.

Before relying on Pages deployment, configure the repository's Pages source to GitHub Actions in the repository settings.
