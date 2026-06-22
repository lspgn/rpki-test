# RPKI Validator Comparisons

This project runs daily RPKI validation with multiple relying-party validators and publishes the results to GitHub Pages.

It keeps each validator's compressed raw JSON output, normalizes shared payloads into a common shape, records a lightweight cache/TAL file inventory, and builds a static dashboard for comparing validators and versions.

## Validators

The matrix is driven by `validators.yml`. Add another pinned version by adding another object to the `validators` list.

Each entry declares:

- `id`: stable artifact and dashboard identifier
- `validator`, `version`, `label`: display and grouping metadata
- `image`: container image pinned by digest
- `threads`: validator worker thread count exposed as `RPKI_VALIDATOR_THREADS`
- `payloads`: supported payload classes
- `script`: command run inside the container with `/out` mounted as the result directory

The default entries enable all supported payloads:

- Routinator: ROA/VRP, BGPsec router keys, ASPA
- `rpki-client`: ROA/VRP, BGPsec router keys, ASPA/VAPs
- Fort: ROA/VRP and BGPsec router keys; ASPA is marked unsupported for the pinned version

## GitHub Pages

The workflow publishes only the latest run for now:

- `data/manifest.json`: latest run manifest
- `data/latest.json`: latest run summary
- `data/runs/<run-id>/summary.json`: per-run summary and comparisons
- `data/runs/<run-id>/<validator-id>/normalized.json`: common payload schema
- `data/runs/<run-id>/<validator-id>/raw/*.json.gz`: compressed native validator output
- `data/runs/<run-id>/<validator-id>/cache-tree.json`: cache and TAL file inventory with size and SHA-256 hashes
- `data/runs/<run-id>/reports/<payload>.json`: object presence report showing which eligible validators saw each normalized object
- logs and status metadata for every validator/version
- `resource-usage.json`, `docker-stats.jsonl`, `log-events.json`, and `timeline.json` for CPU, RAM, PID, log, DNS, and network-flow observability

History retention is disabled while the artifact set is kept lightweight. Raw validator output is published only as `.json.gz`; uncompressed duplicates and cache tarballs are not uploaded.

## Observability

Each validator run samples `docker stats` and calculates peak RAM, peak CPU cores, mean CPU cores, and mean network throughput. The dashboard shows the peak CPU/RAM values per validator and a selectable 10 second timeline with resource graphs, stdout/stderr annotations, DNS queries, and network flows.

See `docs/observability.md` for the optional privileged eBPF workflow covering DNS capture, per-IP/port throughput, syscall counts, and allocation tracing.

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
