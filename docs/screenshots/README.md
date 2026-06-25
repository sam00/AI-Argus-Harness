# Screenshots

Drop PNG/GIF captures here and reference them from the top-level `README.md`.

Recommended captures (security users value these most):

| File | What to capture |
| --- | --- |
| `scan-summary.png` | Terminal after `argus scan ... --offline` (the severity summary + top findings). |
| `graph.png` | `argus graph` / `argus identity` attack-path output. |
| `explain.png` | `argus explain <finding-id>` showing evidence + identity path. |
| `sarif-codescanning.png` | The `report.sarif` imported into GitHub code scanning. |
| `demo.gif` | A short asciinema/terminal recording of a full offline run. |

## Generate the summary capture quickly

```bash
argus scan ./examples/demo-target --offline --no-auth-scan \
  --path ./examples/demo-target --inventory examples/inventory.json
```

Then screenshot the terminal, or record a GIF with
[`asciinema`](https://asciinema.org/) + [`agg`](https://github.com/asciinema/agg):

```bash
asciinema rec demo.cast -c "argus scan ./examples/demo-target --offline --no-auth-scan --path ./examples/demo-target --inventory examples/inventory.json"
agg demo.cast demo.gif
```

> A vector version of the architecture diagram is at
> [`docs/architecture.svg`](../architecture.svg) and renders inline on GitHub.
