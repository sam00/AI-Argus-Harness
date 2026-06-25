# demo-target (intentionally vulnerable, synthetic)

This directory is a **synthetic, intentionally insecure** sample used to
demonstrate AI-Argus-Harness. Everything here is fake:

- The "secrets" are well-known **example** values (e.g. AWS's documented
  `AKIAIOSFODNN7EXAMPLE`) or random non-functional strings.
- The dependency typo (`reqests`) demonstrates typosquat detection.

> ⚠️ Nothing in this folder is a real credential and nothing connects to a real
> system. Do **not** add real secrets here.

## Try it

```bash
argus scan ./examples/demo-target --offline --no-auth-scan \
  --path ./examples/demo-target --inventory examples/inventory.json
```

Pair it with the inventory snapshot (`examples/inventory.json`) to also exercise
the cloud / identity / Kubernetes / SaaS policy checks.
