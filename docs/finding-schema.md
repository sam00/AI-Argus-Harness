# Finding Schema

The canonical finding (see `ai_argus/schemas/finding.schema.json` and
`ai_argus/models.py`). A finding must contain all required fields to be promoted.

```json
{
  "finding_id": "FINDING-1a2b3c4d",
  "title": "Publicly accessible storage bucket: prod-customer-exports",
  "category": "data-exposure",
  "scanner": "aws",
  "stage": "S4",
  "severity": "critical",
  "confidence": "high",
  "risk_score": 16.0,
  "score_breakdown": { "exposure": 4.0, "privilege": 0.0, "...": 0.0 },
  "asset": {
    "id": "asset-…", "type": "cloud", "name": "prod-customer-exports",
    "environment": "prod", "owner": "Cloud Security"
  },
  "evidence": [
    { "source": "cloud-api", "detail": "Bucket grants public access.",
      "confidence": "high", "timestamp": "…", "raw_ref": "ev-…" }
  ],
  "identity_path": [
    { "principal": "anonymous-internet", "permission": "s3:GetObject",
      "target": "prod-customer-exports", "relationship": "can-read" }
  ],
  "impact": {
    "business": "Potential sensitive data exposure from production storage.",
    "technical": "Object storage readable by anonymous principals.",
    "blast_radius": "all objects in bucket"
  },
  "remediation": {
    "summary": "Remove public access and enforce least privilege.",
    "steps": ["Block public access", "Audit bucket policy/ACLs", "Enable access logging"],
    "priority": "critical"
  },
  "owner": { "team": "Cloud Security", "service": "prod-customer-exports", "contact": "" },
  "detection_gap": true,
  "chain_ids": ["CHAIN-…"],
  "dedup_key": "…",
  "review_status": "auto"
}
```

## Required fields (completeness gate)

`asset`, `evidence` (≥1, source-bound), `impact`, `remediation`, `owner`,
`confidence`, and — for `high`/`critical` — `identity_path`.

## Risk score

```
Risk = Exposure + Privilege + Exploitability + IdentityPathStrength
     + DataSensitivity + BusinessCriticality + Chainability + DetectionGap
     + ControlWeakness + Confidence − CompensatingControls
```

Severity is then derived from the score plus qualitative signals (internet
exposure + privileged path + sensitive data + weak detection ⇒ critical).
