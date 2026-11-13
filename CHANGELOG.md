# Changelog

## 0.3.0 — experimental execution included

Added real staged execution commands for the supported schema subset, including
account/schema preparation, private deployments/connections, capture settings,
logging/cleanup, initial snapshot, CDC handoff, load, verification and startup.
Added read-only observation/health and exact OCI create reconciliation. Network,
IAM, Vault secrets and SQL databases remain existing prerequisites. Computed and
other unsupported adapters remain explicit blockers. Generic live acceptance is
pending; do not use the current working deployment as a test target.

## 0.2.0 — foundation

Configuration, discovery, schema planning, explicit feature gates, state journal
and offline tests. No execution adapters in that earlier version.
