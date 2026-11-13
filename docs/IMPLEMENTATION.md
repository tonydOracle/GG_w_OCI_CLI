# Implemented scope in 0.3.0

Execution code is included now; live metadata collection is not a prerequisite
for writing or testing these adapters. All stages can be inspected/tested offline.
Actual application requires reviewed inputs and live readiness checks.

Implemented modules:

- `config.py`, `discovery.py`, `planner.py`: shared configuration, OCI/SQL
  discovery, explicit metadata/type/feature gates, generated mappings/DDL.
- `execution_plan.py`: strict secret-ID settings, typed manifest validation,
  immutable execution compiler, account SQL and stopped pipeline definitions.
- `adapters.py`: OCI CLI with retry disabled, verified-TLS REST without redirects,
  SQL clients, hidden credentials, owner-session authentication before comments.
- `executor.py`: ordered account/schema/provision/connection/GLOBALS/logging/
  snapshot/CDC/load/verify/start stages, observation, health, OCI reconciliation.
- `verification.py`: full-row/column canonical comparison for the execution
  subset, with private temporary SQLite fingerprints and no row-value reports.
- `state.py`: private exclusive journal, fingerprint binding and durable intents.

The stages use configured names/identifiers and generated table/column mappings.
No old snapshot LSN, count, deployment URL or prior probe success is required.

Remaining acceptance and expansion work:

1. Live fresh-environment acceptance against actual source edition/build and OCI
   service, including asynchronous API shapes, credentials, source DDL and large
   datasets. Current simulation is necessary but not sufficient evidence.
2. Exact adapters for computed, spatial/CLR/alias/rowversion and other unsupported
   types; additional float and value-boundary comparison tests. Do not enable
   FETCH to bypass transaction-exactness requirements.
3. Optional bootstrap creation for network/IAM/Vault and destination SQL database;
   this release requires those objects/permissions already configured.
4. Broader typed reconciliation for uncertain SQL/REST/assignment outcomes and
   explicit planned pause/resume/restart adoption. These remain stopped-for-review,
   not silently retried or reset. Creation rejection retries are not automated.
5. Optional end-to-end heartbeat/alarms and performance/concurrent-write workload
   qualification. No scheduled monitoring or notification is installed.

The first supported initial-load mode requires paused application writes. It is
not an online-overlap/HANDLECOLLISIONS implementation. Unsupported selected tables
block the entire execution plan. The PostgreSQL destination remains a data mirror,
not a conversion of SQL Server application routines and behavior.
