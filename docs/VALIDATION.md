# Validation of 0.3.0

85 offline tests pass. This includes the original configuration/discovery/type/
scope/state/credential/CA tests plus:

- Simulated full ordered execution through accounts, schema, deployments,
  connections, GLOBALS restart, logging/cleanup, finite snapshot, retained-LSN
  handoff, initial delivery, whole-value comparison and CDC startup/health.
- Review-hash/write-pause/stage-order checks before mutations.
- No repeated start after completion, no retry after unknown outcome, payload
  drift rejection, exact owned OCI resource reconciliation.
- Changed process identity, CDC retention gaps, target row differences and
  unsupported execution types.
- Correct WSS/dirdat requests, omitted incompatible parameters, Vault secret-ID
  modes, private request files, CLI retry suppression and no HTTP redirect of
  console credentials.
- Target input trails accepted as intended input rather than mistaken for a
  replay; fresh source output collision checks remain enforced.
- Password confirmation before intent creation; rejection of SQL type injection;
  installed transaction-begin LSN schema semantics; malformed Unicode/NUL rejection.
- Apply-owner checkpoint comment credentials and readonly/writable client scopes.

Separately, generated PostgreSQL account/schema/grant SQL, role restrictions,
apply-owned checkpoint/comment operations and comparison query output passed
in a local PostgreSQL 18 WASM engine. This is actual PostgreSQL SQL validation,
not a managed-service/ODBC/GoldenGate transport run.

No live OCI deployment, SQL Server instance or managed PostgreSQL instance was
accessed during this development. SQL Server DDL/capture settings, current OCI
request behavior, private connectivity, asynchronous timing and installed-build
runtime responses still need live acceptance. There is no claim of universal
SQL Server feature support, production readiness or continuous end-to-end proof.
