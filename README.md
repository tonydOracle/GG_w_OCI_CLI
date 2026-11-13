# OCI GoldenGate setup: SQL Server → OCI PostgreSQL

**0.3.0 — experimental execution release.** The execution scripts are included,
in addition to shared configuration, discovery and schema planning. Configuration supplies database names, endpoints, table scope and OCI resources.
Unsupported selected objects block setup.

This release includes actual controllers for account/schema preparation,
creating two private deployments, creating/assigning/testing database and WSS
connections, GLOBALS and source restart, table logging/cleanup, finite initial
snapshot, precise CDC positioning, transport/load, full-value comparison, CDC
startup, health observation and exact OCI create reconciliation.

**Offline tested, not yet live acceptance-tested as a generic installer.**
Use a fresh disposable test installation first. Keep the execution
commands separate from existing working replication deployments.
Computed/special types are blocked until an exact adapter exists; this release
is not a claim that every SQL Server schema or workload is supported.

## Included capabilities

| Command | Purpose |
|---|---|
| init / validate | One strict, secret-free environment configuration |
| fetch-ca / doctor | OCI public CA retrieval and local prerequisites |
| inspect / plan | SQL/OCI metadata and explicit supported schema/mapping plan |
| execution-template / execution-plan | Secret-ID execution settings and immutable reviewed plan |
| execute-stage | Execute one ordered setup stage |
| execute-all | Execute through a chosen stage, retaining one in-memory credential session |
| execution-observe | Read recorded OCI/process state and pending operations |
| reconcile-resource | Resolve a pending OCI deployment/connection create through exact owned readback; no remote write |
| execution-health | Verify current runtime identity/lag, source capture prerequisites, target shape/privileges/TLS |

## First steps

From this extracted project directory on Oracle Linux 9:

```bash
python3 -m ggsetup init --environment demo --directory private/demo
python3 -m ggsetup validate --config private/demo/environment.json
python3 -m ggsetup fetch-ca --config private/demo/environment.json
python3 -m ggsetup doctor --config private/demo/environment.json
python3 -m ggsetup inspect --config private/demo/environment.json
```

Supply actual OCIDs, endpoints, database names and users. Fill required future
execution subnet settings **before** the first inspection binds configuration.
Use an existing trusted CA path instead of fetch-ca if appropriate. Database
passwords are prompted, never saved in configuration.

Then follow [discovery](docs/TUTORIAL.md) to produce a supported schema plan and
[the execution runbook](docs/EXECUTION.md) to compile/review/run execution.
**Do not skip that runbook**: execution changes databases and starts billable
OCI deployments. A successful planning command alone performs no such changes.

## Requirements and deliberate boundaries

- Python 3.10+; Oracle Linux 9; OCI CLI; ODBC sqlcmd/Driver 18; psql. Python uses
  the standard library only. No pip installation needed for `python3 -m ggsetup`.
- An existing OCI PostgreSQL DB system **and SQL database**.
- An existing private subnet/NSGs, routes/DNS/firewalls and IAM permissions.
- Four existing Vault password secret references and GoldenGate secret access.
  This release creates deployments/connections, **not network/IAM/Vault resources**.
- SQL Server and PostgreSQL administrator credentials for preparation; SQL login
  authentication for SQL Server; matching capture/apply passwords for provided
  Vault secrets. Console authentication is GOLDENGATE/basic over verified HTTPS.
- An isolated source SQL database without existing CDC consumers; no concurrent
  installers against the same source DB.
- Application writes and DDL paused through snapshot/load/verification/CDC start.
- Vendor support/build/edition review for the actual environment.

For the first live trial, use [the disposable lab](docs/LAB.md).

See [support](docs/SUPPORT.md), [implementation status](docs/IMPLEMENTATION.md),
[configuration](docs/CONFIGURATION.md), [validation](docs/VALIDATION.md) and
[GitHub publishing](docs/GITHUB.md). License remains undecided.

## Tests

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Mocks exercise all ordered stages and failure guards without cloud access. The
CA test requires openssl. Generated PostgreSQL account/DDL/grant/comparison SQL
was also exercised locally in a PostgreSQL 18 WASM engine. No generic live OCI
or SQL Server deployment was accessed during this release's development.
