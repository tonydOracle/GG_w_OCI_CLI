# Step-by-step: collect and plan a different environment

## 1. Work separately from the existing replication

Extract `oci-gg-setup-0.3.0.zip` into a new folder, for example under
`/home/opc/ggsetup-development`. Do not extract over the original provisioning
scripts or copy original runtime state into this new project. Change into the
extracted `oci-gg-setup-0.3.0` directory. All commands below run from that directory.
There is no pip dependency installation step.

Use your existing OCI Linux login and CLI installation. Check `python3 --version`,
`oci --version`, `psql --version`, and `sqlcmd -?`. This implementation uses ODBC
sqlcmd flags; the Go implementation may behave differently.

## 2. Create one environment configuration

```bash
python3 -m ggsetup init --environment demo --directory private/demo
```

The wizard prompts for settings without database passwords. Supply your actual
OCI CLI config file and profile, authentication method, region, compartment
OCID, source endpoint/database/usernames, target DB system OCID and service
primary FQDN/port/database/usernames. The PostgreSQL **SQL database name** differs
from the OCI DB system display name. The destination database must already
exist for this release. Existing OCI and on-premises SQL Server sources both
work for metadata discovery; no compute OCID is required.

Use database inspection accounts that can read required catalogs. Source
VIEW DEFINITION is required for planning; server service/settings queries may
need additional privileges. Inspection accounts can differ from intended
capture/apply accounts, and inspection does not prove their privileges.

Choose a unique two-to-four-character uppercase GoldenGate prefix and distinct
credential alias names. Fill the private subnet OCID now if you intend to execute setup. Vault/key
and existing-deployment OCIDs may remain blank when using existing secrets and
creating new deployments. These discovery commands perform no provisioning. Source SQL Server certificate
verification defaults to enabled. The target always uses `verify-full`.

Alternatively generate an editable template:

```bash
python3 -m ggsetup init --environment demo --directory private/demo --template
```

Edit `private/demo/environment.json`, replace `REPLACE_ME` and `.example.invalid`
values, and review table scope before the first inspection. In selected mode,
use `["schema","table"]` pairs, not dotted names. Example:

```json
"scope": {
  "mode": "selected",
  "include_tables": [["sales", "Orders"], ["sales", "OrderLines"]],
  "exclude_tables": [],
  "exclude_schemas": ["ggschema", "cdc", "sys", "INFORMATION_SCHEMA"]
}
```

Schema names and identifiers preserve case. No tables are silently skipped for
unsupported columns. Explicit exclusions change scope and must be intentional.

## 3. Validate configuration and get the destination CA

```bash
python3 -m ggsetup validate --config private/demo/environment.json
python3 -m ggsetup fetch-ca --config private/demo/environment.json
python3 -m ggsetup doctor --config private/demo/environment.json
```

`validate` checks configuration structure only. `fetch-ca` reads the OCI DB
system and connection metadata, checks its ID/compartment/primary hostname/port,
parses its public CA with OpenSSL through Python, and saves a private local CA
file. It refuses overwriting an existing file. Certificate rotation requires
review; no `--force` replacement option is provided.

If using an existing CA file, put its path in `target.ca_file` and skip fetch-ca.
Relative CA paths resolve beside environment.json, independent of your shell's
current directory. `doctor` performs local prerequisite checks only; it does
not connect to databases or certify client versions.

If the wizard's endpoint differs from OCI's primary endpoint, correct config
before inspection. Optional TLS bypass for an explicitly accepted self-signed
SQL Server test certificate is `source.trust_server_certificate: true`; transport
remains encrypted, but source server identity is then not verified. Prefer a
trusted source certificate and matching DNS hostname.

## 4. Collect live metadata

```bash
python3 -m ggsetup inspect --config private/demo/environment.json
```

The script performs two approved OCI GET commands and fixed catalog SELECTs on
both databases. It prompts for the two inspection passwords using hidden input.
Passwords appear only in the child client environment, not argv or reports;
privileged OS users can inspect process environments. SQL client startup/env
overrides are removed. OCI profile/auth/region/config are passed explicitly and
CLI RC query defaults are suppressed. OCI_CLI_* environment overrides are not
used; configure credentials in the selected profile or the selected principal
mechanism.

Source and target collection continue independently when queries fail. Default
limit is 10,000 rows **per metadata query**, not application rows. If a result is
truncated, recollect with a higher `--max-rows` (up to 1,000,000). `--timeout`
sets SQL query timeout (default 45 seconds). Metadata is read through separate
connections, not one consistent snapshot. Keep schema changes paused during
collection and planning. Ordinary source data writes are not modified by this
tool; the eventual initial-load workflow will define a separate write-pause gate.

The first inspection creates `private/demo/state/journal.json`, bound to the
configuration fingerprint. Later edits to bound configuration stop with a
mismatch. For corrected configuration during development use a **new directory**
and new environment identity; never edit/delete a journal to bypass the binding.
No migration/adoption command exists yet. Execution adapters use the
same durable journal to prevent replay after unknown outcomes.

The resulting report is `private/demo/state/inspection-<UTC>.json`. `collected`
means collection succeeded, not that replication is supported or configured.
`partial` identifies failed queries; preserve the report. Reports include
private infrastructure and metadata, so keep them off public GitHub/issues.

## 5. Build a plan from the printed inspection path

```bash
python3 -m ggsetup plan --config private/demo/environment.json \
  --inspection private/demo/state/inspection-REPLACE_WITH_PRINTED_TIMESTAMP.json \
  --output private/demo/plan-01
```

A new output directory is required each time. Every run writes `plan.json`.
`blocked` plans list reasons per object and emit **no SQL/parameter artifacts**.
When supported, `schema_plan_ready` also produces:

- `target-schema.review.sql`: target database guard, quoted schemas/tables,
  reviewed type mappings, primary keys and unfiltered unique indexes.
- `capture-tables.review.prm`: explicit TABLE/COLS fragments.
- `apply-maps.review.prm`: explicit MAP/COLMAP fragments.

These files are for review. Do not execute them against your current target.
They do not include credentials, a snapshot LSN, Extract/Replicat creation or
source logging commands. The separate execution controller performs its installed-schema
and readiness checks before starting the corresponding processes. Source identity columns become
ordinary target columns; defaults/routines and application behavior are not
recreated. The target is intended as a source-driven data mirror.

Plans currently require selected target objects to be absent. A populated target
correctly blocks initial planning;
existing-object adoption is a separate feature. A fresh empty SQL database in
the service is appropriate for future installation testing.

## 6. Inspect local state

```bash
python3 -m ggsetup status --config private/demo/environment.json
```

This reads the journal without creating or altering it. Locks prevent concurrent
controllers in one environment. State and output files use private permissions.
An intent cannot be retried or acknowledged under another operation token.
These discovery/status commands perform no remote mutations. Execution
commands use the same journal; their required review and execution sequence
are documented in [EXECUTION.md](EXECUTION.md).

## 7. Continue to execution or review blockers

For a supported schema, continue with [the execution runbook](EXECUTION.md).
Review the generated `plan.json`. A supported schema should be ready;
computed/special types produce explicit blockers. Share the inspection and plan
privately for review, after checking their infrastructure/metadata contents.
No passwords, OCI key files or original remote state directories are needed.

Exit codes: 0 successful requested collection/planning operation, 2 blockers/
partial/error, 130 interruption. A successful schema plan is not replication
readiness. A read-only inspection interrupted by Ctrl+C may not have a complete
saved report; rerunning collection is safe and does not replay source writes.
