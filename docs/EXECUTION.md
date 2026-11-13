# Execution runbook — experimental 0.3.0

These commands execute real mutations. Start with a fresh disposable test
installation. Offline test success is not live service certification. Keep existing
working installations separate; do not import their state or LSN.

## 1. Prepare prerequisites

Complete the discovery tutorial and obtain `schema_plan_ready`. Selected target
application objects must be absent. All selected tables must have supported
columns and primary keys. Computed/spatial/CLR/alias/rowversion and other listed
special features stop before execution. Float/real can be schema-planned but are
blocked for execution until an exact comparison adapter is available.

Use an isolated source SQL database with no existing CDC-tracked tables or
other CDC consumers, and do not run concurrent installers against it. Reusing
preconfigured accounts is supported; sharing capture/logging with an existing
pipeline is not. No source CDC cleanup is changed until the setup owns its
selected table-logging work and managed cleanup is configured.

Before the first inspection, fill `goldengate.subnet_id` in environment.json and
choose unique prefixes/aliases/accounts. Configure private routing, DNS,
security rules and host firewalls between the runner, both deployments and DBs.
Typical ports: SQL Server 1433 (or configured port), PostgreSQL 5432, HTTPS/WSS443.
On-premises SQL Server discovery/setup is permitted when the required route is
already working; this tool does not create VPN/FastConnect/DRG resources.

Your OCI administrator must provide permissions to create/use deployments,
connections and assignments, and GoldenGate resource-principal access to the
four chosen secrets. Supply existing NSG OCIDs and Vault secret OCIDs. This
release intentionally does not create or broaden IAM policies, NSGs or secrets.

Create/select four password secrets for: source console, target console, SQL
capture login and PostgreSQL apply login. Capture/apply passwords entered during
account preparation **must match those secrets**. Secret contents are never
retrieved. The target console secret is reused for the WSS network connection.

For new accounts, choose unique SQL Server server-login and PostgreSQL cluster-
role names. A PostgreSQL role exists across databases in that DB system, not
only within one SQL database. Existing login/role names are not overwritten.
`accounts_mode=existing` requires the users, source management schema/roles and
target management schema ownership already prepared; it does not grant/adopt or
reset existing accounts. Required source memberships: source db_owner plus msdb
SQLAgentReaderRole, not sysadmin. Apply role: LOGIN with no SUPERUSER/CREATEDB/
CREATEROLE/REPLICATION; target management schema owned by apply user.

Source and target SQL databases must already exist. Destination database creation
is outside this execution release. Administrator usernames in execution settings
may differ from the read-only inspection users in environment.json.

## 2. Write execution settings

```bash
python3 -m ggsetup execution-template \
  --output private/demo/execution-settings.json
```

Edit every placeholder. Select the actual source `oggmssql:` build and target
`oggpostgresql:` build available for your region/edition. Review license model, development/testing versus production environment type,
OCPUs, admin usernames, secret IDs and NSGs. Default autoscaling is off and
private deployment mode is enforced. License Included is the editable template
choice, not a license entitlement determination.

Find available builds with OCI CLI (supply your actual profile/auth/region):

```bash
oci goldengate deployment-version list \
  --compartment-id YOUR_COMPARTMENT_OCID \
  --deployment-type DATABASE_MICROSOFT_SQLSERVER --all

oci goldengate deployment-version list \
  --compartment-id YOUR_COMPARTMENT_OCID \
  --deployment-type DATABASE_POSTGRESQL --all
```

No available result is not permission to invent a build. Use reviewed regional
availability or an explicitly selected existing empty deployment/build.
Existing deployments must match expected names, type, OCPU/autoscaling/license/environment settings, private subnet, console
user, secret references and build, and contain no processes, paths or existing CDC cleanup tasks. Reuse of
an active replication deployment is blocked.

`configure_unlimited_lob=true` opts into the instance-wide SQL Server max text
repl size=-1 setting. It refuses RECONFIGURE while unrelated server options have
pending values. Default false leaves that setting unchanged. MAX/LOB columns
require running max text repl size=-1 for this release; configure it separately
or explicitly opt in. No automatic source audit-trigger bypass is included.

## 3. Compile and inspect the immutable execution plan

Use the exact saved schema plan path from discovery:

```bash
python3 -m ggsetup execution-plan \
  --config private/demo/environment.json \
  --schema-plan private/demo/plan-01/plan.json \
  --settings private/demo/execution-settings.json \
  --output private/demo/execution-01
```

Review `execution-plan.json`, `source-account.review.sql` and
`target-schema.review.sql`. Source password preview text is a placeholder, not
an actual credential. Review source account/db_owner privileges, database CDC,
snapshot isolation, optional server LOB setting, target role/schema/grants,
cleanup retention and deployment billing. The plan hash binds configuration,
schema, settings and code-generated definitions. Do not edit generated files.
Execution settings may be corrected/recompiled after a read-only preflight
failure only while no mutation intent, resource or completed stage exists. Once
any mutation intent is recorded, the original plan remains bound to that journal.

The tool prints `execution_sha256`. Copy that exact value into a task-specific
shell variable for the examples:

```bash
GGSETUP_PLAN_SHA='PASTE_THE_PRINTED_SHA256'
```

No passwords belong in that variable or any command argument. Pipeline previews
contain clearly labelled target-origin/marker/LSN placeholders; the controller
resolves those only from OCI metadata and the verified fresh snapshot. Never
execute a preview request or manually start the prepared processes.

## 4. Execute selected stages or the complete sequence

Stop application writes and source/target DDL for the duration of setup. The
`--writes-paused` flag declares that you have done so; it does not pause writers
for you. Direct application writes to replicated target tables are unsupported.

To stop after account/schema preparation, before deployment billing begins:

```bash
python3 -m ggsetup execute-all \
  --config private/demo/environment.json \
  --execution-plan private/demo/execution-01/execution-plan.json \
  --approve-sha256 "$GGSETUP_PLAN_SHA" --writes-paused \
  --until target-schema
```

To execute the whole supported sequence:

```bash
python3 -m ggsetup execute-all \
  --config private/demo/environment.json \
  --execution-plan private/demo/execution-01/execution-plan.json \
  --approve-sha256 "$GGSETUP_PLAN_SHA" --writes-paused
```

Or execute one ordered stage:

```bash
python3 -m ggsetup execute-stage \
  --config private/demo/environment.json \
  --execution-plan private/demo/execution-01/execution-plan.json \
  --approve-sha256 "$GGSETUP_PLAN_SHA" --writes-paused \
  --stage provision
```

`provision` creates billable deployments (unless explicitly reusing matching
empty deployments). All earlier stages must have completed. Hidden password
prompts occur only when needed; credentials stay in memory/child environments.
The apply login may be requested for checkpoint ownership comments. Enter the
same capture/apply passwords referenced by the provided Vault secret IDs.

## 5. Stage reference

| Stage | Actions / completion gate |
|---|---|
| accounts | Precheck names, create capture/apply users and management schemas, verify roles, enable database CDC/snapshot isolation; optional guarded LOB setting |
| target-schema | Recheck source metadata; transactional target mirror DDL and apply grants |
| provision | Create/reuse two matching private GG deployments; verify empty process/path collections |
| connections | Create/assign source SQL, target OCI PostgreSQL and target GG WSS connections; all three deployment-side tests must succeed |
| capture-schema | Update source GLOBALS and stop/start the empty source deployment to reload it; verify readback |
| logging | ADD TRANDATA per table, verify exact table response; create managed cleanup; remove the source DB's native CDC cleanup job; verify native capture/Agent/coverage |
| prepare-initial | Require recent successful cleanup; create distinct checkpoint and stopped initial Extract/path/Replicat |
| extract-initial | Start finite Extract once; verify its single normal task execution, report ownership/selected tables/config echo and fresh nonzero snapshot LSN |
| prepare-cdc | Check retained snapshot coverage and installed transaction-begin LSN schema; create distinct checkpoint and stopped CDC pipeline positioned at that LSN |
| load-initial | Start original initial path/Replicat once; wait for expected counts; stop delivery components normally |
| verify-initial | Recheck metadata and paused counts; compare every row/column through SHA-256 canonical fingerprints; no row values logged |
| start-cdc | Recheck coverage before first Extract start; start owned CDC Extract/path/Replicat once; verify execution identities and health |

Cleanup runs on a ten-minute schedule. Before prepare-initial, a successful
cleanup within 30 minutes is required. A newly created task may not have run
yet: prepare-initial waits up to fifteen minutes for its scheduled successful
run. If that observation times out, inspect and repeat the same command. Logging
also allows a bounded startup wait for the native SQL Server capture job. A stage timeout
never replays its saved start. Source DDL triggers that interfere with CDC or
change baseline counts require diagnosis; the tool does not disable them.

Upon success, every stage is `completed`; the CDC pipeline is running. Review
the report, run controlled database-specific INSERT/UPDATE/DELETE and rollback
checks, and then health. No arbitrary application test rows are generated.

## 6. Health and observation

```bash
python3 -m ggsetup execution-health \
  --config private/demo/environment.json \
  --execution-plan private/demo/execution-01/execution-plan.json

python3 -m ggsetup execution-observe \
  --config private/demo/environment.json \
  --execution-plan private/demo/execution-01/execution-plan.json
```

Health reads runtime/source prerequisites, target shape/privileges/TLS, cleanup,
lag and same-execution identities. It permits normal DML and does not demand
original snapshot counts after startup. It is not a fresh full comparison or
continuous end-to-end heartbeat. Old snapshot retention is not a routine-health
gate after capture starts. No cron/alarms/notifications are installed.

Observation issues GETs and saves a private report of resources, available
processes/checkpoints and pending actions. It does not start/stop/recreate or
adopt executions. A stopped deployment is reported without starting it.

## 7. Errors, ambiguous outcomes and reconciliation

Keep the entire environment directory and its original plan. The cleanup age
setting is not a guaranteed safe outage duration; actual retained CDC, trails
and checkpoints determine recovery feasibility. Never delete an
intent to retry, reset positions, truncate a target, replay a finite load, or
use HANDLECOLLISIONS. Completed mutations are retained; no automatic rollback.
An error may leave one component running; observation does not stop it.

Known recorded resource IDs are polled on rerun without new creation. For a
lost OCI create response with a pending intent, identify the candidate OCID
through the console/CLI and request read-only reconciliation:

```bash
python3 -m ggsetup reconcile-resource \
  --config private/demo/environment.json \
  --execution-plan private/demo/execution-01/execution-plan.json \
  --approve-sha256 "$GGSETUP_PLAN_SHA" \
  --key deployment:source --resource-id CANDIDATE_DEPLOYMENT_OCID
```

Supported keys: deployment:source, deployment:target, connection:source,
connection:target, connection:network. The candidate must be ACTIVE with exact
ownership tags, compartment, name, topology/type and secret reference. This
acknowledges verified local state only, then the original stage can continue.
It never sends another create or changes the candidate.

Pending SQL/REST/assignment outcomes are **not** automatically reconciled by
this release. Do not manually edit the journal or claim success from an absent
resource. Preserve the report for diagnosis. Definite rejection/retry workflows
and planned stop/resume adoption are still explicit future work; this release
chooses stopping for review over speculative retry. A changed PID/lastStarted
requires investigation, not silently resetting the baseline.
