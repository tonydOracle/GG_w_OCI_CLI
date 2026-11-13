# First live acceptance: a disposable SQL database pair

Use this lab before treating 0.3.0 as a qualified generic installer. Keep it separate
from existing working installations. Use distinct database, login, role,
alias, process and deployment names. Two additional deployments are billable;
review the plan and prerequisites before execution.

## 1. Prepare a new SQL Server database

Run as your SQL Server administrator. If these names already exist, choose a
new name rather than deleting or overwriting an existing database.

```sql
USE [master];
GO
CREATE DATABASE [GGSetupLab];
GO
USE [GGSetupLab];
GO
CREATE TABLE dbo.GGSetupSmoke
(
    TestID int NOT NULL PRIMARY KEY,
    Payload nvarchar(100) NULL,
    Amount decimal(19,4) NOT NULL
);
INSERT INTO dbo.GGSetupSmoke(TestID, Payload, Amount)
VALUES (1, N'Before GoldenGate', 19.9500);
GO
```

Do not enable table CDC manually; the setup controller handles it. Do not add
computed columns, special types or DDL triggers to this first lab.

## 2. Prepare a new SQL database within OCI PostgreSQL

Connect to an existing maintenance database as the PostgreSQL service admin:

```sql
CREATE DATABASE "GGSetupLab" TEMPLATE template0;
```

This is a SQL database inside the existing managed DB system, not a new OCI DB
system. Do not create the application table there; the controller generates it.

## 3. Configure and inspect

Follow TUTORIAL.md using environment `lab` and directory `private/lab`.
Choose source/target SQL database `GGSetupLab`, unique capture/apply usernames
such as `ggcapture_lab` / `ggapply_lab`, resource prefix `LB`, unique credential
aliases, a dedicated lowercase `ggschema`, and your actual network/system OCIDs.

If the source still uses an explicitly accepted self-signed test certificate,
set source.trust_server_certificate=true before the first inspection. Otherwise
use a trusted certificate. Target TLS remains verify-full. Set the private
subnet OCID before configuration is bound. The same existing OCI PostgreSQL
DB system endpoint/CA can serve this new SQL database.

Configure four valid Vault secret references and matching administrator/capture/
apply passwords through the execution settings. New SQL login and PG role names
must be unused; PG roles are shared across databases within the same DB system.
Review network/IAM prerequisites and exact regional GG builds in EXECUTION.md.

The lab's expected plan is one table / three columns. Source CDC is initially
disabled; target application objects are absent. After a supported schema plan,
compile the execution plan and follow EXECUTION.md. Keep source writers paused
through all stages. Initial content verification should report one matching row.

## 4. Validate committed changes after CDC startup

Only after start-cdc and execution-health succeed, run on SQL Server:

```sql
USE [GGSetupLab];
GO
BEGIN TRANSACTION;
INSERT INTO dbo.GGSetupSmoke(TestID, Payload, Amount)
VALUES (2, N'Inserted through GoldenGate', 7.2500);
UPDATE dbo.GGSetupSmoke
SET Payload=N'Updated through GoldenGate', Amount=20.5000
WHERE TestID=1;
COMMIT;
GO
```

On PostgreSQL, connect to GGSetupLab and retry after a few seconds if needed:

```sql
SELECT "TestID", "Payload", "Amount"
FROM "dbo"."GGSetupSmoke"
ORDER BY "TestID";
```

Expected: ID 1 with Updated through GoldenGate / 20.5000, and ID 2 with Inserted
through GoldenGate / 7.2500. Observe both values before deleting test row 2.

## 5. Validate delete and rollback

On SQL Server:

```sql
USE [GGSetupLab];
GO
DELETE FROM dbo.GGSetupSmoke WHERE TestID=2;
BEGIN TRANSACTION;
INSERT INTO dbo.GGSetupSmoke(TestID, Payload, Amount)
VALUES (99, N'This transaction is rolled back', 0);
ROLLBACK;
GO
```

On PostgreSQL, after delivery:

```sql
SELECT "TestID", "Payload", "Amount"
FROM "dbo"."GGSetupSmoke"
ORDER BY "TestID";
```

Expected: only updated ID 1. IDs 2 and 99 must be absent. Never insert those rows
manually on PostgreSQL to make a comparison pass. Rerun execution-health and
retain all reports, configuration, original plan, state and trails privately.

This verifies the simple lab subset. It does not qualify other tables/types,
concurrent workloads, failover, large datasets or automatic recovery. No script
in this release deletes the lab databases or deployments. Cleanup/billing review
is a separate deliberate operation; stopping deployments is not a claim that
all related cloud costs disappear.
