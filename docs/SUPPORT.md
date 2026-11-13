# Current schema planning support

This matrix describes planning support, not live GoldenGate certification.
The execution release adds whole-value verification for its exact supported
subset. Float/real are planning-only and execution-blocked; all other blocked
features below remain blocked. The generic execution path has not yet passed
live service acceptance testing. Test in a fresh disposable environment first.

| Source feature | Planning behavior |
|---|---|
| int/bigint/smallint/tinyint | integer/bigint/smallint mapping |
| bit | boolean |
| decimal/numeric precision <=38 | numeric with same precision/scale |
| money/smallmoney | numeric(19,4) / numeric(10,4) |
| real/float | real/double precision; end-to-end value tests still required |
| char/nchar/varchar/nvarchar | character/varying using declared width; Unicode byte width converted to characters |
| varchar(max)/nvarchar(max) | text; actual NUL/encoding/size checks remain a gate |
| binary/varbinary including MAX | bytea; wire representation/LOB tests remain a gate |
| uniqueidentifier | uuid |
| date/datetime/smalldatetime | date/timestamp without time zone |
| datetime2/time with scale <=6 | same target fractional scale |
| datetime2/time with scale 7 | blocked to avoid silent loss of a seventh digit |
| identity | ordinary target value column; no target sequence |
| Exactly one usable primary key | required; no guessed keys |
| Unfiltered enabled unique indexes | generated with NULLS NOT DISTINCT; included non-key columns not recreated |
| Computed columns | blocked pending a reviewed transaction-exact adapter |
| XML, hierarchyid, geography/geometry, CLR/alias types, rowversion, sql_variant, datetimeoffset, legacy LOB types | blocked pending explicit tested handling |
| Memory-optimized, temporal/history, FILETABLE, external, row-security tables | blocked |
| Sparse/column-set, generated-always/hidden, FILESTREAM, encrypted columns | blocked |
| Missing/incomplete/truncated metadata | blocked |
| Existing selected target relations | blocked; no adoption/overwrite |
| Special punctuation/non-ASCII in parameter identifiers | blocked until GoldenGate quoting is independently tested |

All/selected table scope is supported. Unsupported selected objects block the
entire artifact emission. The plan does not silently drop their columns.
No automatic T-SQL expression converter or source-row FETCH strategy exists.

Source routines, triggers, defaults, collations, CHECK and foreign-key constraints
are not migrated. This is a mirror design, not a SQL Server application-porting
tool. Unique constraints follow target comparison semantics, which are not a
claim of collation equivalence. Validate data against target indexes during
load testing. Source schema changes must be paused while metadata is collected.

Implementation metadata syntax: SQL Server 2016+, target PostgreSQL 15+.
Actual OCI GoldenGate support must be checked against the chosen release,
source platform/edition and managed target service version.
