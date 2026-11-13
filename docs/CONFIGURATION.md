# Configuration and state contract

Schema version: 1. Unknown/missing properties are rejected, including password
fields. See `examples/environment.example.json` and `python3 -m ggsetup init`.
The example's OCIDs are intentional nonfunctional placeholders.

| Section | Values |
|---|---|
| environment | Unique lowercase identifier; one folder per configuration/run |
| oci | Config file path, profile, auth, region and destination compartment OCID |
| source | DNS/IPv4, port, SQL database, inspection/capture usernames, location, explicit certificate-bypass boolean |
| target | OCI PostgreSQL DB system OCID, primary DNS/port, SQL database, inspection/apply users and CA path |
| goldengate | Resource prefix, dedicated lowercase ASCII management schema, distinct aliases, optional subnet/Vault/key/existing-deployment OCIDs |
| scope | all/selected, table pairs to include/exclude, schemas to exclude |

Authentication choices: api_key, security_token, instance_principal,
resource_principal. This is a selected-method setting, not an IAM authorization
verdict. Auth-specific runtime credentials remain with OCI CLI, not this JSON.
The target DB system and configured compartment must match. Different source
and target SQL database names are allowed. Different compartments/topologies
for future deployed resources require additional network/IAM planning.

Names for planned Extract/Replicat groups are <=8 characters. Trail prefixes
are deterministic but finite; collision-free allocation against existing live
resources is an execution gate, not guaranteed by hashing. Different
folders alone do not protect remote resources from a name collision.

The configuration fingerprint is SHA-256 over canonical JSON. Inspection/plan
reports bind to it. The journal has a run ID, exclusive OS lock, ordered events,
and durable pending/acknowledged operation intents. Fingerprints detect drift;
they are not cryptographic authentication of operator-edited files. Do not
manually edit state or reports. State from another installation is incompatible
by design and must not be imported as a successful run.

Relative state is always beside environment.json under `state/`. Relative CA
paths resolve beside that file. The OCI CLI config file expands `~`; prefer an
absolute path otherwise. Private output directories must have mode 0700; files
are 0600. Symlink output/state paths are rejected. Keep `private/` out of Git.
Use Linux/macOS POSIX filesystems; Windows is not a validated controller host.

All inspection queries are catalog SELECTs, run independently. Discovery does not perform application-row comparison or remote changes.
Separate execution commands implement account/schema changes, capture/logging,
initial load, full comparison and runtime control. Network/IAM/secret creation
and destination SQL database creation remain prerequisites, not automated stages. The CA fetch writes only a verified public certificate file.

Execution settings live in a separate strict JSON file. The compiled execution
SHA-256 binds settings plus schema plus environment. Once execution starts, do
not change settings/regenerate schema to bypass state. See EXECUTION.md.
