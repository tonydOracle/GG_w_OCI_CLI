# Technical references

The controller must validate installed API capabilities and exact database
values; documentation alone does not certify a particular deployment.

- OCI PostgreSQL connection details and CA metadata:
  https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/psql/connection-details/get.html
- GoldenGate SQL Server supported data types/objects/operations:
  https://docs.oracle.com/en/database/goldengate/core/26/coredoc/prepare-sql-server-understanding-whats-supported.html
- Precise SQL Server initial load and snapshot positioning:
  https://docs.oracle.com/en/database/goldengate/core/26/coredoc/instantiate-precise-instantiation-sql-server.html
- Managed CDC operational considerations:
  https://docs.oracle.com/en/database/goldengate/core/26/coredoc/prepare-cdc-capture-method-operational-considerations-sqlserver.html
- PostgreSQL unique index NULLS NOT DISTINCT syntax:
  https://www.postgresql.org/docs/18/sql-createindex.html
- OCI PostgreSQL GoldenGate connection request fields (for future adapter review):
  https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/goldengate/connection/create-postgresql-connection.html

Current docs describe sensitive-field deprecations that differ from the previously
working reference build. Mutation adapters must capability-check the installed
CLI/service rather than blindly reuse that earlier request contract.
