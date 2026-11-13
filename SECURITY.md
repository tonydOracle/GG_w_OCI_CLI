# Credentials and state

Do not commit real configuration, credentials, private endpoints, metadata
reports, CA collections, runtime journals or trails. Put them under ignored
private/. No passwords are accepted in configuration; use hidden prompts and
OCI CLI's own authentication. Child SQL clients receive passwords in environment
variables, which privileged operating-system users may inspect.

Source certificate verification defaults to on; an explicit test bypass still
requires encryption. Target uses verify-full with a parsed CA. No CA-fetch
operation claims that subsequent hostname verification/reachability will succeed.
Execution commands perform real mutations only after a compiled plan is
reviewed and its exact SHA-256 is supplied. Setup also requires a declared
write pause. Discovery/observation remain read-only.

State is operator-owned private data; fingerprints detect drift, not malicious
operator tampering. Do not edit or delete a saved intent to retry an unknown
operation. Use read-only observation and the exact OCI-create reconciliation command
where supported; other uncertain outcomes stop for diagnosis.
No security contact or automated alerting service is configured.
