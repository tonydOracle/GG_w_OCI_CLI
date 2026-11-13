# GitHub preparation

This new package replaces the sanitized historical reference package as the
active development project, with experimental execution included. Publish only this project's source/docs/tests.
Keep actual configs, CA files, reports, state and original private archives out
of Git. Licensing remains undecided, as requested; LICENSING.md is not a grant.

From a new extracted project directory outside an existing repository:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
git init -b main
git add .gitignore README.md LICENSING.md SECURITY.md CHANGELOG.md pyproject.toml ggsetup tests docs examples
git diff --cached --stat
git diff --cached
```

Review all staged contents. If required, configure your own repository-local
Git author name/email, then:

```bash
git commit -m "Add configuration-driven discovery, planning and staged execution"
gh auth login
gh repo create YOUR-OWNER/oci-gg-setup --private --source=. --remote=origin --push
```

The last command creates/pushes a private repository under your chosen owner.
It has not been executed for you. Review visibility/licensing before public
release. No credentials belong in source, examples or public issue attachments.
The `.gitignore` does not remove files that were already committed or pushed.

Suggested About text: “SQL Server to OCI PostgreSQL GoldenGate setup toolkit;
experimental staged installer for supported schemas; generic live acceptance pending.”
The code includes the full supported setup sequence; do not claim it has been
live acceptance-tested or supports every SQL Server feature.

Authoritative publishing instructions:
- https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github
- https://cli.github.com/manual/gh_repo_create
