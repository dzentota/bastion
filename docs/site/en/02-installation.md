---
slug: installation
parent: docs
---
# Installation

## Requirements

| Component | Minimum | Notes |
|---|---|---|
| PHP | 8.3 | extensions: pdo_sqlite or pdo_mysql, sodium, mbstring |
| Database | SQLite 3.27+ with FTS5, or MySQL / MariaDB (InnoDB) | SQLite is the simplest choice |
| HTTPS | required | the application refuses to run over plain HTTP |

## Verify and upload the release

Every release comes with a SHA-256 checksum and a CycloneDX SBOM. Check the archive before you unpack it.

```bash
shasum -a 256 -c bastion-1.0.0.zip.sha256
unzip bastion-1.0.0.zip
```

Point the web server at the public directory. Everything else, including var, must stay outside the document root.

> The var directory holds the database, the keys and the audit anchor. It must never be reachable over HTTP.

## Run the web installer

Open /install in the browser. To prove you own the site, paste the token from var/install.token. The installer asks for the site languages, creates the first administrator and then disables itself.

The administrator must enrol a second factor (an authenticator app) before the first sign-in completes.

## After installation

- Run bin/sbom verify on the server: it checks vendor/, the bundled fonts and the threat-model export against the SBOM.
- Connect S3-compatible storage for media if you can; until then the dashboard shows a reduced-security notice.
