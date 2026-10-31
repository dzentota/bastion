---
slug: backups
parent: docs
---
# Backups

The var directory is the whole state of a site: the database, the keys in var/keys and the audit anchor.

## What to keep

- A daily copy of the database. With SQLite: sqlite3 var/bastion.sqlite ".backup backup.sqlite".
- A copy of var/keys, stored separately. Without these keys the audit trail and the signatures of revision history cannot be verified, and encrypted second-factor secrets cannot be read.
- Copies taken before each migration, in var/backups.

Move copies off the server, encrypted.

## Restoring

Stop PHP-FPM, put the database file and var/keys back, start PHP-FPM, then run bin/bastion audit:verify.
