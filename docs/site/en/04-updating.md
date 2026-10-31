---
slug: updating
parent: docs
---
# Updates

Install a new release the same way as the first one: verify the checksum, unpack it next to the old release and switch over.

## Database migrations

A release may change the database schema. Ordinary requests never do that. Until the pending migrations are applied, the public site answers "being updated" and only sign-in and the Update database screen are open.

To apply them, sign in as an administrator, open Database and confirm with a fresh code from your authenticator app. A full backup is written to var/backups first; if the backup fails, nothing runs. Each applied migration is recorded in the audit trail.

If you have shell access, bin/bastion migrate does the same.

## Rolling back

There are no down migrations. To roll back, switch back to the previous release and restore the database from the backup taken before the migration.
