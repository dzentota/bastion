---
slug: hardening
parent: docs
---
# Hardening

Bastion sets its own security headers (a strict Content Security Policy without inline scripts or styles, HSTS, frame-ancestors none) and keeps sessions out of public pages. The checks below are about the server around it.

## Checklist

- Only the public directory is the web root; var, src, vendor and build are not reachable.
- The code is owned by root and only readable by the PHP-FPM user; that user can write only var and extensions.
- PHP-FPM runs in its own pool with open_basedir limited to the site directory.
- The second factor stays mandatory for administrators and editors.
- Mail is configured, so that password resets work without shell access.
- Media is stored in S3-compatible storage, not next to the code.

## Behind a CDN

Behind a CDN the connection comes from the CDN, not from the visitor. Trust the client address header only from your CDN's address ranges, at the web-server level. Otherwise AppSensor, which locks out abusive addresses, would lock out whole CDN nodes.

Public pages carry no cookies and are cacheable for five minutes; /admin and /install are never cached.

## Watching the site

The admin dashboard lists configuration weaknesses (Degraded Mode). The audit trail is append-only and chained with an HMAC; run bin/bastion audit:verify every day and alert when it fails.
