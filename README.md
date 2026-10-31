# Bastion

A security-first CMS for ordinary shared hosting, and a practical proof of the AppSec Manifesto: every feature starts with abuser stories, each story is covered by a mitigation in the code and an attack test, and CI refuses a build where that is not true.

- PHP 8.3+, SQLite or MySQL/MariaDB, no daemons, web installer
- Strict CSP without inline code, mandatory second factor for staff, signed and chained audit trail and revision history
- Versioned migrations applied by an administrator, content in several languages, full-text search
- Threat model in [hybridtm](threat-model.php), rendered on the documentation site together with the coverage matrix and a data-flow diagram

## Development

```bash
composer install
vendor/bin/phpunit
vendor/bin/phpstan analyse
bin/threat-gate
```

## Documentation

- Architecture decisions: [docs/adr](docs/adr) (in Russian)
- Roadmap: [docs/roadmap.md](docs/roadmap.md)
- Running a site: [docs/deploy.md](docs/deploy.md)
- Site content: [docs/site](docs/site)

## Security

Please report vulnerabilities privately: **Security → Report a vulnerability** on this repository. Do not open public issues for them.

## License

[MIT](LICENSE)
