# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `.gitignore` covering editor artifacts, OS files, and local overrides.
- `CONTRIBUTING.md` with contribution workflow and config testing checklist.
- `SECURITY.md` with vulnerability disclosure policy.
- `SUPPORT.md` with support channels and escalation path.
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).
- `CODEOWNERS` mapping ownership to sensitive configuration areas.
- GitHub issue templates: bug report, feature request, regression report, documentation issue.
- GitHub pull request template with testing, risk, and rollback checklist.
- GitHub Actions workflow `validate.yml` for automated Nginx, Varnish, Apache, and PHP syntax validation on every pull request.

### Changed
- README HSTS section updated to reflect the active `includeSubDomains; preload` policy (previously described the config as shipping without `includeSubDomains`, which was incorrect).
- Removed commented-out `Cross-Origin-Embedder-Policy` dead code from `nginx/sites-available/system-core.conf`.

### Fixed
- Typos in `nginx/conf.d/spx-bot-mitigation-logic.conf`: "Pakastan" → "Pakistan", "Afganistan" → "Afghanistan".

---

## [1.2.0] — Initial tracked release

### Architecture
- Nginx perimeter layer: Cloudflare real-IP restore, bot mitigation, SPARXSTAR header gate, TLS multi-domain SNI, rate limiting, TUS proxy.
- Varnish cache layer: cookie allowlist, stale-while-revalidate, image format negotiation, TUS pipe routing.
- Apache application layer: WordPress multisite, PHP-FPM 8.4, mod_remoteip, health endpoint.
- `spx-upload-mimes.php` must-use plugin: ICO, WAV, MP3 upload support with finfo content validation.

[Unreleased]: https://github.com/MaximillianGroupInc/system-core/compare/HEAD...HEAD
[1.2.0]: https://github.com/MaximillianGroupInc/system-core/releases/tag/v1.2.0
