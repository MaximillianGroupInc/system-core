# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.2.x   | ✅ Active  |
| < 1.2   | ❌ End of life |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately through
[GitHub's private vulnerability reporting](https://github.com/MaximillianGroupInc/system-core/security/advisories/new).

Include:

- A clear description of the vulnerability.
- The affected file(s) and line numbers where applicable.
- Steps to reproduce or a proof-of-concept (even a rough one helps).
- Your assessment of severity and exploitability.
- Any suggested remediation if you have one.

## Response commitment

- Acknowledgement within **2 business days**.
- Initial severity assessment within **5 business days**.
- Critical / High issues targeted for remediation within **14 days**.
- You will be credited in the release notes unless you prefer anonymity.

## Scope

In scope for this repository:

- Nginx configuration: header injection, auth bypass, IP trust misconfiguration.
- Varnish VCL: cache poisoning, authenticated response leakage, bypass of pass/pipe rules.
- Apache configuration: privilege escalation, directory traversal, mis-scoped access rules.
- WordPress MU plugin (`spx-upload-mimes.php`): file upload bypass, MIME validation weaknesses.
- Secret handling: anything that could expose or weaken the Worker-to-Origin shared secret.

Out of scope:

- Cloudflare product vulnerabilities (report to Cloudflare directly).
- WordPress core or plugin vulnerabilities (report to the respective project).
- Theoretical / speculative issues with no realistic attack path.

## Security design notes

Key security controls in this stack and where they live:

| Control | Location |
|---------|----------|
| Cloudflare-only origin gate | `nginx/nginx.conf` — `geo $realip_remote_addr $spx_from_cloudflare` |
| Worker-to-Origin secret gate | `nginx/nginx.conf` — `map $http_x_worker_origin_secret $spx_is_trusted_worker` |
| Real IP restoration | `nginx/conf.d/spx-cloudflare-trust.conf` |
| Bot/UA mitigation | `nginx/conf.d/spx-bot-mitigation-logic.conf` |
| CSP policy | `nginx/conf.d/spx-csp-logic.conf` |
| CORS credentials allowlist | `nginx/maps/spx-cors-trusted-origins.conf` |
| TLS certificate mapping | `nginx/conf.d/spx-certs-logic.conf` |
| Rate limiting zones | `nginx/nginx.conf` — `limit_req_zone` blocks |
| Upload MIME validation | `var/www/html/wp-content/mu-plugins/spx-upload-mimes.php` |
