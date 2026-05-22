# Contributing to system-core

This repository contains the server-layer configuration for the SPARXSTAR
production stack: Nginx, Varnish, Apache, and WordPress must-use plugins.

---

## Ground rules

- Every change that touches a live config file **must pass local validation
  before opening a pull request** (see the checklist below).
- Do not commit secret values. The `nginx/secrets/worker-secret.conf` file
  in this repository is intentionally empty. Actual secrets live on the
  server only and are rotated out-of-band.
- Prefer small, focused pull requests. One concern per PR.
- All PRs require at least one approving review from a CODEOWNER before merge.

---

## Local validation checklist

Run these commands against the files you modified before pushing.

### Nginx

```bash
# Syntax check only — does not require a running server.
# Point to your local copy of the config tree.
nginx -t -c /path/to/nginx/nginx.conf
```

If you do not have Nginx installed locally, use the Docker one-liner:

```bash
docker run --rm \
  -v "$(pwd)/nginx:/etc/nginx:ro" \
  nginx:stable nginx -t
```

### Varnish

```bash
# Validate VCL without starting the daemon.
varnishd -C -f /path/to/varnish/default.vcl
```

Docker one-liner:

```bash
docker run --rm \
  -v "$(pwd)/varnish/default.vcl:/etc/varnish/default.vcl:ro" \
  varnish:stable varnishd -C -f /etc/varnish/default.vcl
```

### Apache

```bash
# Syntax check only.
apachectl -f /path/to/apache/apache2.conf -t
```

### PHP (must-use plugins)

```bash
php -l var/www/html/wp-content/mu-plugins/spx-upload-mimes.php
```

---

## Pull request process

1. Fork the repository and create a branch off `main`.
2. Make your changes and run the validation checklist above.
3. Open a pull request using the provided template. Fill in every section.
4. A CODEOWNER review is required before merge.
5. Squash-merge is preferred for clean linear history.

---

## Config file conventions

- Comments explain **why**, not what. Nginx directives are self-documenting.
- Section delimiters use `# ===` (80 chars) for major blocks and `# ---`
  for sub-blocks. Match the surrounding style.
- Keep map blocks sorted alphabetically within a logical group.
- IP allowlists (Cloudflare ranges, VPC IPs) must include a comment linking
  to the authoritative source and the last-verified date.
- Never inline a secret value. Use the `include` pattern with a server-side
  file, same as `nginx/secrets/worker-secret.conf`.

---

## Reporting issues

Use the GitHub issue templates in `.github/ISSUE_TEMPLATE/`.

Security issues must be reported privately — see [SECURITY.md](SECURITY.md).
