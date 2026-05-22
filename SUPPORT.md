# Support

## Documentation

The primary reference for this repository is [README.md](README.md).

It covers:

- Architecture overview (Cloudflare → Nginx → Varnish → Apache)
- Configuration file map
- Port assignments and internal bindings
- Provisioning checklist and required host-side files
- Security design notes (HSTS, SPARXSTAR header flow, Cloudflare IP ranges,
  Varnish cookie allowlist, TUS upload path)
- Migration guide from previous config versions

## Asking questions

For questions about configuration decisions or deployment:

- Open a [GitHub Discussion](https://github.com/MaximillianGroupInc/system-core/discussions)
  (Q&A category).

For confirmed bugs or regressions:

- Open a [GitHub Issue](https://github.com/MaximillianGroupInc/system-core/issues)
  using the appropriate template.

## Security issues

**Do not use public channels for security issues.**

Follow the process in [SECURITY.md](SECURITY.md).

## What is not supported here

- Cloudflare account configuration, WAF rules, or Worker code — those live in
  separate repositories or the Cloudflare dashboard.
- WordPress theme or plugin development.
- General Linux system administration questions unrelated to this stack.
