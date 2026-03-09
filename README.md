# system-core
Server configuration for system core following version 1.2 guidelines

## Architecture Overview

```
INTERNET USERS
      │
┌─────────────────────┐
│      CLOUDFLARE      │  TLS · WAF · HTTP/3 · Bot Filter · CDN
└─────────────────────┘
      │  Trusted Edge Request (CF-Connecting-IP header)
┌─────────────────────┐
│        NGINX         │  Real IP restore · Protocol sanity
│  (perimeter layer)   │  Security headers · Rate limiting
└─────────────────────┘
      │  Clean Request (port 6081)
┌─────────────────────┐
│       VARNISH        │  HTML cache · TTL · stale-while-revalidate
│   (cache layer)      │  Cookie allowlist · Bypass routing
└─────────────────────┘
      │  Cache miss / pass (port 8080)
┌─────────────────────┐
│  APACHE + WORDPRESS  │  Multisite · WooCommerce · Mercator
│   (app layer)        │  GraphQL · Submission Core · PHP-FPM 8.4
└─────────────────────┘
```

Internal transport between layers uses loopback (`127.0.0.1`) only and is
never exposed publicly.  TUS upload traffic is routed by Nginx directly to
the TUS Node server (port 1080), bypassing Varnish entirely.

## Configuration Files

| File | Purpose |
|------|---------|
| `nginx/nginx.conf` | Global Nginx settings: real IP restore, geo/UA maps, rate-limit zones, upstream backends |
| `nginx/sites-available/system-core.conf` | Virtual host: TLS, security headers, UA/geo checks, SPARXSTAR header gate, per-route proxying |
| `varnish/default.vcl` | Cache policy: bypass rules, cookie allowlist, TTL/grace, image format negotiation |
| `apache/sites-available/system-core.conf` | WordPress multisite: mod_remoteip, HTTPS reconstruction, PHP-FPM 8.4, health endpoint |

## Ports

| Service | Port | Binding |
|---------|------|---------|
| Nginx HTTPS | 443 | Public |
| Nginx HTTP (redirect) | 80 | Public |
| Varnish | 6081 | 127.0.0.1 |
| Apache + WordPress | 8080 | 127.0.0.1 |
| TUS Node server | 1080 | 127.0.0.1 |

## Provisioning Notes

### Required files and directories

```bash
# TLS certificates (Nginx)
/etc/ssl/certs/system-core.crt
/etc/ssl/private/system-core.key

# Worker-to-Origin shared secret (Nginx)
# Format — one line: "your-shared-secret-value"  1;
# This is referenced by: map $http_x_worker_origin_secret $is_trusted_worker
# Never commit the actual secret value to this repository.
/etc/nginx/secrets/worker-secret.conf

# PHP-FPM 8.4 socket (Apache)
/run/php/php8.4-fpm.sock

# Varnish / Apache health probe endpoint (plain text, no PHP)
echo "OK" > /var/www/html/health && chmod 644 /var/www/html/health
```

### Nginx sites-enabled symlink

```bash
ln -s /etc/nginx/sites-available/system-core.conf \
      /etc/nginx/sites-enabled/system-core.conf
```

### Apache activation

```bash
a2ensite system-core
a2enmod remoteip setenvif proxy_fcgi rewrite headers
systemctl reload apache2
```

### Required Apache modules

- `mod_remoteip` — real visitor IP from `X-Forwarded-For`
- `mod_setenvif` — `HTTPS=on` reconstruction before Mercator SUNRISE
- `mod_proxy_fcgi` — PHP-FPM 8.4 handler
- `mod_rewrite` — WordPress multisite rewrites
- `mod_headers` — `Cache-Control` on admin routes

## Security Notes

### Cloudflare IP ranges

Nginx `set_real_ip_from` directives must be kept in sync with Cloudflare's
published ranges.  Verify at each infrastructure review:

- IPv4: <https://www.cloudflare.com/ips-v4>
- IPv6: <https://www.cloudflare.com/ips-v6>

### Worker-to-Origin secret

The `X-Worker-Origin-Secret` header is the secondary trust gate for
SPARXSTAR edge-auth headers (Section 14.4).  Without a valid secret, Nginx
evaluates all SPARXSTAR headers to `""` regardless of source IP, preventing
header spoofing even if a Cloudflare IP is somehow reachable directly.

Rotate the secret value by:
1. Updating `/etc/nginx/secrets/worker-secret.conf`
2. Updating the matching secret in the Cloudflare Worker (Worker Secrets)
3. Reloading Nginx: `nginx -s reload`

### SPARXSTAR header flow

```
Cloudflare Worker
  → sets X-SPARXSTAR-* headers after JWT validation
  → sets X-Worker-Origin-Secret: <shared-secret>
  → forwards to Nginx origin

Nginx
  → verifies $is_trusted_worker via map on X-Worker-Origin-Secret
  → $pass_sparxstar_* maps: preserve headers if trusted, "" if not
  → forwards to Varnish → Apache
```

### TLS 0-RTT

`ssl_early_data off` is set globally.  0-RTT must NOT be enabled on any
route that modifies state (auth, payments, form submissions) due to replay
attack risk (Section 4.1).

### Varnish cookie allowlist

Authenticated sessions are identified by any of the following cookies:

- `wordpress_logged_in_*`
- `wp-postpass_*`
- `woocommerce_items_in_cart*`
- `wp_woocommerce_session_*`
- `SCF_*`

Requests carrying these cookies bypass the cache entirely (Varnish `pass`).
All other cookies are stripped before the cache lookup so anonymous pages
are served from cache without cookie fragmentation.

### Fail2Ban integration

Nginx logs include `real_ip`, `country`, and `block_reason` fields.
Fail2Ban rules must read `real_ip` (restored from `CF-Connecting-IP`),
not `$remote_addr`, to avoid banning Cloudflare edge nodes.
