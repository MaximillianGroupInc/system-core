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
never exposed publicly.

**TUS audio upload path** — large audio files bypass Varnish entirely:
Nginx terminates TUS connections and proxies directly to the TUS Node server
(port 1080), with no buffering, no body size limit, and 3600s timeouts.
Varnish also has a belt-and-suspenders `req.backend_hint = tus_node` rule
for any `/files/` traffic that reaches it via a non-standard path.

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

### HSTS `includeSubDomains` activation checklist

The default config ships with `max-age=31536000` only (no `includeSubDomains`)
to prevent accidentally locking subdomains that are not yet HTTPS-only.

Before enabling `includeSubDomains`:

1. Confirm every subdomain (`www.*`, `api.*`, `cdn.*`, `mail.*`, etc.) has a
   valid TLS certificate and redirects HTTP → HTTPS.
2. Confirm no subdomain serves content over plain HTTP that must be reachable
   by end users.
3. Once confirmed, update `nginx/sites-available/system-core.conf`:
   ```nginx
   add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   ```
4. Optionally add `; preload` and submit to <https://hstspreload.org/> once
   the `includeSubDomains` version has been live and stable for several weeks.

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

## TUS Resumable Audio Upload

Large audio files are uploaded via the [TUS resumable upload protocol](https://tus.io/)
at the `/files/` path.  Every layer in the pipeline is explicitly configured to
give this traffic unobstructed, buffering-free passage.

### Upload path

```
Browser / Mobile Client
  → HTTPS POST/PATCH /files/  (TUS protocol)

Cloudflare
  → passes through; WAF rules must whitelist TUS methods (PATCH, HEAD, OPTIONS)

Nginx (perimeter)
  → location /files/  —  proxy_request_buffering off
                          proxy_buffering off
                          client_max_body_size 0  (no body size limit)
                          proxy_read_timeout 3600s
                          proxy_send_timeout 3600s
  → proxies directly to TUS Node server (port 1080)
  → UA checks and rate limiting are EXEMPT for /files/ (TUS clients send
     minimal headers per TUS spec §1.5)

Varnish (belt-and-suspenders)
  → req.backend_hint = tus_node (port 1080)
  → return(pipe)  — Varnish does NOT buffer or cache any part of the upload
  → vcl_pipe sets Connection: close to prevent connection reuse after pipe ends
  → TUS Node backend has extended timeouts (first_byte=300s,
     between_bytes=120s) to accommodate large files on slow mobile links

TUS Node server (port 1080)
  → stores chunks, manages upload state, assembles final audio file
  → Apache is never involved in the upload path
```

### Why pipe and not pass?

Varnish `pass` still buffers the full request body before forwarding.
`pipe` establishes a raw TCP tunnel between the client and the TUS Node,
forwarding bytes without buffering — essential for large audio files that
can exceed available Varnish memory and for TUS PATCH requests that must
not be interrupted.

### Timeout configuration

| Layer | Setting | Value | Reason |
|-------|---------|-------|--------|
| Nginx | `proxy_read_timeout` | 3600s | Long-lived TUS sessions |
| Nginx | `proxy_send_timeout` | 3600s | Slow mobile uplinks |
| Nginx | `proxy_connect_timeout` | 75s | Loopback; 75s is generous |
| Varnish `tus_node` | `first_byte_timeout` | 300s | TUS Node may delay ACK for large chunks |
| Varnish `tus_node` | `between_bytes_timeout` | 120s | Bursty retry patterns on mobile |

### Serving processed audio

Once the TUS Node has assembled the audio file it is moved to the served
assets path.  Varnish caches processed audio assets (`mp3`, `mp4`, `ogg`,
`webm`, `wav`, `flac`, `aac`, `m4a`, `opus`) with a **30-day TTL** and
`Vary: Accept` so clients that negotiate different container formats
(e.g. `audio/ogg` vs `audio/mpeg`) receive the correct variant from cache.
