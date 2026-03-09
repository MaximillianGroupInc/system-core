vcl 4.1;

# =============================================================================
# VARNISH VCL — CACHE LAYER
# Role: HTML cache authority, TTL management, stale-while-revalidate,
#       cookie allowlist enforcement, bypass routing, X-Forwarded header
#       preservation.  Varnish must NOT enforce HTTPS or alter X-Forwarded
#       headers injected by Nginx.
# Backend: Apache on port 8080 (loopback, trusted internal transport).
# =============================================================================

import std;

# -----------------------------------------------------------------------------
# Backend — Apache + WordPress
# -----------------------------------------------------------------------------
backend apache {
    .host = "127.0.0.1";
    .port = "8080";
    .connect_timeout    = 5s;
    .first_byte_timeout = 120s;
    .between_bytes_timeout = 60s;
    .probe = {
        .url       = "/health";
        .timeout   = 3s;
        .interval  = 10s;
        .window    = 5;
        .threshold = 3;
    }
}

# =============================================================================
# vcl_recv — Request processing
# Decides: cache lookup, pass, or pipe.
# =============================================================================
sub vcl_recv {
    set req.backend_hint = apache;

    # -------------------------------------------------------------------------
    # Preserve X-Forwarded headers injected by Nginx.  These must survive the
    # full path so WordPress and Mercator domain mapping work correctly.
    # -------------------------------------------------------------------------
    if (!req.http.X-Forwarded-For) {
        set req.http.X-Forwarded-For = client.ip;
    }

    # -------------------------------------------------------------------------
    # Bypass routes — these paths must never be served from cache.
    # -------------------------------------------------------------------------

    # WordPress admin and login — always bypass.
    if (req.url ~ "(?i)^/wp-(admin|login\.php)") {
        return (pass);
    }

    # STAR dashboards — authenticated member surfaces.
    if (req.url ~ "(?i)^/star-") {
        return (pass);
    }

    # GraphQL — never cache; rate-limited and persisted-query controlled.
    if (req.url ~ "(?i)^/graphql") {
        return (pass);
    }

    # TUS / Submission Core upload paths — pipe to avoid body buffering that
    # could cause timeout or memory pressure on slow mobile connections.
    if (req.url ~ "(?i)^/files/") {
        return (pipe);
    }

    # Submission Core (non-TUS routes) — pass; never cache.
    if (req.url ~ "(?i)^/submission") {
        return (pass);
    }

    # WordPress cron — never cache.
    if (req.url ~ "(?i)^/wp-cron\.php") {
        return (pass);
    }

    # xmlrpc — pass (Nginx blocks this; belt-and-suspenders).
    if (req.url ~ "(?i)^/xmlrpc\.php") {
        return (pass);
    }

    # -------------------------------------------------------------------------
    # Only cache GET and HEAD requests.
    # POST/PUT/DELETE/PATCH always go to origin.
    # -------------------------------------------------------------------------
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    # -------------------------------------------------------------------------
    # Cookie allowlist — enforced on all non-bypassed requests.
    #
    # At this point in vcl_recv, all bypass routes have already returned:
    # /wp-admin, /wp-login.php, /star-*, /graphql, /files/, /submission.
    # Only public-facing routes remain.
    #
    # Logic:
    #   • No session/auth cookies → strip all cookies so the response can
    #     be served from cache (anonymous public page).
    #   • Session/auth cookies present → pass to origin; do not cache.
    #
    # Both URL match and cookie regex are case-insensitive ((?i) prefix) —
    # some WordPress proxies normalise cookie names inconsistently.
    # [^;]* (not [^;]+) handles empty-value cookie segments correctly.
    # -------------------------------------------------------------------------
    if (req.http.Cookie) {
        if (req.http.Cookie !~ "(?i)(wordpress_logged_in_|wp-postpass_|woocommerce_items_in_cart|wp_woocommerce_session_|SCF_)") {
            # No recognised session cookie — strip and allow cache lookup.
            unset req.http.Cookie;
        } else {
            # Authenticated session detected — bypass cache and go to origin.
            return (pass);
        }
    }

    # -------------------------------------------------------------------------
    # Strip geo-hash query parameters (?v=...) on authenticated routes to
    # prevent cache key fragmentation while preserving session integrity.
    # -------------------------------------------------------------------------
    if (req.url ~ "(\?|&)v=[^&]*") {
        set req.url = regsuball(req.url, "(\?|&)v=[^&]*", "");
    }

    # -------------------------------------------------------------------------
    # Normalise cache-varying Accept header for WebP/AVIF image negotiation.
    # -------------------------------------------------------------------------
    if (req.http.Accept ~ "image/avif") {
        set req.http.X-Accept-Image = "avif";
    } else if (req.http.Accept ~ "image/webp") {
        set req.http.X-Accept-Image = "webp";
    } else {
        set req.http.X-Accept-Image = "default";
    }

    return (hash);
}

# =============================================================================
# vcl_pipe — used for TUS upload paths to avoid body buffering.
# =============================================================================
sub vcl_pipe {
    # Varnish vcl_pipe flushes the connection after the piped TUS session ends.
    # Setting Connection: close prevents Varnish from reusing the backend
    # connection for a different request after the pipe terminates.
    set req.http.connection = "close";
    return (pipe);
}

# =============================================================================
# vcl_hash — cache key construction
# =============================================================================
sub vcl_hash {
    hash_data(req.url);
    hash_data(req.http.host);

    # Include image format negotiation in the cache key.
    if (req.http.X-Accept-Image) {
        hash_data(req.http.X-Accept-Image);
    }

    return (lookup);
}

# =============================================================================
# vcl_backend_response — set TTLs and grace periods
# =============================================================================
sub vcl_backend_response {
    # -------------------------------------------------------------------------
    # Public HTML pages — 10-minute TTL with stale-while-revalidate grace
    # of 60 seconds so users never see a cache-miss stall.
    # -------------------------------------------------------------------------
    if (beresp.http.Content-Type ~ "text/html") {
        if (beresp.http.Cache-Control !~ "no-store|no-cache|private") {
            set beresp.ttl   = 10m;
            set beresp.grace = 60s;
        }
    }

    # -------------------------------------------------------------------------
    # Public static assets — long TTL driven by versioned filenames.
    # -------------------------------------------------------------------------
    if (bereq.url ~ "\.(css|js|woff2?|ttf|otf|eot)(\?.*)?$") {
        set beresp.ttl   = 180d;
        set beresp.grace = 1d;
        unset beresp.http.Set-Cookie;
    }

    if (bereq.url ~ "\.(jpg|jpeg|png|gif|svg|ico|webp|avif)(\?.*)?$") {
        set beresp.ttl   = 30d;
        set beresp.grace = 1d;
        unset beresp.http.Set-Cookie;
    }

    # -------------------------------------------------------------------------
    # Never cache responses that explicitly opt out.
    # -------------------------------------------------------------------------
    if (beresp.http.Cache-Control ~ "no-store|no-cache|private") {
        set beresp.uncacheable = true;
        set beresp.ttl = 120s;
        return (deliver);
    }

    # -------------------------------------------------------------------------
    # Do not cache responses carrying Set-Cookie (authenticated responses).
    # -------------------------------------------------------------------------
    if (beresp.http.Set-Cookie) {
        set beresp.uncacheable = true;
        set beresp.ttl = 120s;
        return (deliver);
    }

    # -------------------------------------------------------------------------
    # Mark responses with Vary: Accept for image format negotiation.
    # -------------------------------------------------------------------------
    if (beresp.http.Vary) {
        set beresp.http.Vary = beresp.http.Vary + ", Accept";
    } else {
        set beresp.http.Vary = "Accept";
    }

    return (deliver);
}

# =============================================================================
# vcl_deliver — add diagnostic headers and clean up
# =============================================================================
sub vcl_deliver {
    # Add cache status header for debugging (remove in production if desired).
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
        set resp.http.X-Cache-Hits = obj.hits;
    } else {
        set resp.http.X-Cache = "MISS";
    }

    # Remove internal Varnish headers before delivering to Nginx/client.
    unset resp.http.X-Varnish;
    unset resp.http.Via;

    return (deliver);
}

# =============================================================================
# vcl_synth — custom synthetic responses (e.g. redirects)
# =============================================================================
sub vcl_synth {
    set resp.http.Content-Type = "text/plain; charset=utf-8";
    return (deliver);
}
