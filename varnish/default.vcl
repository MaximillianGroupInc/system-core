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
# Backends
# -----------------------------------------------------------------------------

# Apache + WordPress — primary backend for all cacheable/pass traffic.
backend apache {
    .host = "127.0.0.1";
    .port = "8080";
    .connect_timeout    = 5s;
    .first_byte_timeout = 120s;
    .between_bytes_timeout = 60s;
    .probe = {
        # /health is a lightweight static endpoint in Apache that returns 200
        # without invoking WordPress or PHP-FPM (see Apache config).
        .url       = "/health";
        .timeout   = 3s;
        .interval  = 10s;
        .window    = 5;
        .threshold = 3;
    }
}

# TUS Node server — dedicated backend for large resumable audio/media uploads.
# /files/ traffic is piped directly here to avoid body buffering, Varnish
# memory pressure, and the default 60s pipe timeout that would kill long
# uploads on slow mobile connections.
#
# Timeout rationale for large audio files:
#   connect_timeout  — TUS Node is loopback-local; 5s is generous.
#   first_byte_timeout — The TUS Node may need time before it acknowledges
#       a large chunk; 300s gives headroom for slow mobile uplinks.
#   between_bytes_timeout — Time between successive data chunks on the
#       upload stream; 120s accommodates bursty African mobile connections.
backend tus_node {
    .host = "127.0.0.1";
    .port = "1080";
    .connect_timeout       = 5s;
    .first_byte_timeout    = 300s;
    .between_bytes_timeout = 120s;
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

    # WordPress admin and all wp-*.php files — always bypass.
    if (req.url ~ "(?i)^/(wp-admin(?:/|$|\?)|wp-[^/]*\.php(?:$|\?))") {
        return (pass);
    }

    # STAR dashboards — authenticated member surfaces.
    if (req.url ~ "(?i)^/star-") {
        return (pass);
    }

    # WooCommerce cart — authenticated session surface.
    if (req.url ~ "(?i)^/cart(/|$|\?)") {
        return (pass);
    }

    # GraphQL — cache anonymous GET requests only. Nginx allows GET/HEAD to
    # /graphql (via limit_except POST GET HEAD), and Apache now also permits
    # GET/HEAD so that Varnish can populate its cache on a miss.
    #
    # WP GraphQL's GET-based persistent-query caching issues GET requests; the
    # data served here is a static public dictionary (words + definitions) that
    # is never user-specific, so anonymous GET responses are safe to cache.
    # POST and other methods fall through to the "Only cache GET/HEAD" guard
    # below, which passes them to origin uncached.
    #
    # Auth signals checked (any → pass to origin, never cache):
    #   - Authorization header  (Bearer/Basic tokens, JWT, etc.)
    #   - X-WP-Nonce header     (WordPress nonce — user-scoped)
    #   - Known session/auth and UX-affecting cookies (aligned with the
    #     general cookie allowlist; extend alongside it as needed, plus SCF_
    #     for Submission Core).
    if (req.method == "GET" && req.url ~ "^/graphql") {
        if (req.http.Authorization ||
            req.http.X-WP-Nonce ||
            req.http.Cookie ~ "(?i)(wp_logged_in|wordpress_logged_in_|wp-postpass_|woocommerce_cart_hash|woocommerce_items_in_cart|wp_woocommerce_session_|woocommerce_recently_viewed|store_notice|SCF_)") {
            return (pass);
        }
        unset req.http.Cookie;
        return (hash);
    }
    
    # TUS / Submission Core upload paths — route to TUS Node backend and pipe
    # to avoid any request-body buffering that would cause timeout or memory
    # pressure on slow mobile connections.
    #
    # These are large audio files (see README: "TUS Resumable Audio Upload"):
    # Varnish must not buffer,
    # queue, or cache any part of the upload stream.  Routing directly to the
    # tus_node backend (port 1080) bypasses Apache entirely for this path.
    # Nginx handles /files/ → TUS directly in normal operation; this rule is
    # belt-and-suspenders for any traffic that reaches Varnish via a different
    # path.
    if (req.url ~ "(?i)^/files/") {
        set req.backend_hint = tus_node;
        return (pipe);
    }

    # Submission Core (non-TUS routes) — pass; never cache.
    if (req.url ~ "(?i)^/submission") {
        return (pass);
    }

    # index.php and xmlrpc.php — pass (Nginx blocks xmlrpc; belt-and-suspenders).
    if (req.url ~ "(?i)^/(index|xmlrpc)\.php") {
        return (pass);
    }

    # Sitemaps — bypass; never cache dynamic XML sitemaps.
    if (req.url ~ "(?i)^/sitemap[^/.]*\.xml") {
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
    # /wp-admin, /wp-*.php, /star-*, /cart, /files/, /submission,
    # /index.php, /xmlrpc.php, /sitemap*.xml.
    # Anonymous GET /graphql (no auth signals) has had its Cookie stripped and
    # returned (hash); authenticated /graphql was already passed above.
    # POST /graphql falls through the GET/HEAD guard above and is passed.
    # Only public-facing GET/HEAD routes remain here.
    #
    # Logic:
    #   • No session/auth cookies → strip all cookies so the response can
    #     be served from cache (anonymous public page).
    #   • Session/auth cookies present → pass to origin; do not cache.
    #
    # The cookie regex uses (?i) (case-insensitive) and matches cookie name
    # prefixes as substrings within the Cookie header value.
    # -------------------------------------------------------------------------
    if (req.http.Cookie) {
        if (req.http.Cookie !~ "(?i)(wp_logged_in|wordpress_logged_in_|wp-postpass_|woocommerce_cart_hash|woocommerce_items_in_cart|wp_woocommerce_session_|woocommerce_recently_viewed|store_notice|SCF_)") {
            # No recognised session cookie — strip and allow cache lookup.
            unset req.http.Cookie;
        } else {
            # Authenticated session detected — bypass cache and go to origin.
            return (pass);
        }
    }

    # -------------------------------------------------------------------------
    # Normalise Accept header for WebP/AVIF image format negotiation.
    # Only set for image requests — avoids fragmenting the HTML/text cache into
    # avif/webp/default variants when the response does not actually vary.
    # ⚠  The image extension regex below must stay in sync with the matching
    #    patterns in vcl_backend_response (TTL and Vary rules).
    # -------------------------------------------------------------------------
    if (req.url ~ "\.(jpg|jpeg|png|gif|svg|ico|webp|avif)(\?.*)?$") {
        if (req.http.Accept ~ "image/avif") {
            set req.http.X-Accept-Image = "avif";
        } else if (req.http.Accept ~ "image/webp") {
            set req.http.X-Accept-Image = "webp";
        } else {
            set req.http.X-Accept-Image = "default";
        }
    }

    return (hash);
}

# =============================================================================
# vcl_pipe — used for TUS upload paths to avoid body buffering.
# =============================================================================
sub vcl_pipe {
    # Varnish vcl_pipe flushes the connection after the piped TUS session ends.
    # bereq.http.Connection controls the backend-side TCP connection header for
    # piped requests.  Setting it to "close" prevents Varnish from reusing the
    # backend connection for a different request after the pipe terminates.
    # (req.http.Connection only affects the client side and has no effect here.)
    set bereq.http.Connection = "close";
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

    # GraphQL GET — incorporate query-id into cache key so different persistent
    # queries cached at the same /graphql URL map to distinct cache objects.
    # Only GET reaches here: vcl_recv passes POST and all non-GET /graphql
    # requests to origin before hash, so no POST body collision is possible.
    if (req.method == "GET" && req.url ~ "^/graphql") {
        if (req.http.x-graphql-query-id) {
            hash_data(req.http.x-graphql-query-id);
        }
    }

    return (lookup);
}

# =============================================================================
# vcl_backend_response — set TTLs and grace periods
# =============================================================================
sub vcl_backend_response {

    # -------------------------------------------------------------------------
    # GraphQL JSON — cache it (only for anonymous, cacheable 200 JSON responses)
    #
    # Gated on both response signals (status, Content-Type, Cache-Control) and
    # request auth signals (Authorization, X-WP-Nonce, session cookies) so
    # that authenticated or personalized responses are never stored in cache,
    # even if vcl_recv somehow passed them to origin.
    # -------------------------------------------------------------------------
    if (bereq.url ~ "^/graphql" &&
        beresp.status == 200 &&
        beresp.http.Content-Type ~ "application/json" &&
        beresp.http.Cache-Control !~ "(?i)no-store|no-cache|private" &&
        !bereq.http.Authorization &&
        !bereq.http.X-WP-Nonce &&
        bereq.http.Cookie !~ "(?i)(wp_logged_in|wordpress_logged_in_|wp-postpass_|woocommerce_cart_hash|woocommerce_items_in_cart|wp_woocommerce_session_|SCF_)") {
        set beresp.ttl = 1h;
        set beresp.grace = 5m;
    }
    # -------------------------------------------------------------------------
    # Public HTML pages — 10-minute TTL with stale-while-revalidate grace
    # of 60 seconds so users never see a cache-miss stall.
    # Only 2xx responses are eligible; 3xx redirects (which may be temporary)
    # and error pages (4xx/5xx) get a short TTL to prevent stale redirect
    # targets or transient errors from being served from cache for 10 minutes.
    # -------------------------------------------------------------------------
    if (beresp.http.Content-Type ~ "text/html") {
        if (beresp.http.Cache-Control !~ "(?i)no-store|no-cache|private") {
            if (beresp.status >= 200 && beresp.status < 300) {
                set beresp.ttl   = 10m;
                set beresp.grace = 60s;
            } else {
                # Short TTL for error pages — avoids persisting transient errors.
                set beresp.ttl   = 5s;
                set beresp.grace = 0s;
            }
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

    # ⚠  The image extension regex below must stay in sync with the matching
    #    pattern in vcl_recv (X-Accept-Image normalisation).
    if (bereq.url ~ "\.(jpg|jpeg|png|gif|svg|ico|webp|avif)(\?.*)?$") {
        set beresp.ttl   = 30d;
        set beresp.grace = 1d;
        unset beresp.http.Set-Cookie;
    }

    # -------------------------------------------------------------------------
    # Processed/served audio and video assets — long TTL.
    # These are already-transcoded files served to end-users; upload streams
    # (/files/) never reach this path (they are piped to tus_node in vcl_recv).
    # Includes .weba (WebM Audio) which browsers may request instead of .mp3
    # or .wav based on declared Accept capabilities or bandwidth.
    # Also covers legacy container formats (flv, wmv, m4v, mpeg/mpg) for
    # compatibility with older content in the media library.
    # ⚠  Extension list must stay in sync with the Vary: Accept rule below.
    # -------------------------------------------------------------------------
    if (bereq.url ~ "\.(mp3|mp4|mpeg|mpg|ogg|webm|weba|wav|flac|aac|m4a|m4v|opus|mov|avi|mkv|flv|wmv)(\?.*)?$") {
        set beresp.ttl   = 30d;
        set beresp.grace = 1d;
        unset beresp.http.Set-Cookie;
    }

    # -------------------------------------------------------------------------
    # Document, spreadsheet, and presentation assets — long TTL; static by nature.
    # PDFs, Word documents, Excel spreadsheets, and PowerPoint files are versioned
    # by filename in WordPress media library uploads and are safe to cache long-term.
    # -------------------------------------------------------------------------
    if (bereq.url ~ "\.(pdf|doc|docx|ppt|pptx|xls|xlsx)(\?.*)?$") {
        set beresp.ttl   = 30d;
        set beresp.grace = 1d;
        unset beresp.http.Set-Cookie;
    }

    # -------------------------------------------------------------------------
    # Never cache responses that explicitly opt out.
    # -------------------------------------------------------------------------
    if (beresp.http.Cache-Control ~ "(?i)no-store|no-cache|private") {
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
    # Add Vary: Accept for image and audio/video format negotiation.
    # Only applied to media responses — avoids fragmenting the HTML/text/JS
    # cache on the full Accept header value and destroying hit rates.
    #
    # Images: browsers negotiate WebP/AVIF via Accept: image/avif, image/webp.
    # Audio: clients negotiate containers via Accept (e.g., audio/webm [weba]
    # vs audio/ogg vs audio/mpeg [mp3] vs audio/wav) based on codec support or
    # bandwidth capability — each variant gets its own cache slot.
    # Video: similar Accept-based negotiation for video/webm vs video/mp4.
    # ⚠  Extension list must stay in sync with the audio/video TTL rule above.
    # -------------------------------------------------------------------------
    if (bereq.url ~ "\.(jpg|jpeg|png|gif|svg|ico|webp|avif|mp3|mp4|mpeg|mpg|ogg|webm|weba|wav|flac|aac|m4a|m4v|opus|mov|avi|mkv|flv|wmv)(\?.*)?$") {
        if (beresp.http.Vary) {
            set beresp.http.Vary = beresp.http.Vary + ", Accept";
        } else {
            set beresp.http.Vary = "Accept";
        }
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
