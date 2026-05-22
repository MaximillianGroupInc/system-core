## Summary

<!-- One sentence describing what this PR changes and why. -->

## Type of change

- [ ] Bug fix (existing behaviour was incorrect)
- [ ] Configuration hardening / security improvement
- [ ] Performance improvement
- [ ] Governance / documentation only
- [ ] New feature / capability

## Affected components

- [ ] `nginx/` — Nginx perimeter layer
- [ ] `varnish/` — Varnish cache layer
- [ ] `apache/` — Apache application layer
- [ ] `var/www/html/wp-content/mu-plugins/` — WordPress MU plugins
- [ ] `.github/` — Repository governance / CI

## Validation checklist

All items must be checked before requesting review.

- [ ] `nginx -t` passes (or Docker equivalent — see CONTRIBUTING.md)
- [ ] `varnishd -C -f varnish/default.vcl` passes (or Docker equivalent)
- [ ] `apachectl -t` passes (or Docker equivalent)
- [ ] `php -l` passes for any modified PHP files
- [ ] No secret values committed (worker secret file remains empty placeholder)
- [ ] Cloudflare IP ranges are still in sync if touching `spx-cloudflare-trust.conf` or the `$from_cloudflare` geo block

## Testing notes

<!-- How was this change tested? Include environment, commands run, and any
     observed behaviour before and after. -->

## Risk assessment

<!-- What could break if this change is wrong? Is there a blast radius beyond
     the files modified? Is a Nginx/Varnish/Apache reload sufficient or does
     the service need a full restart? -->

**Reload or restart required:**
- [ ] `nginx -s reload`
- [ ] `systemctl reload varnish`
- [ ] `systemctl reload apache2`
- [ ] Full service restart (explain why below)

## Rollback notes

<!-- How do you revert this change quickly if something goes wrong in
     production? A `git revert` + reload is usually sufficient, but call
     out anything that requires additional steps (e.g. clearing Varnish
     cache, rotating a secret, updating Cloudflare). -->

## CHANGELOG entry

<!-- Paste the line(s) you added to CHANGELOG.md under `[Unreleased]`. -->
