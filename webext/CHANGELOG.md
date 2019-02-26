# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## Unreleased

### Added

- User may filter Alt-Svc headers. We remove them by default, and allow users
  to reallow them on an individual basis only. If the same Alt-Svc is used on
multiple domains (as would be the case if cloudflare were still running its
onion alternate services, for example), it has to be explicitly allowed for
each domain.

### Changed

- When checking a TLS cert for a SAT domain in the url bar, do not require the
  traditional part (`foo.com` of `[56char]onion.foo.com`) to be the subject of
the certificate. It can be a subject alt name (SAN), just like the SAT domain.
(GH issue #1)
- AltSvc headers are now stored in local state, not session state

### Removed

- The hardcoded "preload" list of aternate services known to exist.

## v1.1.0 - 2019-02-22

### Added

- Optionally do not require the SAT domain that we're visiting to exist in the
  TLS certificate, instead being covered by a wildcard. When enabled,
`[56char]onion.foo.com` is allowed if `*.foo.com` is in the certificate (and it
better be, the browser should have halted this connection long before if it
isn't!).
- Optionally do not require SAT domain Alt-Svc headers to exist in the TLS
  certificate. This doesn't change any of the regular Alt-Svc requirements in
browsers, like requiring it to be able to use the TLS certificate that the
origin domain is using. Requiring the Alt-Svc domain (in this case a SAT
domain) to be in the TLS certificate too is *more* strict.
- Require traditional part of SAT domain Alt-Svc headers to be in TLS
  certificate.

### Changed

- Catch exception when trying to get securityInfo and the API doesn't exist.
- Store and display all AltSvc headers we get, not just the SAT and onion ones
- Min version of FF only needs to be 63, not 65
- Improve log strings with the time
- Improve log strings with func, file, and line info

## v1.0.2 - 2019-02-19

### Changed

- Most usages of "Alliuminated" are now "SAT" instead. This mean the name of
  the extension has changed too.

## v1.0.1 - 2019-02-13

### Fixed

- pages/index.html was moved to pages/badSigEtc.html, but when updating the
  code I missed a spot. Redirects to this error page when -- for example -- the
onion sig header is bad, we not working. Installing the extension from its
archive would result in no warnings. Temporarily installing it locally would
produce a weird error page from Firefox.

## v1.0.0 - 2019-02-12

These features have existed for some amount of time in older versions than
1.0.0, but now for some reason I'm calling this close enough to "feature
complete" that they are now "added." Or whatever. Okay here it goes ...

### Added

- When visiting Self-Authenticating Traditional (SAT) domain names, the
  webserver must provide us with a header containing signed data. A SAT domain
takes the form of [56char]onion.foo.com. The data must be recently signed by
the ed25519 key encoded into the SAT domain and tie the SAT domain to the TLS
certificate currently in use. Right now we are in "roll-out relaxation" so we
don't require the SAT to be in the certificate (though there still must at
least be a wildcard in the certificate that covers it, else Firefox would throw
a fit), but in the long run we want this requirement for full and proper
security.

- Filtering of v3 onion Alternative Services (AltSvc) and of SAT AltSvces. If
  the webserver provides an AltSvc that is either a v3 onion or a SAT domain,
then it must also provide proper signed data in a header in order for the
extension to give it to the browser. Proper means that the signed data was
recently signed by the ed25519 key encoded in the name. Once Tor Browser
supports the securityInfo API, the extension needs to be updated to check that
the base domain (foo.com in [56char]onion.foo.com) is in the current TLS
certificate. Even when fully implemented, this  filtering of AltSvc headers
provides no where near the same level of added security as visiting SAT domains
directly.

- An implementation of Dirt Simple Trust (DST). The extensions watches as you
  browse the web, and if you ever come a cross a specially formatted list of
SAT domains *while visiting a SAT domain*, it will remember this list. You can
tell the exention which lists have maintainers whom you trust to properly
attest Tradition domain <--> SAT domain mappings. Then as you browse the web
and stumble upon SAT domains,  extension will tell you which lists (if any)
they are on.

- Setting "Attested SAT Domains Only": Enabling this setting requires that all
  SAT domains that you visit appear on at least one SAT domain list that you
trust.
