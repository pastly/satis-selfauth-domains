# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## Unreleased

Nothing.

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