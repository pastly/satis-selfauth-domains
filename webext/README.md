A Firefox / Tor Browser web extension for self-authenticating traditional
domains (SAT domains) and alternate services.

The extension requires the [securityInfo API][], which first appeared in FF 62.
Tor Browser will have this API no later than July 2019 (when the next [ESR][]
of FF is released). Alpha versions of Tor Browser may have this API if the TB
devs choose to backport it.

Some compromises have been made in order to allow this extension to work in Tor
Browser 8 without browser modifications.

See LICENSE.md for license information.

[securityInfo API]: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/getSecurityInfo
[ESR]: https://www.mozilla.org/en-US/firefox/organizations/
