Jan 2019 note: This video demonstrates an old version of the extension and
website. See the main README for more information.

                Alliuminated domain
                -------------------

This video should play in Firefox and Chrome.

At 0:06: The user clicks on the link to the alliuminated domain so that the
extension will work.

At 0:17: The user clicks on links to /index.html and /good.html. While they
have the same content on our website, they are totally different pages and
could have totally different content (see how the URL in the URL bar changes).
Since the user has our extension as is visiting an alliuminated domain, it
performed its checks automatically in the background and deemed everything to
be okay, hence the user was allowed to visit these pages.

At 0:25: The user clicks on a link to /badtime.html. For testing purposes, we
made our webserver send Alliumination information to the user's browser that is
outdated, so the extension stops the user from visiting this page. Notice that
the page being displayed is from our extension, not from the webserver.

At 0:33: The user returns to the website. Notice the page being displayed is
from the webserver again.

At 0:40: The user tries /baddomain.html. Like /badtime.html, we made our
webserver serve bad information so the extension could be tested. Notice again
that the page displayed is from our extension, not the webserver.
