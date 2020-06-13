# Contents

## webext/

A Firefox web extension for checking SAT addresses (validating signatures,
retrieving sattestation lists, verifying site sattestations).

## server-scripts/

Scripts and config templates useful for the managing the server-side. This
includes an nginx config template, an apache httpd config, and update script,
and update scripts.

# Setting Up Client Side (Easy mode)

The extension may be installed as a "Temporary Extension" in Firefox and Tor
Browser by following the instructions under "Load the extension into Firefox".

The file may be downloaded from:
https://www.selfauthdomain.info/sata.xpi

# Setting Up Client Side (Hard mode)

## Download this repository

You need the Firefox/Tor Browser web extension located in the webext/
directory.

## Load the extension into Firefox

1. In the URL bar, type "about:debugging"

2. Click "Load Temporary Add-on..."

3. Navigate to the webext/ directory of this repo

4. Select any file in the webext/ directoy (for example, manifest.json) and
   click "Open"

The extension should now be loaded. Clicking on "Debug" in the extension's
information box will open up debug logs that the extension generates.
https://i.imgur.com/zS4BvGQ.png

## Verify the extension is working

There is some demo websites available at:
  - https://sattestorA.selfauthdomain.info
  - https://sattestee1.selfauthdomain.info
  - https://sattestorB.selfauth.site
  - https://sattestee2.selfauth.site
that can be used for testing. Visiting either sattestorA.selfauthdomain.info or
https://sattestorB.selfauth.site and then clicking on the extension's onion button
in the top right should list 1 or 2 Alt-Svc that it has allowed to be passed on
to the browser.

Visiting the "(NEW)" SAT address on that page
https://selfauth.site?onion=ilfu36iq3wde4htupfx6kbelsdgm5tnkgjtvyw3ijorqd6tdipekhzqd
should be allowed to work. Everything should look the same on the page.

When at the SAT domain, visiting one of the bad links (like /baddomain.html)
should be disallowed.

At the contains some links to other SAT addresses that the owner of
selfauth.site has verified as safe mappings. A sattestor's sattestation list is
available at the /.well-known/sattestion.json resource. For example, at
https://sattestorA.selfauthdomain.info/.well-known/sattestation.json

To verify the extension has automatically loaded these off the page and into
memory (NOTE: in a more real version of this extension, it would prompt the
user before automatically trusting this list), click on the onion button and
check that there's a "Trusted SAT mappings lists" section with one list in it
with 2 domain mappings.

## Setting Up Server Side

Assumptions:

- Your satsigner souce code directory is /home/satis/src/satsigner.
- Your traditional domain is example.com.
- Tor will generate the onion address
  rbxel6kjp4o7hz6fmy7af4nv5vyg37fnwddfxnzxqzss2h7lrkzs4rid.onion for you
- Your TLS certificate chain will be located at
  /etc/letsencrypt/live/example.com/fullchain.pem
- Your TLS fingerprint will be
  1F897271B61AFF9F581CEFE869E191C1C549C2F552757F96A75215187FA2767B

## Get and build my branch of Tor

## Run satsigner

The program requires 8 parameters:
  - path to keys
  - hostname
  - onion address
  - fingerprint
  - self-labels
  - sattestor labels
  - in (config) directory
  - out directory

The \<path to keys\> is the path to the onion serivce keys (secret and public).

The \<hostname\> is the DNS name (example.com)

The \<onion address\> is...the 56 character, base-32 encoded v3 onion address (not
    including '.onion') (rbxel6kjp4o7hz6fmy7af4nv5vyg37fnwddfxnzxqzss2h7lrkzs4rid)

The \<fingerprint\> is the TLS certificate fingerprint
    (1F897271B61AFF9F581CEFE869E191C1C549C2F552757F96A75215187FA2767B)

The \<self-labels> is a comma-separated list of labels the site gives itself (such as 'news')

The \<sattestor labels\> is a comma-separated list of contextual labels for which this site,
    as a sattestor, is trustworthy

The \<in directory\> is the path to a directory containing a sattestation.csv file

The \<out directory\> is the path to a directory where the SAT headers and
    sattestation.json should be written

## Generate a TLS certificate with your SAT domain in it

With the assumptions given at the beginning of this section, your traditional
domain is example.com and your SAT domain is
rbxel6kjp4o7hz6fmy7af4nv5vyg37fnwddfxnzxqzss2h7lrkzs4ridonion.example.com.
(Note the lack of a dot before "onion"). The SAT domain format is canonical
for SAT addresses.

Do whatever is necessary to obtain a TLS certificate with both of these names
in it. This may mean adding the SAT domain to your example.com nginx config
file, updating your DNS records, and using Let's Encrypt.

Note the location of your shiny new TLS certificate's fullchain.pem

## Create Signed Headers and Sattestations

You should now run satsigner periodically, roughly every 6 days. You can run this
in a cronjob (or use something more sophisticated). You'll need to recompute the
TLS certificate's digest occasionally.

      ./satsigner /var/lib/tor/example.com example.com rbxel6kjp4o7hz6fmy7af4nv5vyg37fnwddfxnzxqzss2h7lrkzs4rid 1F897271B61AFF9F581CEFE869E191C1C549C2F552757F96A75215187FA2767B science,news science,news satsigner_in/ satsigner_out/

To be specific, the digest is the SHA-256 hash of the DER encoding of the certificate.

      openssl x509 -inform pem -in /etc/letsencrypt/live/example.com/fullchain.pem -outform der | sha256sum | cut -c -64 | tr '[a-z]' '[A-Z]'

## Tell your webserver about the signed data

satsigner has generated its signature over the appropriate data in
satsiger_out. Now that information needs to be included in the webserver's
configuration file.

This repository includes nginx.conf.tmpl, update-satis-sig-nginx-conf.sh,
htaccess.tmpl, and update-satis-sig-apache-conf.sh (all in server-scripts/) to get this
data into either nginx or apache. 

The nginx config files are not tested.

### Configure Apache httpd

1. Edit the update-satis-sig-apache-conf.sh script so the paths at the top of the file are appropriate for your configuration

2. In htaccess.tmpl, edit the alt-svc header so it uses your onion service

3. reload apache

       systemctl reload httpd


### get that into nginx's config (previous instructions, not tested recently)

1. copy my nginx conf into a template I can edit

2. add the self-auth domain to the server_name line(s) so nginx will correctly
   respond to traffic on that name too.

3. plan on using the macro processor m4 to find and replace text in the
   template file ...

4. decide what text m4 will be looking for. For example M4_SATIS_SIG ...

5. tell nginx to add an X-SAT-Sig header to all queries:

       add_header X-SAT-Sig M4_SATIS_SIG;

6. run m4 with the nginx config template and outputting the result to the
   real nginx config file.

       m4 -DM4_SATIS_SIG="$B64_SIG" nginx.conf.tmpl > /etc/nginx/sites-available/example.com

7. reload nginx

       systemctl reload nginx

Now when people visit example.com, their browser should be getting an X-SAT-Sig
header. Our extension will be expecting it if they visit
rbxel6kjp4o7hz6fmy7af4nv5vyg37fnwddfxnzxqzss2h7lrkzs4ridonion.example.com.

## Wrap these processes up in scripts and run them periodically

If your TLS certificate is going to change regularly (for example, Let's
Encrypt certificates expire every 90 days), you should automatically run the
update-torrc.sh script every time you change your TLS certificate. I have mine
run right after 'certbot renew' as a cronjob.

The signatures Tor creates expire every few days. If Tor is running constantly
in the background, it will be updating its signature files every day by
default. Thus you just need to run update-satis-sig-nginx-conf.sh (or your
simplier script) daily to pick up the changes and put them in your nginx
config. As long as your Tor is configured to generate these files much more
often than they expire, it's not terribly important that the get updated in
your nginx config immediately. Just make sure it gets done each day as a
cronjob, for example.

## Older info

## satis.system33.pw/

Website files used in the video demonstration

## Alliuminated domain.webm

A video demonstrating the product of (an older version of) these files. See its
README for more information. SAT domains used to be called "Alliuminated"
domains.

## tor/

A git submodule pointing to the Tor code that has the necessary changes to
generate these signatures. If you want to get it manually for some reason, it's
the branch selfauth-sig-0.3.5.7 at https://github.com/pastly/public-tor

## tor.selfauth-sig-0.3.5.7.tar.xz

The Tor code as of my branch selfauth-sig-0.3.5.7 in case this is easier for
you than a submodule.
