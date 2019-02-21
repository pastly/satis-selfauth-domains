# Contents

## satis.system33.pw/

Website files used in the video demonstration

## webext/

A Firefox web extension for checking SAT domain names.

## Alliuminated domain.webm

A video demonstrating the product of (an older version of) these files. See its
README for more information. SAT domains used to be called "Alliuminated"
domains.

## server-scripts/

Scripts and config templates useful for the managing the server-side. This
includes an nginx config template and update script, as well as a torrc config
template and update script.

## tor/

A git submodule pointing to the Tor code that has the necessary changes to
generate these signatures. If you want to get it manually for some reason, it's
the branch selfauth-sig-0.3.5.7 at https://github.com/pastly/public-tor

## tor.selfauth-sig-0.3.5.7.tar.xz

The Tor code as of my branch selfauth-sig-0.3.5.7 in case this is easier for
you than a submodule.

# Setting Up Client Side (Easy mode)

As of 5 Feb 2019, the extension is signed by Mozilla and able to be installed
from a signed archive file. You do not have to download this repository to
install the extension.

Simply visit
https://demos.traudt.xyz/extensions/firefox/sat_domain_tools/ in
Firefox (and probably Tor Browser, see "Hard mode" section below), select the
highest-version \*.xpi file, and allow the extension to be installed.

It is configured to auto update.

# Setting Up Client Side (Hard mode)

At the time of writing (1 Feb 2019) Tor Browser has not been tested recently,
but it's alpha 8.5.X series is assumed to still be working. Firefox 65 does
work.

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

There is a toy website at https://satis.system33.pw that can be used for
testing. Visiting that page and then clicking on the extension's onion button
in the top right should list 1 or 2 Alt-Svc that it has allowed to be passed on
to the browser.

Visiting the "(NEW)" SAT domain on that page
https://hllvtjcjomneltczwespyle2ihuaq5hypqaavn3is6a7t2dojuaa6rydonion.satis.system33.pw/
should be allowed to work. Everything should look the same on the page.

When at the SAT domain, visiting one of the bad links (like /baddomain.html)
should be disallowed.

At the bottom of the page is a list of SAT domains that the owner of
satis.system33.pw has verified as safe mappings. These are readable by the
extension.

To verify the extension has automatically loaded these off the page and into
memory (NOTE: in a more real version of this extension, it would prompt the
user before automatically trusting this list), click on the onion button and
check that there's a "Trusted SAT mappings lists" section with one list in it
with 2 domain mappings.

## Setting Up Server Side

Assumptions:

- Your tor souce code directory is /home/satis/src/tor.
- Your traditional domain is example.com.
- Tor will generate the onion address
  rbxel6kjp4o7hz6fmy7af4nv5vyg37fnwddfxnzxqzss2h7lrkzs4rid.onion for you
- Your TLS certificate chain will be located at
  /etc/letsencrypt/live/example.com/fullchain.pem
- Your TLS fingerprint will be
  1F897271B61AFF9F581CEFE869E191C1C549C2F552757F96A75215187FA2767B

## Get and build my branch of Tor

See tor/ or tor.\*.tar.xz for the code. I include a build.sh script.

Don't run Tor yet.

## Configure Tor (first time)

Put the following in your torrc, located at /home/satis/src/tor/torrc

    SocksPort 0
    DataDirectory data
    Log notice file data/notice.log
    Log notice stdout
    PidFile data/tor.pid
    HiddenServiceDir data/hs-example.com
    HiddenServicePort 443
    HiddenServiceVersion 3

Run Tor briefly:

    ./src/app/tor -f torrc

It should run in the foreground without errors, and ctrl-c will kill it.  Don't
ctrl-c until Tor has logged '[notice] Bootstrapped 100%: Done'

There will now be a hostname file at data/hs-example.com/hostname. This is the
onion address Tor generated. Take note of it.

## Generate a TLS certificate with your SAT domain in it

With the assumptions given at the beginning of this section, your traditional
domain is example.com and your SAT domain is
rbxel6kjp4o7hz6fmy7af4nv5vyg37fnwddfxnzxqzss2h7lrkzs4ridonion.example.com.
(Note the lack of a dot before "onion")

Do whatever is necessary to obtain a TLS certificate with both of these names
in it. This may mean adding the SAT domain to your example.com nginx config
file, updating your DNS records, and using Let's Encrypt.

Note the location of your shiny new TLS certificate's fullchain.pem

## Configure Tor (second/final time)

We now have everything necessary to reconfigure Tor and run it for real.

Replace your torrc (at /home/satis/src/tor/torrc) with the following.

    SocksPort 0
    DataDirectory data
    Log notice file data/notice.log
    PidFile data/tor.pid
    %include example.com.torrc

(We removed logging to stdout and will now pull HiddenService\* config options
from the file example.com.torrc)

Find torrc.tmpl and update-torrc.sh in this repo (in the server-scripts
directory). The former is the template for example.com.torrc, and the latter
fills in the template to generate the actual example.com.torrc

Edit the variables at the top of update-torrc.sh to point to your actual
certificate, domain, torrc template, etc.

Run the script. It should complain about not being able to reload Tor (because
you haven't started Tor yet, right?). The error should be: 'cat: ...: No such
file or directory' followed by usage info for the 'kill' command. Anything else
and there's probably something wrong.

Once the script has been run once with only the allowed error, you should find
example.com.torrc now exists at /home/satis/src/tor/example.com.torrc.  Verify
it exists, it has your traditional domain (example.com), and it has your TLS
fingerprint. For example, it should look like this (without comments)

    HiddenServiceDir data/hs-example.com
    HiddenServicePort 443
    HiddenServiceVersion 3
    HiddenServiceSatisSig 1
    HiddenServiceSatisDomain example.com
    HiddenServiceSatisFingerprint 1F897271B61AFF9F581CEFE869E191C1C549C2F552757F96A75215187FA2767B
    HiddenServiceSatisSigInterval 86400

You should now run Tor continuously in the background. Ideally you wrap it up
in a script that is run on boot with a cronjob. To just run it in the
background now:

      ./src/app/tor -f torrc --quiet &

After a few seconds, data/notice.log should state
'[notice] Bootstrapped 100%: Done' followed by log lines stating it has wrote
some satis sig files.

## Tell your webserver aobut the signed data

Tor has generated its signature over the appropriate data in
data/hs-example.com/satis_sig. This file is just raw bytes, and we need to turn
that into base64-encoded bytes in an HTTP header that our webserver sends to
clients.

I use nginx and (at the time of writing) the included nginx.conf.tmpl and
update-satis-sig-nginx-conf.sh (both in server-scripts/) to get this data into
my nginx config. These are a little more complex than would be necessary for
other people, especially if you don't want to use the purposefully bad
signatures too.

I will now explain the script by walking you through how I would reimplement it
to be simpler.

### First, to encode the file in base64

    B64_SIG=$(base64 data/hs/satis_sig | while read line; do echo -n $line; done)

### Then, to get that into nginx's config

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

A similar process should be possible with Apache.

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
