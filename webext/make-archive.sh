#!/usr/bin/env bash
set -eu
fname=archive.zip

rm -fv $fname
# Don't do --symlinks (-y) because AMO can't handle them
zip -r $fname . \
    -i manifest.json \
    -i *.js \
    -i *.md \
    -i icons/*.png \
    -i popup/* \
    -i pages/* \
    -i lib/* \
    -i pages/lib/* \
    -i popup/lib/* \
    -i lib/asn1js/hex.js \
    -i lib/asn1js/base64.js \
    -i lib/asn1js/oids.js \
    -i lib/asn1js/int10.js \
    -i lib/asn1js/asn1.js \
    -i pages/lib/asn1js/hex.js \
    -i pages/lib/asn1js/base64.js \
    -i pages/lib/asn1js/oids.js \
    -i pages/lib/asn1js/int10.js \
    -i pages/lib/asn1js/asn1.js \
    -i popup/lib/asn1js/hex.js \
    -i popup/lib/asn1js/base64.js \
    -i popup/lib/asn1js/oids.js \
    -i popup/lib/asn1js/int10.js \
    -i popup/lib/asn1js/asn1.js \

echo OK
