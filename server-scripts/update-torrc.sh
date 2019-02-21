#!/usr/bin/env bash
set -e

# Variables
####################################
cert_fname="/etc/letsencrypt/live/satis.system33.pw/fullchain.pem"
traditional_domain_name="satis.system33.pw"
torrc_tmpl_fname="torrc.tmpl"
torrc_out_fname="/home/satis/src/tor/satis.system33.pw.torrc"
reload_tor_command="cat /home/satis/src/tor/data/tor.pid | xargs kill -HUP"

# Useful functions
####################################
function fail {
	echo $1 >&2
	exit 1
}

function get_cert_fp {
	# Use openssl to get the given certificate's SHA256 fingerprint
	fname="$1"
	[ "$fname" != "" ] || fail "Must pass a filename to get_cert_fp"
	[ -f "$fname" ] || fail "$fname does not exist"
	openssl x509 -in "$fname" -noout -fingerprint -sha256 |\
		cut -d '=' -f 2 | tr -d ':'
}

# Check that we are root, because we probably need to be
####################################
[ "$EUID" == "0" ] || fail "$0 should be run as root"

# Check that needed programs exist
####################################
which openssl &>/dev/null || fail "Missing required program openssl"
which m4 &>/dev/null || fail "Missing required program m4"
which cut &>/dev/null || fail "Missing required program cut"
which tr &>/dev/null || fail "Missing required program tr"

# Check that needed files exist
####################################
[ -f "$cert_fname" ] || fail "$cert_fname must exist"

# Begin program
####################################
fp="$(get_cert_fp "$cert_fname")"
m4 \
	-DM4_TRAD_DOMAIN="$traditional_domain_name"\
	-DM4_TLS_FP="$fp" \
	"$torrc_tmpl_fname" > "$torrc_out_fname"

eval "$reload_tor_command"
