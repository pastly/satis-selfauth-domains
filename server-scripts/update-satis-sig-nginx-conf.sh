#!/usr/bin/env bash
set -e

# Variables
####################################
satis_sig_fname="/home/satis/src/tor/data/hs/satis_sig"
satis_sig_bad_time_fname="/home/satis/src/tor/data/hs/satis_sig_bad_time"
satis_sig_bad_fp_fname="/home/satis/src/tor/data/hs/satis_sig_bad_fp"
satis_sig_bad_domain_fname="/home/satis/src/tor/data/hs/satis_sig_bad_domain"
satis_sig_bad_sig_fname="/home/satis/src/tor/data/hs/satis_sig_bad_sig"
nginx_tmpl_fname="/root/satis/nginx.conf.tmpl"
nginx_out_fname="/etc/nginx/sites-available/satis.system33.pw"
reload_nginx_command="systemctl reload nginx"


# Useful functions
####################################
function fail {
	echo $1 >&2
	exit 1
}

function get_current_sig {
	# Read the give satis_sig file and return the base64-encoded contents
	fname="$1"
	[ "$fname" != "" ] || fail "Must pass a filename to get_current_sig"
	[ -f "$fname" ] || fail "$fname does not exist"
	base64 "$fname" | while read line; do echo -n $line; done
}

# Check that we are root, because we probably need to be
####################################
[ "$EUID" == "0" ] || fail "$0 should be run as root"

# Check that needed programs exist
####################################
which base64 &>/dev/null || fail "Missing required program base64"
which m4 &>/dev/null || fail "Missing required program m4"

# Check that needed files exist
####################################
[ -f "$satis_sig_fname" ] || fail "$satis_sig_fname must exist"
[ -f "$satis_sig_bad_time_fname" ] || fail "$satis_sig_bad_time_fname must exist"
[ -f "$satis_sig_bad_fp_fname" ] || fail "$satis_sig_bad_fp_fname must exist"
[ -f "$satis_sig_bad_domain_fname" ] || fail "$satis_sig_bad_domain_fname must exist"
[ -f "$satis_sig_bad_sig_fname" ] || fail "$satis_sig_bad_sig_fname must exist"
[ -f "$nginx_tmpl_fname" ] || fail "$nginx_tmpl_fname must exist"

# Begin program
####################################
b64_sig="$(get_current_sig  "$satis_sig_fname")"
b64_sig_bad_time="$(get_current_sig  "$satis_sig_bad_time_fname")"
b64_sig_bad_fp="$(get_current_sig  "$satis_sig_bad_fp_fname")"
b64_sig_bad_domain="$(get_current_sig  "$satis_sig_bad_domain_fname")"
b64_sig_bad_sig="$(get_current_sig  "$satis_sig_bad_sig_fname")"
m4 \
	-DM4_SATIS_SIG="$b64_sig" \
	-DM4_SATIS_SIG_BAD_TIME="$b64_sig_bad_time" \
	-DM4_SATIS_SIG_BAD_FP="$b64_sig_bad_fp" \
	-DM4_SATIS_SIG_BAD_DOMAIN="$b64_sig_bad_domain" \
	-DM4_SATIS_SIG_BAD_SIG="$b64_sig_bad_sig" \
	"$nginx_tmpl_fname" > "$nginx_out_fname"
# No quotes on purpose
$reload_nginx_command
