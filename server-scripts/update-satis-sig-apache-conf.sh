#!/usr/bin/env bash
set -e

# Variables
####################################
satis_sig_fname="/home/satis/hs-example.com/satis_sig"
satis_sig_bad_time_fname="/home/satis/hs-example.com/satis_sig_bad_time"
satis_sig_bad_fp_fname="/home/satis/hs-example.com/satis_sig_bad_fp"
satis_sig_bad_domain_fname="/home/satis/hs-example.com/satis_sig_bad_domain"
satis_sig_bad_sig_fname="/home/satis/hs-example.com/satis_sig_bad_sig"
satis_sig_bad_label_fname="/home/satis/hs-example.com/satis_sig_bad_label"
htaccess_tmpl_fname="/root/satis/htaccess.tmpl"
htaccess_out_fname="/var/www/htdocs/.htaccess"


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
	cat "$fname"
}

# Check that we are root, because we probably need to be
####################################
[ "$EUID" == "0" ] || fail "$0 should be run as root"

# Check that needed programs exist
####################################
which m4 &>/dev/null || fail "Missing required program m4"

# Check that needed files exist
####################################
[ -f "$satis_sig_fname" ] || fail "$satis_sig_fname must exist"
[ -f "$satis_sig_bad_time_fname" ] || fail "$satis_sig_bad_time_fname must exist"
[ -f "$satis_sig_bad_fp_fname" ] || fail "$satis_sig_bad_fp_fname must exist"
[ -f "$satis_sig_bad_domain_fname" ] || fail "$satis_sig_bad_domain_fname must exist"
[ -f "$satis_sig_bad_sig_fname" ] || fail "$satis_sig_bad_sig_fname must exist"
[ -f "$satis_sig_bad_label_fname" ] || fail "$satis_sig_bad_label_fname must exist"
[ -f "$htaccess_tmpl_fname" ] || fail "$htaccess_tmpl_fname must exist"

# Begin program
####################################
b64_sig="$(get_current_sig  "$satis_sig_fname")"
b64_sig_bad_time="$(get_current_sig  "$satis_sig_bad_time_fname")"
b64_sig_bad_fp="$(get_current_sig  "$satis_sig_bad_fp_fname")"
b64_sig_bad_domain="$(get_current_sig  "$satis_sig_bad_domain_fname")"
b64_sig_bad_sig="$(get_current_sig  "$satis_sig_bad_sig_fname")"
b64_sig_bad_label="$(get_current_sig  "$satis_sig_bad_label_fname")"
generation_date=`date`
m4 \
	-DM4_SATIS_SIG="$b64_sig" \
	-DM4_SATIS_SIG_BAD_TIME="$b64_sig_bad_time" \
	-DM4_SATIS_SIG_BAD_FP="$b64_sig_bad_fp" \
	-DM4_SATIS_SIG_BAD_DOMAIN="$b64_sig_bad_domain" \
	-DM4_SATIS_SIG_BAD_SIG="$b64_sig_bad_sig" \
	-DM4_SATIS_SIG_BAD_LABEL="$b64_sig_bad_label" \
	-DM4_SATIS_GENERATION_DATE="$generation_date" \
	"$htaccess_tmpl_fname" > "$htaccess_out_fname"

# Comment 'Generated on' line
sed -i 's/Generated on/# Generated on/' "$htaccess_out_fname"
