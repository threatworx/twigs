#!/usr/bin/env bash
#
# make_signing_cert.sh - Create a self-signed code signing certificate for
# signing the twigs PowerShell scripts (build.sh with TW_SIGN_P12).
#
# A self-signed signature is only trusted on Windows machines where the
# certificate (.cer) has been added to both "Trusted Root Certification
# Authorities" and "Trusted Publishers", for example with Group Policy or
# Intune. Elsewhere it shows as untrusted. Use a certificate from a public CA
# for machines you don't manage.
#
# Usage:
#   ./make_signing_cert.sh [-n common_name] [-d days] [-o output_dir] [-b basename] [-f]
#
#   -n  certificate subject common name   (default: ThreatWorx twigs code signing)
#   -d  validity in days                  (default: 1095, three years)
#   -o  output directory                  (default: current directory)
#   -b  output file base name             (default: twigs-signing)
#   -f  overwrite existing output files
#
# The .pfx password is read from TW_SIGN_PASS, or asked for when it isn't set.
#
# Writes:
#   <basename>.pfx  certificate and private key, password protected. Keep it
#                   secret (e.g. a CI secret); build.sh reads it via TW_SIGN_P12.
#   <basename>.cer  public certificate (DER) to import on Windows machines.
#   <basename>.pem  the same public certificate in PEM form.
#
# Requirements: openssl.

set -euo pipefail

CN="ThreatWorx twigs code signing"
DAYS=1095
OUT_DIR="."
BASE="twigs-signing"
FORCE=false

usage() { awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "$0"; exit "${1:-0}"; }
die() { echo "ERROR: $*" >&2; exit 1; }

while getopts ":n:d:o:b:fh" opt; do
    case "$opt" in
        n) CN="$OPTARG" ;;
        d) DAYS="$OPTARG" ;;
        o) OUT_DIR="$OPTARG" ;;
        b) BASE="$OPTARG" ;;
        f) FORCE=true ;;
        h) usage 0 ;;
        :) echo "Option -$OPTARG needs a value" >&2; usage 1 ;;
        *) echo "Unknown option -$OPTARG" >&2; usage 1 ;;
    esac
done
shift $((OPTIND - 1))
[[ $# -eq 0 ]] || { echo "Unexpected argument: $1" >&2; usage 1; }
[[ "$DAYS" =~ ^[0-9]+$ && "$DAYS" -gt 0 ]] || die "-d must be a positive number of days"
command -v openssl >/dev/null || die "openssl not found"

mkdir -p "$OUT_DIR"
PFX="$OUT_DIR/$BASE.pfx"; CER="$OUT_DIR/$BASE.cer"; PEM="$OUT_DIR/$BASE.pem"
if [[ "$FORCE" != true ]]; then
    for f in "$PFX" "$CER" "$PEM"; do
        [[ -e "$f" ]] && die "$f already exists (use -f to overwrite)"
    done
fi

PASS="${TW_SIGN_PASS:-}"
if [[ -z "$PASS" ]]; then
    read -r -s -p "Password for $BASE.pfx: " PASS; echo
    read -r -s -p "Repeat password: " PASS2; echo
    [[ "$PASS" == "$PASS2" ]] || die "passwords do not match"
    [[ -n "$PASS" ]] || die "an empty password is not allowed"
fi

WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
umask 077
printf '%s' "$PASS" > "$WORK/pass"

# A config file of our own rather than -addext: with the system openssl.cnf,
# -addext can duplicate extensions, and certificates with duplicate extensions
# are rejected. CA:TRUE with keyCertSign lets the certificate act as its own
# trust anchor, as Windows "Trusted Root" requires.
cat > "$WORK/req.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
utf8 = yes
[dn]
CN = $CN
[ext]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,digitalSignature,keyCertSign
extendedKeyUsage = codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF

openssl req -x509 -config "$WORK/req.cnf" -newkey rsa:3072 -sha256 -days "$DAYS" -nodes \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>"$WORK/err" || { cat "$WORK/err" >&2; die "certificate creation failed"; }
# AES-256 / SHA-256 PBE for the .pfx (the openssl 1.1 default, RC2/3DES, is weak)
openssl pkcs12 -export -inkey "$WORK/key.pem" -in "$WORK/cert.pem" -name "$CN" \
    -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 \
    -passout "file:$WORK/pass" -out "$WORK/out.pfx" 2>"$WORK/err" || { cat "$WORK/err" >&2; die "pfx export failed"; }

openssl x509 -in "$WORK/cert.pem" -outform DER -out "$WORK/cert.cer"
install -m 644 "$WORK/cert.pem" "$PEM"
install -m 644 "$WORK/cert.cer" "$CER"
install -m 600 "$WORK/out.pfx" "$PFX"

echo "Subject:    $(openssl x509 -in "$PEM" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
echo "Thumbprint: $(openssl x509 -in "$PEM" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g') (SHA-1)"
echo "Expires:    $(openssl x509 -in "$PEM" -noout -enddate | sed 's/^notAfter=//')"
echo
echo "$PFX  (private - keep secret)"
echo "$CER  (public - import on Windows into Trusted Root and Trusted Publishers)"
echo "$PEM"
