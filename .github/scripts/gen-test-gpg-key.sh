#!/bin/bash
# Generates a throwaway, passphrase-less GPG key for CI test-signing only.
# Never used for release signing - release.yml imports the real org key instead.
set -euo pipefail

gnupghome="$(mktemp -d)"
chmod 700 "$gnupghome"
echo "GNUPGHOME=$gnupghome" >> "$GITHUB_ENV"

printf 'allow-loopback-pinentry\n' > "$gnupghome/gpg-agent.conf"
printf 'pinentry-mode loopback\n' > "$gnupghome/gpg.conf"

GNUPGHOME="$gnupghome" gpg --batch --passphrase '' \
  --quick-generate-key "colatrl CI test key <ci-test@colatrl.invalid>" default default never

keyid="$(GNUPGHOME="$gnupghome" gpg --list-secret-keys --with-colons | awk -F: '/^fpr:/ {print $10; exit}')"
echo "TEST_GPG_KEYID=$keyid" >> "$GITHUB_ENV"
