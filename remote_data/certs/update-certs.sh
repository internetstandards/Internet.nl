#!/bin/sh

./mk-ca-bundle.pl -t -s SHA1 -d release -f
perl -i'' -pe 's/[^[:ascii:]]//g' ca-bundle.crt

echo "Extract SHA1 fingerprints"
grep "SHA1 Fingerprint" ca-bundle.crt | cut -d "=" -f 2 > root_fingerprints.tmp
sed 's/://g' root_fingerprints.tmp > root_fingerprints
rm root_fingerprints.tmp
