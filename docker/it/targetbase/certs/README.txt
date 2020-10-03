UPDATE: The certificates in this directory can now be auto-updated/generated
via the docker/it/targetbase/recreate_certificates.sh script. It is preferred
over the manual way as it also updates any matching TLSA records.

The certificates in this directory were generated according to the
instructions in the docker/it/targetbase/ca-ocsp/README.txt file, e.g.

cd docker/it/targetbase/ca-ocsp
DOMAINNAME=tls1213sni.test.nlnetlabs.tk
BASEFILENAME=../certs/$DOMAINNAME

or

DOMAINNAME=*.test.nlnetlabs.tk
BASEFILENAME=../certs/wildcard.test.nlnetlabs.tk

Now follow the instructions in the ca-ocsp/README.txt file.


some.other.domain.der:
----------------------

This file is for serving an OCSP response which was fetched for a different
site/certificate and thus is invalid for the site which we configure to use
it.

The .der file was obtained using the process explained here:

    https://raymii.org/s/articles/OpenSSL_Manually_Verify_a_certificate_against_an_OCSP.html

