# Docker DNS setup

There are several DNS components. First, there are the following three Docker containers:

1. A non-validating resolver, used for DNS resolving by almost all tests. As we have our own DNSSEC validation test, we want to see bogus responses as well.
2. A validating resolver, used to validate DANE records through ldns-dane.
3. An authoritative name server for the connection test zone.

Besides, an authoritative name server that should be hosted elsewhere, is needed for the DNS records in the zone for `INTERNETNL_DOMAINNAME`.

The resolvers (1 and 2) do not require any specific configuration.
In this document, `INTERNETNL_DOMAINNAME` is `example.com`. Furthermore, example IP addresses are used.

## Common parts

Note that typically, you would use `$ORIGIN example.com.` in your zone, allowing for these suffixes to be removed.

For accessing the absolute minimum basic functionality of the application the following DNS records must be configured:

    example.com.                    A      192.0.2.1
                                    AAAA   2001:db8:1::1
    www.example.com.                CNAME  example.com.
    nl.example.com.                 CNAME  example.com.
    en.example.com.                 CNAME  example.com.
    ipv6.example.com.               AAAA   2001:db8:1::1
    nl.ipv6.example.com.            CNAME  ipv6.example.com.
    en.ipv6.example.com.            CNAME  ipv6.example.com.

The hostname (`INTERNETNL_DOMAINNAME`) should have SPF, DKIM and DMARC,
as some mail servers may filter on this, and it could affect mail tests.
For a domain that does not otherwise send email, use:

    example.com.		               TXT	"v=spf1 a -all"	; The "a" mechanism is needed for the mail test (see rfc7208, section-2.3).
    *._domainkey.example.com.	     TXT	"v=DKIM1; p="	; empty DKIM, also to score 100% for this non-sending subdomain that does have SPF "a" mechanism which is needed for mail test.
    _dmarc.example.com.	           TXT	"v=DMARC1; p=reject; sp=reject;"

    ; optionally set an CAA record to Let's Encrypt or any other used ACME supporting certificate authority (note that if CAA is used, the correct certificate authority must be present)
    ; example.com.                 CAA 0 issue "letsencrypt.org;"

The `INTERNETNL_DOMAINNAME` host should also have a working MX and correct FCrDNS.
DANE records are recommended, but not required.

For modern HTTP3 support a HTTPS resource record should be added for each domain:

    example.com.                    HTTPS  1 . alpn=h2,h3
    www.example.com.                HTTPS  1 . alpn=h2,h3
    nl.example.com.                 HTTPS  1 . alpn=h2,h3
    en.example.com.                 HTTPS  1 . alpn=h2,h3
    ipv6.example.com.               HTTPS  1 . alpn=h2,h3
    nl.ipv6.example.com.            HTTPS  1 . alpn=h2,h3
    en.ipv6.example.com.            HTTPS  1 . alpn=h2,h3

## Specific settings for batch mode

For batch, the connection test is not used, and the authoritative name server should not be publicly available.
Set `IPV4_IP_PUBLIC=127.0.0.1` and `IPV6_IP_PUBLIC=::1` in `docker/host.env`.

## Specific settings for connection test in single test mode

For the connection test the following records are also required (i.e., not needed for batch mode):

    conn.example.com.               CNAME  example.com.
    en.conn.example.com.            CNAME  example.com.
    nl.conn.example.com.            CNAME  example.com.

    conn.ipv6.example.com.          CNAME  ipv6.example.com.
    nl.conn.ipv6.example.com.       CNAME  ipv6.example.com.
    en.conn.ipv6.example.com.       CNAME  ipv6.example.com.

    test-ns-signed.example.com.     NS     example.com.
    test-ns6-signed.example.com.    NS     ipv6.example.com.

The Docker image will create two DNS zones, served by the authoritative name server for the connection test zone.
These are signed, and therefore also require the correct `DS` records.

Obtain the `DS` records by inspecting the logs of the `unbound` service and
finding the 2 lines beneath `Please add the following DS records for domain`:

    $ docker logs internetnl-prod-unbound-1 2>&1 | grep -A2 "Please add the following DS records for domain"
    Please add the following DS records for domain example.com:
    test-ns-signed.example.com.   IN  DS  55295 8 2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    test-ns6-signed.example.com.  IN  DS  33292 8 2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Then, configure those two DS records in their parent zone.

You can verify DNSSEC using:

  - https://dnsviz.net/d/test.a.conn.test-ns-signed.example.com/dnssec/
  - https://dnsviz.net/d/test.aaaa.conn.test-ns-signed.example.com/dnssec/

# Advanced CAA configuration

Letsencrypt is used in the `webserver` container to automatically generate TLS certificates. Basic CAA records can be created to ensure only Letsencrypt issues certificates are valid for the `INTERNETNL_DOMAINNAME`:

    example.com.                 CAA 0 issue "letsencrypt.org;"

To provide even stricter configuration the ACME validation method and the account ID registered with Letsencrypt can be specified.

The validation method used is `http-01` and the account ID can be obtailed by running the following command after setup (this might require installing the `jq` tool):

    jq -r .uri < /var/lib/docker/volumes/internetnl-prod_certbot-config/_data/accounts/acme-v02.api.letsencrypt.org/directory/*/regr.json

Instead of the CAA record above add this to the zone file:

    example.com.                 CAA	128 issue "letsencrypt.org;validationmethods=http-01;accounturi=https://acme-staging-v02.api.letsencrypt.org/acme/acct/123456"

Also see: https://letsencrypt.org/docs/caa/

## Backing up/restoring/reusing Letsencrypt account

Letsencrypt account ID and private key are stored in a Docker volume for persistence between deploys. If you want to completely redeploy without losing the Letsencrypt account used in de CAA record, or you want to use the same account for multiple installations, you need to make a backup/copy of the following directory:

    /var/lib/docker/volumes/internetnl-prod_certbot-config/_data/

When deploying a new instance, first complete the full setup. After that perform the following steps to restore the account:

    docker compose --project-name=internetnl-prod stop webserver
    rm -rf /var/lib/docker/volumes/internetnl-prod_certbot-config/_data/*
    cp -r <location of backed up _data directory> /var/lib/docker/volumes/internetnl-prod_certbot-config/_data/
    docker compose --project-name=internetnl-prod start webserver

The certbot instance in the webserver container should start requesting a certificate for the domain after at most 1 minute. You can check the progress using:

    docker compose --project-name=internetnl-prod exec webserver cat /var/log/letsencrypt/letsencrypt.log
