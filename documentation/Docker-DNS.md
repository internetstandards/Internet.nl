# Docker DNS setup

There are several DNS components in the Docker setup:

* A non-validating resolver, used for DNS resolving by almost all tests.
  As we have our own DNSSEC validation test, we want to see bogus responses as well.
* A validating resolver, used to validate DANE records through ldns-dane.
* An authoritative server for the connection test zone.
* The DNS records in the zone for `INTERNETNL_DOMAINNAME`.
  These are hosted elsewhere, but have certain requirements for the instance to work.

The resolvers do not require any specific configuration.
In this document, `INTERNETNL_DOMAINNAME` is `example.com`.

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

    example.com.		           TXT	"v=spf1 a -all"	; The "a" mechanism is needed for the mail test (see rfc7208, section-2.3).
    _domainkey.example.com.	       TXT	"v=DKIM1; p="	; empty DKIM to score 100% for this non-sending subdomain that does have SPF "a" mechanism which is needed for mail test.
    _dmarc.example.com.	           TXT	"v=DMARC1; p=reject; sp=reject;"

    ; optionally set an CAA record to Let's Encrypt (note that if CAA is used, Let's Encrypt must be present)
    ; example.com.                 CAA 0 issue "letsencrypt.org;"

The `INTERNETNL_DOMAINNAME` host should also have a working MX and correct FCrDNS.


## Specific settings for batch mode

For batch, the connection test is not used, and the authoritative server should not be publicly available.
Set `IPV4_IP_PUBLIC=127.0.0.1` and `IPV6_IP_PUBLIC=::1` in `docker/host.env`.


## Specific settings for single test mode

For the connection test the following records are also required (i.e., not needed for batch mode):

    conn.example.com.               CNAME  example.com.
    en.conn.example.com.            CNAME  example.com.
    nl.conn.example.com.            CNAME  example.com.

    conn.ipv6.example.com.          CNAME  ipv6.example.com.
    nl.conn.ipv6.example.com.       CNAME  ipv6.example.com.
    en.conn.ipv6.example.com.       CNAME  ipv6.example.com.

    test-ns-signed.example.com.     NS     example.com.
    test-ns6-signed.example.com.    NS     ipv6.example.com.

The Docker image will create two DNS zones, served by the authoritative server.
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

