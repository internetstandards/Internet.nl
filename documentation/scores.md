*This document is historic. It has outdated information for the score
calculation and/or the actual tests but still could server as an overview for
the tests and the though process behind them.*

# Connectivity test.

Aimed at both security and future-proofness of the connection.
The tests are currently divided into two groups, each of which weight
equally in the possible end-score of 100%.  Roughly one could say
one category is more targeted towards security while the other targets
whether the connection will stand the test of time.  That isn't completely
true as the security tests also performs its test over future-proof
connections and vice versa.
The tests are really concerning the IPv6 standards and DNSSEC standards.

Since neither security nor future-proofness should be considered more
important, both tests score equally 50%.  End-users need both.

## Does the end-user performing the test have a working IPv6 connection.

There are a number of tests performed to verify a number of aspects of
the IPv6 standard.  The IPv6 standard is a large standard which describes
a lot of how IPv6 traffic should be handled.  Some items are less important,
and there are a great deal of aspects that cannot be verified in a
browser based test.  We do not target the verification whether the
connection implements the IPv6 standard, only that the end-user experience
is that a fully functioning IPv6 connection is available.

If content can be retrieved from an IPv6 only source without restrictions
then 40% out of the 50% can be achieved.  If this isn't fully possible,
but you are able to retrieve content using an explicit IPv6 address (rather
than resolving an IPv6 AAAA address), then instead of 40% out of the 50%
the connection still scores 10%.

The remainder 10% out of the 50% is scored by resolving DNS queries that
are only available when the resolver is able to perform IPv6-only nameservers.

Also tested and monitored, but not scored are whether:
- The user has a bit more anonymity on the web by using the SLAAC standard.
  This gains a bit of extra anonymity in some circumstances but can also
  be a burden for other users.  Also such anonymity is bypassed by tracking
  methods;
- Your ISP provider name;
- Your resolvers (as far as can be determined, this is prone to mistakes);
- Your IPv4 and IPv6 addresses and possible reverse domain name.

Deliberately Internet.nl does not target tests like a speed test of the
connection.  We only look at standards-conforming and security of the
Internet connection itself.

Speed is really more about quality, for instance.  Though the standards
do dictate that the speed over IPv6 may not be less than over IPv4.
At the moment, we do not include this to avoid discussion over speed
characteristics at all.

## Is the user protected from falsified domain name information (DNSSEC)

Plain DNS is vulnerable to hijacking.  A standard exists to prove the
information is authentic.  Owners of DNS domain names provide authentication
information, service providers should then check this information and block
any invalid information.

We check whether this check and subsequent blocking of bogus information
is performed.  Although the tests performs a number of checks, the outcome
is really an all-or-nothing score.


# Web-server test

The web-server test is composed of three parts
- IPv6: is the web-content available in an IPv6-only network infrastructure
- DNSSEC: is the DNS domain name secured using DNSSEC
- TLS: are you really securely communicating with the web-server

Each of these three score an equal 33% in the final score

    Because of reorganization of the categories and some cross-references in
    the tests only on a coarse level the information is currently presented.

## Content can be delivered over IPv6

This does not only require the web-server to have an IPv6 address, but also
for it to be actually responding, having equal (enough) content as over IPv4
and not serving fake content.
A bit more controversial is the nameservers which must also respond over
IPv6.  We are going to accept a minimum of nameservers to be reachable over
IPv6.

When communicating over IPv6 it should also provide the correct secure
communication as with encryption and certificate authentication.  This
quite often is broken.

    The *web* check tests whether the domain's HTTP service is available
    via IPv6. The check scores 50 if there is at least one AAAA record, all
    addresses given in AAAA records are can be connected to on either port
    80 or 443, and all ports reachable via IPv4 are also reachable via IPv6.
    The check scores 15 it at least one address given in an AAAA record is
    reachable on at least one of ports 80 or 443 but not all addresses can be
    reached on either port or more ports are reachable via IPv4 than IPv6.
    Otherwise, the check scores 0.

    The *web simhash* check tests whether the index pages served for the domain
    via IPv4 and IPv6 appear to be the same. This check is not currently
    scored.

    The *ns* check tests whether the name servers for the domain are reachable
    through IPv6. Each name server given in the domain's zone's NS record set
    that has at least one AAAA record and all AAAA records are reachable
    scores 50. Each such name server that has at least one least one reachable
    AAAA record but not all AAAA records are reachable scores 15. Each other
    name server scores 0. The test score is the arithmetic mean of the scores
    of all name servers.

## Domain secured using DNSSEC

Either secured, giving full score, or not secured which still gives a
small score (currently 6% out of the 33% possible).
The only way to get a zero score here is if your domain is hijacked or
you have misconfigured your domain and the standard demands that your
domain should be considered to be hijacked (because it could be).

## Secure communicating

We would follow the guidelines from the Nationaal Cyber Security Centrum
(NCSC) on which would be good or acceptable settings.  Anything that is
considered by the NCSC to be good enough for the moment will give you a
full score.

    The score is 0 if TLS is not available or the sum of the scores of the following checks if it is:
    - The *fs* check tests forward secrecy settings. It scores 10 if the group size for Diffie-Hellman key exchange, if used, is at least 2048 bits and the group size for Elliptic-Curve Diffie-Hellman key exchange, if used, is at least 224 bits.
    - The *ciphers* check tests whether the site only offers secure cipher methods. It scores 10 if connecting with only these ciphers fails: EXP, aNULL, PSK, SRP, IDEA, DES, eNULL, RC4, MD5.
    - The *protocols* check tests whether only TLS protocol versions considered secure are being allowed. It scores 10 if connecting with SSLv2 or SSLv3 fails.
    - The *compression* check tests whether TLS compression is not being used and scores 10 in this case. - WHY?
    - The *secure reneg* check tests whether secure renegotiation is supported. A score of 10 if it is. - WHY?
    - The *client reneg* check tests whether clients are not allowed to initiate renegotiation for a score of 10. - WHY?
    - The *cert pubkey* check tests the key lengths of the public keys in the certificate chain. Specifically, it scores 10 if the key length is at least
    -- 256 bits for elliptic curve public keys,
    -- 2048 bits for RSA public keys, and
    -- 224 bits for DSA public keys.
    - The *cert signature* check tests that only SHA512, SHA384, or SHA256 are used as signature algorithms for all non-root certificates in the certificate chain and gives a score of 10 in that case.
    - The *cert trusted* check tests whether the certificate chain verifies using Mozilla’s certificate bundle as trust anchor for ten points.
    - The *cert hostmatch* check tests whether the certificate presented by the server contains the requested domain name either in the CN or subjectAltName fields. A score of 10 if it does.
    - The *dane* checks tests whether TLSA record set is available for the domain and, if so, if the certificate presented by the site validates using the TLSA record set. The score is 0 in either of the three cases that there is no TLSA record set, that verification fails, or that verification succeeds.
    - The *forced_https* checks whether an HTTP request is redirected to an HTTPS web server of the same domain or subdomain. The absence of an HTTP web server is also considered a success.

# Mail test

The mail test mainly concerns security, and authentication for both
mail being sent and received by the server.
However because no actual mail is being passed some checks are difficult
to perform.

Authentication is however also part of the future-proofness of the e-mail.
E-mail is suffering from spam and phishing attacks, which threaten its
usefulness.  It is therefor unfair to say that only IPv6 targets future-
proofness.

The e-mail tests are divided into four test groups that each contribute
to 25% percent of the score.

## Mail-servers available over IPv6

Whether mail-servers are in principle reachable over IPv6.  For other mail
servers to be able to deliver mail to the server in an IPv6-only network
it is necessary that both the DNS names themselves are resolvable over
IPv6 as well as the mail-server being reachable over IPv6.  Not having
one of each cuts the score in half for this item.

    This probe tests whether the domain’s mail exchangers are connectable
    through IPv6. The probe's score is the sum of the following two checks.

    The *mx* check tests whether the mail exchangers themselves are reachable
    through IPv6. The tests scores 100 if there is explicitely no MX record.
    Otherwise, each of the domain names of the MX record is tested. It scores
    50 if there is at least one AAAA record and all addresses given in AAAA
    records are reachable on port 25. It scores 15 if there is more than one
    AAAA record, at least one given address is reachable on port 25, and at
    least one given address ist not. The overall score of the check is the
    arithmetic mean of all the individual domain name tests (I think).

    The *ns* check tests whether the name servers for the domain are reachable
    through IPv6. Each name server given in the domain’s zone’s NS record set
    that has at least one AAAA record and all AAAA records are reachable
    scores 50. Each such name server that has at least one least one reachable
    AAAA record but not all AAAA records are reachable scores 15. Each other
    name server scores 0. The test score is the arithmetic mean of the scores
    of all name servers.

## Mail servers name authentication

As with all DNSSEC, this is an all-or-nothing approach.  If the DNS
domain is secured with DNSSEC you are certain that the mail-server you
are addressing is actually the one listed by the domain.  At the moment
still a consolation score of 5% out of the 25% for this category is
awarded if you are just insecure and not considered a hijacked domain.

If you have not secured your domain name with DNSSEC, you can not be
certain that you are not actually sending mail to some malicious party
that has hijacked the domain.  Other attempts to encrypt and provide
certificates for the other systems are futile as the malicious server
can just have valid encryption anyway.

That is why DNSSEC, even though just a simple test, is a prerequisite
for security.

## Mail server authentication

Does the mail server pass our criteria for the:
- SPF
- DMARC
- and DKIM
Each of these three weigh equally in the score.

The exact criteria are still being tightened.  This is in part because
there is not full agreement on acceptable settings.  At the very
moment we just check for the minimum, but this is to be changed soon.

The standards allow for just a primitive setting that in effect just
prepares for tightening and does not limit or secure anything.  It acts
the same as it there was nothing specified at all.

## Mail server encryption

Normally we would follow the guidelines from the Nationaal Cyber Security
Centrum (NCSC) on which would be good or acceptable settings, and we do
report on good, acceptable or sub-standard encryption levels.

For incoming mail we do accept any level of encryption to be good enough,
even though some encryption levels really should not be used anymore.
The rationale is that it is the sending party of the e-mail that should
choose a good encryption level and it is just up to the incoming e-mail
server to accept this.

Of course the incoming mail server should accept encryption, so at the
moment, just being able to receive e-mail over an encrypted channel is
considered good enough.  All listed mail exchangers do need to
pass this test though, the lowest chain counts here.

Here also the exact criteria are still being tightened.  While at the
moment just accepting encrypted communication is giving a full score on
this test, one should really accept strong enough encryption, and not just
any if all methods you accept are not considered good enough anymore.
This test is quite time consuming though and in practice isn't really
occurring.

Not weighted also into the score is whether the mail server can be
security communicated with with the help of the DANE standard.  The DANE
standard would be very helpful, but simply isn't propagated enough.
