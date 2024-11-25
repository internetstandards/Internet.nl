# TLS testing

TLS is one of the more complicated tests, as there are a ton of things to check.
The only way to find out whether a particular feature is supported by a TLS
server is to try to negotiate it, and see if or succeeds or the server
drops the connection.
This means TLS also performs many connections.

The test builds heavily on
[sslyze](https://github.com/nabla-c0d3/sslyze)
and
[nassl](https://github.com/nabla-c0d3/nassl).

## Code structure

The TLS testing code is all in `checks.tasks.tls`:
* `evaluation.py` translates facts found in testing, into an evaluation of a
  score and good/phase out/bad values for various more isolated scenarios, like the
  TLS version. It also contains dataclasses for some other evaluations.
* `http.py` deals with HTTP header and HTTPS redirection checks.
* `scans.py` contains the scanning and parsing, and glues this to the evaluation.
* `tasks_reports.py` interfaces between the scanning and the task/reporting
  structures of the wider project. It's the entry point for starting tests.
* `tls_constants.py` defines criteria, like the rating of individual cipher suites.

## Target IPs

The test targets for web are all addresses of the target.
For mail, one IPv6 and one IPv6 IP for each MX is tested.

## Connection limits

Multiple servers are always tested in parallel. 
Web uses multiple connections per IP. Mail tests with one
connection per IP by default, as mail servers often do
not allow more.
start to prevent it interfering with the IPv6 check.

There is a special case: some mail servers are lenient with many
simultaneous connections, but perform anti-spam by making
individual connections very slow. For these, the connection
limit for mail is raised. At time of writing, this applies
to gmail.

## Test criteria

The criteria follow the
[IT Security Guidelines for Transport Layer Security 2.1](https://english.ncsc.nl/publications/publications/2021/january/19/it-security-guidelines-for-transport-layer-security-2.1).
Sufficient or phase out is generally a status NOTICE, bad is a status FAIL.
Some tests are optional and INFO at worst, e.g. DANE for web.

These criteria are almost all listed in `tls_constants.py`, except some
more complex ones in `evaluation.py` (like DH params) and some trivial
ones in `scans.py` (like zero RTT on or off).

All tests/lists try to refer back to the guideline/table/footnote from
the NCSC guidelines that they are based on.

## Scan process

The preferred method is to refer to sslyze, which we do for almost all scans,
like FS parameters, OCSP, certificate parameters and trust, renegotiation, etc.

There are a few special cases:

* Cipher order preference detection is not supported by sslyze, so we
  have our own, on top of nassl. It can take some shortcuts, because
  we only care about good>sufficient>phase out>bad.
* SHA2 key exchange is a small custom test, as it is not in sslyze.
* Sslyze is a bit blunt which can be improved by knowing which TLS
  versions are supported before calling it. There's a small precheck
  that determines this.

## Changes in release 1.10

This documentation was written for the 1.10 version, in which the TLS
test was updated as mentioned. In prior versions, the TLS code was
handcrafted on top of a patched nassl. Several changes
were made:

* The cipher order detection was missing certain scenarios, such as
  servers that preferred RSA>ECDHE, CBC>POLY1305. It is not known
  in which particular cases this bug in the old code triggered.
* CCM_8 ciphers were not detected.
* -OLD ciphers were detected, and are no longer.
* OCSP stapling detection was glitchy at times in the old code.
* The old code distinguished "the server cipher order preference is wrong"
  from "the server has no preference". The new code does not separate
  these, as the usefulness is limited.
