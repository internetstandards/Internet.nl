# Change Log

## Unreleased next version

SSL_OP_PRIORITIZE_CHAHA support, support for more ciphers via the
ModernConnection, explicit check for NULL MX, DKIM not required for non email
sending domains, and more.

New
- docker/it/targetbase/recreate-certificates.sh allows for easy recreation of
  the IT related certificates.
- Support for SSL_OP_PRIORITIZE_CHACHA. [(#461)]
- Introduce manual HoF page(s).
- Support non email sending domains in mailtest for DKIM test. [(#249)]
- Keep and display the organizational domain for DMARC.
- 100% badges page in knowledge base. [(#443)]
- Explicitly test for NULL MX. [(#468)]
- Accessibility statement page. [(#290)]
- Use IDNA2008. [(#507)]

Changes
- Minimum max-age for HSTS is now 1 year. [(#421)]
- Accept all 3xx+3xx and 3xx+2xx DANE rollover schemes. [(#341)]
- Certificate Usage Field on TLSA records for email test. [(#329)]
- Validate CSP directives. [(#325)]
- Make X-Frame-Options optional and no longer consider ALLOW-FROM as sufficiently secure. [(#503)]
- No prescribed cipher ordering within a security level. [(#506)]
- Adjusted requirement level for client initiated renegotiation (informational). [(#510)]
- Update to jquery 3.5.1 [(#508)]

Bug Fixes
- Fix indefinite locks in cache (not a current problem).
- Fix ip_similarity for batch results where no IPv6 nor Ipv4 connection was
  possible.
- Better exception handling for untrusted certificate in OCSP check.
- Keep the same configured socket timeout for subsequent TLS connections.
- Nonces cause IPv4 vs IPv6 comparison to fail. [(#463)]
- Can't test site with invalid IDN. [(#484)]
- set_async(True) causes libunbound under celery to not honor config options
  set notable cache-max-ttl; remove for now.
- ARIA and DSS algorithms not detected. [(#477)]

Dependencies
- Updated python-pip-requirements.txt:
  - django-redis pinned to 4.10
  - celery bumped to 4.3.1 (vine dependency)
  - vine pinned to 1.3.0
  - beautifulsoup4 added [(#463)]

Migrations
- New column in DB (mailtestauth_dmarc_record_org_domain). [(#249)]
- New columns in DB for NULL MX. [(#468)]

Settings
- New SMTP_EHLO_DOMAIN setting in settings.py. [(#483)]
- New optional HAS_ACCESSIBILITY_PAGE setting in settings.py. [(#290)]

[(#249)]: https://github.com/NLnetLabs/Internet.nl/issues/249
[(#290)]: https://github.com/NLnetLabs/Internet.nl/issues/290
[(#329)]: https://github.com/NLnetLabs/Internet.nl/issues/329
[(#325)]: https://github.com/NLnetLabs/Internet.nl/issues/325
[(#341)]: https://github.com/NLnetLabs/Internet.nl/issues/341
[(#421)]: https://github.com/NLnetLabs/Internet.nl/issues/421
[(#443)]: https://github.com/NLnetLabs/Internet.nl/issues/443
[(#461)]: https://github.com/NLnetLabs/Internet.nl/issues/461
[(#463)]: https://github.com/NLnetLabs/Internet.nl/issues/463
[(#468)]: https://github.com/NLnetLabs/Internet.nl/issues/468
[(#477)]: https://github.com/NLnetLabs/Internet.nl/issues/477
[(#483)]: https://github.com/NLnetLabs/Internet.nl/issues/483
[(#484)]: https://github.com/NLnetLabs/Internet.nl/issues/484
[(#503)]: https://github.com/NLnetLabs/Internet.nl/issues/503
[(#506)]: https://github.com/NLnetLabs/Internet.nl/issues/506
[(#507)]: https://github.com/NLnetLabs/Internet.nl/issues/507
[(#508)]: https://github.com/NLnetLabs/Internet.nl/issues/508

## 1.2.1

Hotfix release.

Bug Fixes
- Fix broken connection test from 1.2.0; wrong variable name.

## 1.2.0

Update of the batch API to v2, removal of the X-XSS-Protection test, visual and
content improvements for no-MX cases.

New
- Batch API updated to v2. [(#337)] [(#395)] [(#336)] [(#436)]
- No MX configured: informational status/icons and more suitable category verdict. [(#455)]
- Remove test for X-XSS-Protection. [(#456)]

Bug Fixes
- Fix breaking bug when the cert chain could not be received.
- Fix breaking bug for daneTA hack.
- Only use the translated local name from Django for configured languages.
- Fix arbitrary text injection in news and FAQ articles.
- Make sure to pick and test the same mailservers when the number of configured
  mailservers is greater than the allowed one.
- Mailservers without STARTTLS support give wrong verdict. [(#437)]
- IPv6 connectivity for nameservers. [(#411)]
- Make sure only one SMTP connection is active at a time.
- Fix uncaught exception when decrypting HTTPS data.
- Fix for statistics page (days are missing). [(#417)]
- Fix for connecting to either IPv4 or IPv6 for the mail test.
- mail_starttls_tls_available icon when a server is not tested. [(#457)]
- Typos.

[(#336)]: https://github.com/NLnetLabs/Internet.nl/issues/336
[(#337)]: https://github.com/NLnetLabs/Internet.nl/issues/337
[(#395)]: https://github.com/NLnetLabs/Internet.nl/issues/395
[(#411)]: https://github.com/NLnetLabs/Internet.nl/issues/411
[(#417)]: https://github.com/NLnetLabs/Internet.nl/issues/417
[(#437)]: https://github.com/NLnetLabs/Internet.nl/issues/437
[(#436)]: https://github.com/NLnetLabs/Internet.nl/issues/436
[(#455)]: https://github.com/NLnetLabs/Internet.nl/issues/455
[(#456)]: https://github.com/NLnetLabs/Internet.nl/issues/456
[(#457)]: https://github.com/NLnetLabs/Internet.nl/issues/457

## 1.1.2

Hotfix release.

Bug Fixes
- Documentation update.
- Content update.
- Typos.

## 1.1.1

Hotfix release.

New
- Ignore cipher order when only GOOD ciphers are supported.

Bug Fixes
- Fix scoring bug on FS params.
- Fix scoring bug when no starttls tests could be performed.
- DHE should be SUFFICIENT not GOOD.
- Fix JS bug for matomo.
- Fix unhandled NoIpError exception.
- Typos.

## 1.1.0

TLS 1.3 support, NCSCv2 guidelines, IT suite and more.

New
- Update internet.nl to conform with the new v2 of the NCSC guidelines. [(#402)]
- Updated Hall of Fame. [(#170)]

Dependencies
- Python bumped to 3.7. Make sure to update your environment and reinstall
  everything Python related (including unbound). You can follow the
  [Installation instructions](https://github.com/NLnetLabs/Internet.nl/blob/v1.1.0/documentation/Installation.md).
- The [nassl fork](https://github.com/ximon18/nassl/tree/free_bsd) was updated.
  Make sure to use the _new_ repository and follow the
  [Installation instructions](https://github.com/NLnetLabs/Internet.nl/blob/v1.1.0/documentation/Installation.md).

Bug Fixes
- Long domain names break the design. [(#401)]
- Use headings where text is styled as headings. [(#389)]
- Alternative text for images | green and red shields statistics on homepage. [(#387)]
- Contrast too low for text "Dated result ....". [(#307)]
- Skiplink (to menu) does not work in small screens. [(#306)]
- Fix the mailserver part of DNSSEC to give a warning when there are no mailservers.
- Connection test: DNSSEC defaults to secure when no client connection. [(#410)]
- Widget for embedding test on other websites. [(#362)]
- HTML-element is closed while not opened based on @julezrulez commit. [(#392)]
- Try to detect browser DoNotTrack. [(#426)]

[(#401)]: https://github.com/NLnetLabs/Internet.nl/issues/401
[(#402)]: https://github.com/NLnetLabs/Internet.nl/issues/402
[(#389)]: https://github.com/NLnetLabs/Internet.nl/issues/389
[(#387)]: https://github.com/NLnetLabs/Internet.nl/issues/387
[(#307)]: https://github.com/NLnetLabs/Internet.nl/issues/307
[(#306)]: https://github.com/NLnetLabs/Internet.nl/issues/306
[(#410)]: https://github.com/NLnetLabs/Internet.nl/issues/410
[(#362)]: https://github.com/NLnetLabs/Internet.nl/issues/362
[(#170)]: https://github.com/NLnetLabs/Internet.nl/issues/170
[(#392)]: https://github.com/NLnetLabs/Internet.nl/issues/392
[(#426)]: https://github.com/NLnetLabs/Internet.nl/issues/426

## 1.0.3

Hotfix release.

Dependencies
- The [python-whois fork](https://github.com/ralphdolmans/python-whois) was
  updated. Make sure to pull the latest version and reinstall.

Bug Fixes
- Uncaught exception from python-whois. [(#374)]
- Typos.

[(#374)]: https://github.com/NLnetLabs/Internet.nl/issues/374

## 1.0.2

Hotfix release.

Bug Fixes
- Report unusable TLSA records as non-valid. [(#372)]

[(#372)]: https://github.com/NLnetLabs/Internet.nl/issues/372

## 1.0.1

Hotfix release.

Bug Fixes
- Don't check the root certificate's hash function. [(#368)]
- Missing space between test explanation and technical details. [(#369)]

[(#368)]: https://github.com/NLnetLabs/Internet.nl/issues/368
[(#369)]: https://github.com/NLnetLabs/Internet.nl/issues/369

## 1.0.0

Initial public release.
