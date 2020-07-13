# Change Log

## Unreleased next version

New

Dependencies

Bug Fixes

## 1.2.1

Bug Fixes
- Fix broken connection test from 1.2.0; wrong variable name.

## 1.2.0

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
