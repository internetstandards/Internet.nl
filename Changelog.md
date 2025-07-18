# Change Log

## 1.11.0 (in progress)

_Compared to the latest 1.10 release._

### Feature changes

- ...

### Significant internal changes

- ...
- 
### Possibly required changes to deployments

...

### API changes

- ...

## 1.10.3

- Added [missing User-Agent](https://github.com/internetstandards/Internet.nl/issues/1048) to 0-RTT HTTP requests

## 1.10.2

- Updated unbound to fix an issue where
  [DNSSEC insecure targets could be flagged as bogus](https://github.com/internetstandards/Internet.nl/issues/1803)
  due to [unbound incorrectly returning a bogus EDE](https://github.com/NLnetLabs/unbound/issues/1293).
- Fixed an issue where
  [DMARC records were not always found](https://github.com/internetstandards/Internet.nl/issues/1808)
  on CloudFlare name servers.
- Added missing [CAA fields to API](https://github.com/internetstandards/Internet.nl/pull/1801).
- Fixed [incomplete detection of insufficient or invalid CAA](https://github.com/internetstandards/Internet.nl/pull/1811)
  along with some improvements in UTF-8 handling.

The API version is updated to 2.6.0 due to the new CAA fields.

## 1.10.1

- Fixed handling for [CAA with non-ascii characters](https://github.com/internetstandards/Internet.nl/pull/1788).
- Fixed possible exception in [mail test prechecks](https://github.com/internetstandards/Internet.nl/pull/1787).
- Fixed an [issue with rate limiting](https://github.com/internetstandards/Internet.nl/pull/1792).
- Update [Django to 4.2.22](https://github.com/internetstandards/Internet.nl/pull/1795) to fix 
  [CVE-2025-48432](https://www.djangoproject.com/weblog/2025/jun/04/security-releases/).

## 1.10.0

_Compared to the latest 1.9 release._

### Feature changes

- A test for CAA records was added for web and mail tests. This checks for the presence of one or more correctly
  formatted CAA records, of which one must have an `issue` tag. This test is not required, i.e. does not affect scoring.
- The [sectxt](https://github.com/DigitalTrustCenter/sectxt) library, used for validating security.txt files, was updated from 0.9.4 to 0.9.7.
  This includes:
  - A new error if a PGP signed message ends with more than one newline, named `too_many_line_separators` ([sectxt/#78](https://github.com/DigitalTrustCenter/sectxt/issues/78)).
  - Improved detection of repeated use of fields that must only occur once. Previously, these were not always detected ([sectxt/#83](https://github.com/DigitalTrustCenter/sectxt/issues/83)).
  - Fixed an issue with checking signatures made with AEAD keys ([sectxt/#79](https://github.com/DigitalTrustCenter/sectxt/issues/79)).
  - Fixed exception [for certain malformed PGP signatures](https://github.com/DigitalTrustCenter/sectxt/issues/85).
- The test date and time are now [included in the print CSS](https://github.com/internetstandards/Internet.nl/pull/1735).

### Significant internal changes

- The test code no longer interfaces with libunbound, but 
 [uses dnspython as a stub resolver](https://github.com/internetstandards/Internet.nl/pull/1578).
- Periodic tests [are no longer enabled by default](https://github.com/internetstandards/Internet.nl/pull/1628).
- UWSGI [cheaper](https://uwsgi-docs.readthedocs.io/en/latest/Cheaper.html) options are used to reduce idle processes and reduce memory consumption.

### Possibly required changes to deployments

- The `resolver-permissive` container was obsoleted and removed.
- Periodic tests will only run when [specifically enabled](https://github.com/internetstandards/Internet.nl/blob/main/documentation/Docker-deployment.md#periodic-tests)
  with the CRON_15MIN_RUN_TESTS, TEST_DOMAINS_SITE and/or TEST_DOMAINS_MAIL settings.
- There is now support for running multiple instances per server, sharing a Routinator instance,
  intended for acceptance testing.

On upgrade from an earlier version, a
[change in networking setup](https://github.com/internetstandards/Internet.nl/pull/1688) requires
recreation of one of the Docker networks. Before deploy, bring down the entire environment and make sure the network is removed:
```
docker compose --project-name=internetnl-prod down
docker network rm internetnl-prod_public-internet
```

### API changes

- The API version was updated to version 2.5.0.
- The fields `caa_enabled`, `caa_errors`, `caa_recommendations`, `caa_records`, and `caa_found_on_domain` have been added
  ([OpenAPI diff](https://github.com/internetstandards/Internet.nl/blob/0dd94d67a6363404cfcf6e2690d6938d09b319b2/interface/batch/openapi.yaml#L738-L760)).
- The API report URL was [updated to use HTTPS](https://github.com/internetstandards/Internet.nl/issues/1704).

## 1.9.3

- Updated the [expired PGP key](https://github.com/internetstandards/Internet.nl_content/pull/57).
  
## 1.9.2

- Fixed an issue where static files incorrectly required authentication (#1676)

## 1.9.1

- Fixed an issue where the database cleanup would use excessive memory and get an OOM kill (#1670)

## 1.9.0

1.9.0 (compared to latest 1.8) contains several testing changes, along with content improvements:

- The RPKI test [is now included in the total test score](https://github.com/internetstandards/Internet.nl/issues/745)
  and its worst score is now a failure.
  Note that, as the score is evenly divided over all major categories, the score impact from each individual major
  category has been reduced. Therefore, scoring success on RPKI but fail on other tests, may result in a higher score
  than with 1.8. See the [scoring documentation](https://github.com/internetstandards/Internet.nl/blob/main/documentation/scoring.md)
  for details on the scoring algorithm.
- [Improvements in the null MX recommendation](https://github.com/internetstandards/Internet.nl/issues/989) based on SPF values.
- SPF test now [correctly counts include/redirect for the 10 lookup limit](https://github.com/internetstandards/Internet.nl/issues/1336).
- DMARC test now [detects a missing URI scheme](https://github.com/internetstandards/Internet.nl/pull/1493).

Internal changes:
- CI now detects missing or conflicting database migrations.
- Many documentation improvements.
- Improvements in customisability for forked versions.

For all issues, see the [1.9 milestone](https://github.com/internetstandards/Internet.nl/issues?q=milestone%3Av1.9),
though some of those were backported to 1.8 already.

## 1.8.10

1.8.10 contains a [fix in IPv6 nameserver reachability](https://github.com/internetstandards/Internet.nl/issues/1597).
The test did not correctly check connectivity to the IPv6 address, causing false good tests.
This was likely introduced in 1.8.0.

## 1.8.9

1.8.9 contains a [fix for batch scheduling](https://github.com/internetstandards/Internet.nl/pull/1554) where report
generation did not have appropriate locking. During busy moments, this caused the queue to overflow with repeated
jobs to generate the same report over and over.

## 1.8.8.1

1.8.8.1 is a release only to [add an intermediate news post](https://github.com/internetstandards/Internet.nl/pull/1535).

## 1.8.8

1.8.8 is a release only to [add an intermediate news post](https://github.com/internetstandards/Internet.nl/pull/1516).

## 1.8.7

1.8.7 mainly contains various important fixes to support batch deployment.

* Updated sectxt to use a patched version of PGPy with a fix for a 
  [catastrophic regex backtracking issue](https://github.com/SecurityInnovation/PGPy/pull/467)
* Updated nassl to fix memory leak in OCSP check.
* Connection test zones are now re-signed every week instead of every month.
* Support for new Docker (compose) versions and some checks for incompatible versions.
* Many updates to the Docker setup to handle issues with large batch jobs
* Extensions in Grafana dashboards for batch monitoring.
* Various improvements to CI UX.
* Update to the [latest version of sectxt](https://github.com/internetstandards/Internet.nl/issues/1046)
  which includes detection of BOM, unknown fields, and several PGP issues.

## 1.8.6

Functional changes:

* Fixed an issue where redirects with an explicit port 443 were incorrectly.
  rejected in the HTTPS redirect test (#1291).
* 4xx and 5xx in the IPv4/6 similarity test are now permitted (#1267).
* Changed user agent to a common format (#1224).
* Fixed excessive caching TTLs in some DNS queries for some tests.
* Added support for br and zstd compression in HTTP compression test.
* All tests, except some parts of TLS, now use a [standard User-Agent format](https://github.com/internetstandards/Internet.nl/issues/1224)
  which can also be modified for third party deployments.

Internal changes:

* Access and user management was improved with a separate command to manage users,
  which can be applied to batch API only, or all URLS (#1267, #1274, #1396).
* Added periodic re-signing of connection test DNS zones.
* DNS configuration was documented along with several fixes in the certbot config (#1275, #1228).
* Added a log exporter for nginx.
* Added test probes every 15 minutes.
* Added periodic restart for nassl worker.
* Several other bugfixes.

## 1.8.5

Release 1.8.5 contains a hotfix for the [sectxt library failing on leap days](https://github.com/DigitalTrustCenter/sectxt/issues/66).

## 1.8.4

Release 1.8.4:

- Updates unbound to 1.19.1-internetnl to fix CVE-2023-50387 and CVE-2023-50868.
- Restricts HTTPS redirects to the same domain, no longer allowing directions to a subdomain first (#1208).
- Updates a number of other dependencies.
- Fixes an issue where certbot renewals were not correctly run.

## 1.8.3

Release 1.8.3 fixes an issue where HSTS and CSP headers were missing from he www-subdomain of the main domain (#1210, #1211).

## 1.8.2

Release 1.8.2 fixes an issue where the connection test would fail to start in certain cases due to an incorrect HTTP downgrade (#1194, #1195).

## 1.8.1

Version 1.8.1 includes a number of internal improvements, including:

- Various improvements in the build setup, including building forks.
- Improvements in logging quality and reducing log volume.
- Corrections in the live tests.
- Improved error handling in TLS certificate requests in deployments.

There are no changes to functionality or requirements of the tests.

## 1.8.0

- A new [Docker based deployment, development, testing and CI setup](https://github.com/internetstandards/Internet.nl/pull/890) has been added to replace all previous processes. See the [getting started guide](https://github.com/internetstandards/Internet.nl/blob/main/documentation/Docker.md) for how to use this.
- The test for Referrer-Policy has been updated to [check for a sufficiently secure and valid policy](https://github.com/internetstandards/Internet.nl/issues/357).
- The security.txt test now [checks the Canonical field](https://github.com/internetstandards/Internet.nl/issues/772) as well.
- Updated to [version 0.8.3 of the sectxt library](https://github.com/DigitalTrustCenter/sectxt) including validation of CSAF fields.
- RFC9091 np= is now [permitted in DMARC policies](https://github.com/internetstandards/Internet.nl/issues/876).
- The Content-Security-Policy check now [requires explicit https: scheme](https://github.com/internetstandards/Internet.nl/issues/810) and an issue was fixed where ['none' combined with other sources](https://github.com/internetstandards/Internet.nl/issues/913) was incorrectly accepted.
- The IPv4/IPv6 similarity test was [relaxed to a notice](https://github.com/internetstandards/Internet.nl/issues/485) when the response contents are different.
- Fixed [incorrect handling of IPv6-mapped IPv4 addresses](https://github.com/internetstandards/Internet.nl/issues/824) in the RPKI test.
- [Improved attributes in input fields](https://github.com/internetstandards/Internet.nl/issues/943) for improved user experience.
- Fixed an [issue in footer alignment](https://github.com/internetstandards/Internet.nl/issues/494).

This release has API version 2.4.0:
- The `referrer_policy_errors` and `referrer_policy_recommendations` fields were added.
  These contain errors and/or recommendations regarding the Referrer-Policy test.
- `https_redirect` can now also have “no_https” as status, for a web server that offers either no HTTPS or HTTPS with a very outdated, insecure TLS configuration, as in this case the redirect is not evaluated.

## 1.7.1

- Fixed the new [display of TLS versions](https://github.com/internetstandards/Internet.nl/issues/944) for mail tests. 
- Fixed a [language mix-up](https://github.com/internetstandards/Internet.nl/issues/941) in the security.txt labels.
- Fixed an [issue with the connection test and CSP form-action](https://github.com/internetstandards/Internet.nl/issues/945)

## 1.7

- Added specific [error messages in the technical details](https://github.com/internetstandards/Internet.nl/issues/577)
  for Content-Security-Policy results.
- Added requirements for [base-uri](https://github.com/internetstandards/Internet.nl/issues/525) and
  [form-action](https://github.com/internetstandards/Internet.nl/issues/524) to the Content-Security-Policy test.
- Added translations for [security.txt error messages](https://github.com/internetstandards/Internet.nl/issues/774).
- The TLS versions tech table
  [now shows the detected TLS versions](https://github.com/internetstandards/Internet.nl/issues/512)
  instead of only TLS versions with issues.
- Fixed an [uncaught exception](https://github.com/internetstandards/Internet.nl/issues/494)
  in the security.txt text which could cause the entire test to fail for some HTTP responses.
- Corrected handling of [bogus TLSA records](https://github.com/internetstandards/Internet.nl/issues/681).
- A bare "https:" is [no longer allowed in Content-Security-Policy](https://github.com/internetstandards/Internet.nl/pull/925)
  as it matches any HTTPS host.
- [Loosened requirement for null MX](https://github.com/internetstandards/Internet.nl/issues/748)
  when a domain has no A or AAAA.
- Fixed an issue where the
  [frame-src test was inconsistent with the documentation](https://github.com/internetstandards/Internet.nl/issues/643).
- [Added the version number](https://github.com/internetstandards/Internet.nl/issues/494) to the footer.
- [Added Sentry support](https://github.com/internetstandards/Internet.nl/issues/770) for error reporting.
- Code quality was cleaned up in various places.
- Dependencies were updated.

This release has API version 2.3.0:
- The `record_org_domain` was added for DMARC
  ([#489](https://github.com/internetstandards/Internet.nl/issues/489)).
- The `securitytxt_errors` and `securitytxt_recommendations` types were changed.
  They now contain error codes (and possibly context) rather than full sentences.
- The `content_security_policy_errors` field was added with error codes for CSP.
- An issue was fixed where the `mx_nameservers` field was not included in results
  ([#882](https://github.com/internetstandards/Internet.nl/issues/882)).

## 1.6.3

- Fixed an issue in the HTTPS client code that caused DMARC records to not be detected, due to a missing
  public suffix list.

## 1.6.2

- Fixed issues in the example configs regarding [celery concurrency](https://github.com/internetstandards/Internet.nl/issues/817)
- Fixed an issue where test failures could cause [old test results to be displayed instead](https://github.com/internetstandards/Internet.nl/pull/802)
- Added [celery task info to log messages](https://github.com/internetstandards/Internet.nl/commit/d59ae723c095c2f1ef98b9c16e28bba02a9e49ff) to help debugging/tracing
- Small fixes to test explanation content

This release has API version 2.2.0, as there are no API changes.

## 1.6.1

- Fixed issues in the security.txt check for [invalid time formats](https://github.com/internetstandards/Internet.nl/pull/800) and [empty responses](https://github.com/internetstandards/Internet.nl/issues/790)
- [Updated social media links](https://github.com/internetstandards/Internet.nl/issues/804)
- [Fixed an issue in the API and updated the version](https://github.com/internetstandards/Internet.nl/pull/776)

This release has API version 2.2.0, a late update due to new fields added in 1.6.0.

## 1.6

- Add [security.txt support](https://github.com/internetstandards/Internet.nl/pull/730).
  For all IPs of web servers, this looks for the existence and validity of a
  [RFC9116](https://www.rfc-editor.org/rfc/rfc9116.html) security.txt file.

This release has API version 2.1.0, which is incorrect as it does include new fields for security.txt. This was fixed in 1.6.1.

## 1.5.1

- Fixes a tiny typo in the RPKI news content.

This release has API version 2.1.0, as there are no API changes.

## 1.5.0

#### New

- RPKI support [(#613)]. For all IPs of all name servers, mail servers and web server, this check looks for the existence of an RPKI ROA, and whether all BGP routes covering these IPs are valid. As this is a new check, the total score does not yet include RPKI results.

#### Other changes

- Fixed issues with the IPv4/IPv6 consistency test for large pages [(#665)]
- Various dependencies updated [(#721)] [(#725)] [(#695)] [(#688)] [(#712)]
- Internal documentation improvements [(#717)]
- Small improvements in cache reset requests [(#724)]
- Small improvements in various test explanations.
- The privacy statement was updated to clarify the use of third party services.

This release has API version 2.1.0, as it includes new fields for RPKI.

## 1.4.0
Software update and development & documentation release.

Note: the docker image will not build at the moment, this is a work in progress and will be in 1.4.1.

New
- Mention LinkedIn next to Twitter in footer [(#496)]
- Add security.txt based on https://securitytxt.org/ [(#493)]

Changes
- Improve description of the ipv4-ipv6 comparison results and what may be a reason for the differences [(#540)]
- Refer to https://dutchcloudcommunity.nl/ on https://internet.nl/about/ [(#589)]
- Check for max of 10 DNS lookups in SPF test [(#286)]
- System administrators can disable/enable categories of tests (for example, only run IPv6 tests)
- Files from the /static/ directory are now cached by the client for one day by default (instead of none)

Bugfixes
- Fix some minor typos and broken link [(#574)] [(#575)]
- Add a missing ' in the frame-ancestors explanation [(#578)]
- An empty part of Content Security Policy gives an error [(#583)]
- Recursion error when stripping nonces in IPv4 and IPv6 comparison [(#587)] 
- Remove certificate from the certificate chain in the shipped cert chain file [(#614)]

Dependencies
- Update Django version to latest LTS version, together with dependencies [(#486)]
- Update version of Celery to the latest LTS version, together with dependencies [(#586)]
- Updated jQuery (also stops support for very old browsers) [(#565)]
- Pinned all dependencies on specific versions with pip-tools.

Settings
- Moved Django settings to an environment file, so it can be more easily configured in automated environments (containers)
- Made a clear distinction between user confgured settings and 'standard app settings'
- Add DEFAULT_AUTO_FIELD to default config file [(#599)]
- Increased the test duration 50%-100% for all tests on single mode, to deal with slow servers or servers that have a lot of MX records.
- Made the rate limiting feature of starting new scans configurable in the settings (not via environment)

Migrations
- Administrative movements of models to a new subproject (checks).

Development & documentation
- Added installation steps to makefile for easier installation of the virtual environment and custom python dependencies
- Added Github action that checks for code linting and runs tests. More QA tools to come.
- Added various tests and moved the existing tests to be run in pytest. Coverage today: 32%
- Added a partial admin web interface that is available during development, to more easily inspect the contents of the database
- Added an ERD diagram image of the database to the documentation
- Removed infinite wait on Unbound pipe, to reduce complexity in the connection leakage issue (see ahead)
- Added example and usable configuration examples for Redis, workers, services, Apache etc
- Added a logger with dictconfig, this allows run time logging of the application
- Added (debug) log statements for further code inspection, especially on expiring tasks
- Separate scanning code from UI code via a new django app "checks"
- Added workaround / configs for Redis-backend-connection leak: https://github.com/internetstandards/Internet.nl/issues/676 on single scan mode. Cron settings and some bash scripts that restart the scan services every 6 hours. This allows tens of thousands of scans per recycle.
- Spread out tasks over more dedicated workers to be able to inspect and manage bottlenecks
- Fixed Django-app bootstrapping, which prevented the app from loading correctly
- Building and testing for Python 3.7 and 3.10 to transit to the new version
- Added caching of static files in the apache config
- Simplified and deduplicated the apache config

This release has API version 2.0.1.

## 1.3.2

Hotfix release.

Changes
- (Docker) Use pg_isready to check db availability on startup [(#551)]

Bug Fixes
- CSP: subdomains not processed properly within default-src directive [(#530)]
- Fix for Public Suffix List: do not ignore rules that include wildcards.
- Key exchange parameter divergence [(#538)]
- Fix for 'non email sending domains and DKIM' does not work for bare domains [(#532)]
- Fix broken github tarball url for internetstandards/nassl [(#549)]
- Work around Celery bug #5409 leaving stale pid files [(#550)]
- Do not test redirects after test for first upgrade to HTTPS in "HTTPS redirect" subtest [(#555)]
- Typos.

Dependencies
- Updated fork targets:
  - unbound: https://github.com/ralphdolmans/unbound -> https://github.com/internetstandards/unbound
  - nassl: https://github.com/ximon18/nassl -> https://github.com/internetstandards/nassl
  - python-whois: https://github.com/ralphdolmans/python-whois -> https://github.com/internetstandards/python-whois

[(#530)]: https://github.com/internetstandards/Internet.nl/issues/530
[(#532)]: https://github.com/internetstandards/Internet.nl/issues/532
[(#538)]: https://github.com/internetstandards/Internet.nl/issues/538
[(#549)]: https://github.com/internetstandards/Internet.nl/issues/549
[(#550)]: https://github.com/internetstandards/Internet.nl/issues/550
[(#551)]: https://github.com/internetstandards/Internet.nl/issues/551
[(#555)]: https://github.com/internetstandards/Internet.nl/issues/555

## 1.3.1

Hotfix release.

Bug Fixes
- Pick the correct domain for checking nameservers. [(#526)]
- Typos.

[(#526)]: https://github.com/internetstandards/Internet.nl/issues/526

## 1.3.0

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
- Updated requirements.txt:
  - django-redis pinned to 4.10
  - celery bumped to 4.3.1 (vine dependency)
  - vine pinned to 1.3.0
  - beautifulsoup4 added [(#463)]
  - idna added [(#507)]

Migrations
- New column in DB (mailtestauth_dmarc_record_org_domain). [(#249)]
- New columns in DB for NULL MX. [(#468)]

Settings
- New SMTP_EHLO_DOMAIN setting in settings.py. [(#483)]
- New optional HAS_ACCESSIBILITY_PAGE setting in settings.py. [(#290)]

[(#249)]: https://github.com/internetstandards/Internet.nl/issues/249
[(#290)]: https://github.com/internetstandards/Internet.nl/issues/290
[(#329)]: https://github.com/internetstandards/Internet.nl/issues/329
[(#325)]: https://github.com/internetstandards/Internet.nl/issues/325
[(#341)]: https://github.com/internetstandards/Internet.nl/issues/341
[(#421)]: https://github.com/internetstandards/Internet.nl/issues/421
[(#443)]: https://github.com/internetstandards/Internet.nl/issues/443
[(#461)]: https://github.com/internetstandards/Internet.nl/issues/461
[(#463)]: https://github.com/internetstandards/Internet.nl/issues/463
[(#468)]: https://github.com/internetstandards/Internet.nl/issues/468
[(#477)]: https://github.com/internetstandards/Internet.nl/issues/477
[(#483)]: https://github.com/internetstandards/Internet.nl/issues/483
[(#484)]: https://github.com/internetstandards/Internet.nl/issues/484
[(#503)]: https://github.com/internetstandards/Internet.nl/issues/503
[(#506)]: https://github.com/internetstandards/Internet.nl/issues/506
[(#507)]: https://github.com/internetstandards/Internet.nl/issues/507
[(#508)]: https://github.com/internetstandards/Internet.nl/issues/508

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

[(#336)]: https://github.com/internetstandards/Internet.nl/issues/336
[(#337)]: https://github.com/internetstandards/Internet.nl/issues/337
[(#395)]: https://github.com/internetstandards/Internet.nl/issues/395
[(#411)]: https://github.com/internetstandards/Internet.nl/issues/411
[(#417)]: https://github.com/internetstandards/Internet.nl/issues/417
[(#437)]: https://github.com/internetstandards/Internet.nl/issues/437
[(#436)]: https://github.com/internetstandards/Internet.nl/issues/436
[(#455)]: https://github.com/internetstandards/Internet.nl/issues/455
[(#456)]: https://github.com/internetstandards/Internet.nl/issues/456
[(#457)]: https://github.com/internetstandards/Internet.nl/issues/457

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
  [Installation instructions](https://github.com/internetstandards/Internet.nl/blob/v1.1.0/documentation/Installation.md).
- The [nassl fork](https://github.com/ximon18/nassl/tree/free_bsd) was updated.
  Make sure to use the _new_ repository and follow the
  [Installation instructions](https://github.com/internetstandards/Internet.nl/blob/v1.1.0/documentation/Installation.md).

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

[(#401)]: https://github.com/internetstandards/Internet.nl/issues/401
[(#402)]: https://github.com/internetstandards/Internet.nl/issues/402
[(#389)]: https://github.com/internetstandards/Internet.nl/issues/389
[(#387)]: https://github.com/internetstandards/Internet.nl/issues/387
[(#307)]: https://github.com/internetstandards/Internet.nl/issues/307
[(#306)]: https://github.com/internetstandards/Internet.nl/issues/306
[(#410)]: https://github.com/internetstandards/Internet.nl/issues/410
[(#362)]: https://github.com/internetstandards/Internet.nl/issues/362
[(#170)]: https://github.com/internetstandards/Internet.nl/issues/170
[(#392)]: https://github.com/internetstandards/Internet.nl/issues/392
[(#426)]: https://github.com/internetstandards/Internet.nl/issues/426

## 1.0.3

Hotfix release.

Dependencies
- The [python-whois fork](https://github.com/ralphdolmans/python-whois) was
  updated. Make sure to pull the latest version and reinstall.

Bug Fixes
- Uncaught exception from python-whois. [(#374)]
- Typos.

[(#374)]: https://github.com/internetstandards/Internet.nl/issues/374

## 1.0.2

Hotfix release.

Bug Fixes
- Report unusable TLSA records as non-valid. [(#372)]

[(#372)]: https://github.com/internetstandards/Internet.nl/issues/372

## 1.0.1

Hotfix release.

Bug Fixes
- Don't check the root certificate's hash function. [(#368)]
- Missing space between test explanation and technical details. [(#369)]

[(#368)]: https://github.com/internetstandards/Internet.nl/issues/368
[(#369)]: https://github.com/internetstandards/Internet.nl/issues/369

## 1.0.0

Initial public release.


# Template:
## Next unreleased version

--- Brief description for next version ---

New
- 

Changes
- 

Bug Fixes
-

Dependencies
- 

Migrations
- 

Settings
- 
