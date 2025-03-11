# CAA check

The CAA test looks for the existence and validity of a CAA record. This is
done on the test target domain for web, and each mail server name for mail.

It is part of the TLS certificate tests.
Like those, it runs on each IPv4 and IPv6 address found in web tests,
which is "wrong" as the result is the same. At the time of implementation
though, it was found to be too hard to integrate otherwise.
It's a very light check, so this is acceptable.

Key references:
- [RFC8659](https://www.rfc-editor.org/rfc/rfc8659.html) DNS Certification Authority Authorization (CAA) Resource Record, particularly [chapter 4](https://www.rfc-editor.org/rfc/rfc8659.html#name-mechanism)
- [RFC8657](https://www.rfc-editor.org/rfc/rfc8657.html) Certification Authority Authorization (CAA) Record Extensions for Account URI and Automatic Certificate Management Environment (ACME) Method Binding, specifically [chapter 4](https://www.rfc-editor.org/rfc/rfc8657.html#name-extensions-to-the-caa-record)
- [IANA Certification Authority Restriction Properties](https://www.iana.org/assignments/pkix-parameters/pkix-parameters.xhtml#caa-properties) registry
- [IANA ACME Validation Methods](https://www.iana.org/assignments/acme/acme.xhtml#acme-validation-methods)  registry (referred from RFC8657)

https://caatestsuite.com/ has useful test cases, though those do not work
as a full test target through the web UI, as they only have CAA records.
They work for the `caa` manual probe though.

## Data sources

The check looks up the relevant CAA record, which means it starts with
requesting CAA from the target, and then climbs the tree.

The parsing of records is done by our own parser, built as much as
possible on the ABNF grammar from the RFCs.
Parsing looks only at syntax, and no further network lookups are done.

## Scoring decisions

The status is good (success) if:

* One or more CAA records were found.
* All CAA records have correct syntax.
* At least one CAA record has the `issue` tag.

In all other cases, the status is bad (notice).

## Notes

* The test records `caa_found_on_domain`, also included in a tech table
  line, to know at which tree level the CAA records were retrieved.
* We do not check whether the current TLS certificate matches
  one or more of the `issue*` records, i.e. whether the current
  certificate could be re-issued.
* We do not evaluate more than 1000 records.
* The API and database support recommendations for future use,
  but none are currently used.
