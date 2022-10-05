# Security.txt check

The security.txt test looks for the existence and validity of a 
[RFC9116](https://www.rfc-editor.org/rfc/rfc9116.html) security.txt file
on web domains.

It is part of the security options / appsecpriv tests, along with HTTP security
headers. Like those, it runs on each IPv4 and IPv6 address found in web tests.


## Data sources

The check does an HTTPS request to the domain under test, on
`/.well-known/security.txt` and, failing that, `/security.txt`. Redirects are
followed.

The parsing of files is done by the
[sectxt](https://github.com/DigitalTrustCenter/sectxt) library.
This library also contains networking code, but we do not use it.

## Scoring decisions

The status can be:

* _Good (success)_ if a valid security.txt file was found, and
  there are no errors or recommendations.
* _Recommendations (info)_ if a valid security.txt file was found, and
  there were no errors, but there were recommendations.
* _Bad (notice)_ if the file could not be found, or errors were
  found during retrieval (our code) or parsing (sectxt library).

The errors detected in our code during retrieval, i.e. in addition to
errors and recommendations based on the content as detected by the
sectxt library, are:

* `Security.txt could not be located.` in case of a HTTP 404
* `Security.txt could not be located: unexpected HTTP response code {code}.`
  in case of an HTTP response code that is neither 200 nor 404
* `Content must be utf-8 encoded.` if the response could not be decoded
  as utf-8
* `HTTP Content-Type header must be sent.` if the Content-Type header is missing
  (in case of redirects: missing in the last request)
* `Media type in Content-Type header must be 'text/plain'.` or
  `Charset parameter in Content-Type header must be 'utf-8' if present.`
  in case if invalid values in the Content-Type header
* `Security.txt was located on the top-level path (legacy place), but must be placed under the '/.well-known/' path.`
  in case there was a 404 on the well-known path, but a file was found
  and evaluated in the root.

While we do not use the networking/HTTP code of the 
[sectxt](https://github.com/DigitalTrustCenter/sectxt) library, we do aim
to keep our error messages identical where reasonable.

Also note:

* Tests are only performed over HTTPS.
* We do not check TLS certificate name match, consistent with other checks.
  There is a separate TLS check for name matching. The separate check only
  applies to the domain under test, so we do not check certificate validity
  after redirects.
* We follow at most 8 redirects (same as for all other HTTP fetches).
* If the request to `.well-known/security.txt` returns a response code
  other than 200, we try `/security.txt` and proceed from there, and
  generate the error about the legacy path mentioned above.
  In case of other issues, like invalid content-type or other errors,
  there is no fallback to `/security.txt`.
* If we receive a response without Content-Type or a Content-Type other
  than text/plain, the response is not passed to the parser. It is likely
  to be an HTML page, which would flood the user with useless errors
  about syntax errors.
* We only read the first 100KB of the file.
* Errors and recommendations are, at this time, directly passed from
  the sectxt library into the tech table.
* Due to the level of confusion around its meaning, we do not check the
  `Canonical` field at this time.
