# Batch testing HTTP API

This document provides general documentation and lists the available API
requests and their possible replies for the batch testing.

## General information

### Access

The domain for the batch testing is <batch_domain>. Access to this domain is
granted by the provided username:password through HTTP Basic Authentication.

Given the plaintext/hashed nature of HTTP Basic Authentication, connections to
the site should use HTTPS.

If you use software that needs the HTTP Basic Authentication information to be
manually inserted as an HTTP header, the "username:password" string should be
base64 encoded and used in a header like:

`
Authorization: Basic (base64-encoded-string)
`

### Versioning

The batch API uses a version number. A change in the version number means that
the output or user input of the API may have changed. Any changes will be
documented in this section.

The version number is part of the results (see below) but also is part of the
API's URLs. In case the user requests a URL with the previous version, a
message to check the version number will be returned as a result to the API
call.

The version number's purpose is to only indicate changes in the API. No support
for previous versions will be provided.

## Registering a web batch request

In order to register a batch request we need to provide a name (does not have
to be unique between batch requests, mainly used as an identifier for the user)
and the desired domains in a list.

Only unique and valid domain names of the ones provided are going to be tested.
This may produce less results than the number of domain names initially
submitted.

*__A note on the domains' list:__ After the initial validation of the domains'
name, domains are used as-is. It is therefore the responsibility of the user to
provide all the needed domains to be tested (i.e. web testing the bare and the
www-version of a domain requires both domain names to be present in the
domains' list).*

```
POST /api/batch/v1.0/web/ HTTP/1.1

{ "name": "My web test",
  "domains": [ "nlnetlabs.nl",
               "www.nlnetlabs.nl",
               "opennetlabs.nl",
               "www.opennetlabs.nl" ]}
```

### Expected answer

```
HTTP/1.1 200 OK
Content-Type: application/json

{ "success": true,
  "message": "OK",
  "data": {
            "results": "https://<batch_domain>/api/batch/v1.0/results/01c70c7972d143ffb0c5b45d5b8116cb/"
          }
}
```
where we can poll the `results` url for the batch's results.

### Other answers

Other possible answers could be:

1. Problem while parsing the domains from the above request.
   ```
   HTTP/1.1 200 OK
   Content-Type: application/json

   { "success": false,
     "message": "Problem parsing domains",
     "data": []
   }

   ```

## Registering a mail batch request

```
POST /api/batch/v1.0/mail/ HTTP/1.1

{ "name": "My mail test",
  "domains": [ "nlnetlabs.nl",
               "opennetlabs.nl" ]}
```
Apart from the difference in the request path, the web and mail register
requests have the same expected answers.

## Getting results

We can get/poll the results by using the `results` url provided when
registering a batch request.

```
GET /api/batch/v1.0/results/01c70c7972d143ffb0c5b45d5b8116cb/ HTTP/1.1
```

### Expected answer

```
HTTP/1.1 200 OK
Content-Type: application/json

{ "success": true,
  "message": "OK",
  "data": {
    "submission-date": "2017-10-05T10:16:19.316626+00:00",
    "finished-date": "2017-10-05T10:26:19.316626+00:00",
    "name": "My web test"
    "identifier", "01c70c7972d143ffb0c5b45d5b8116cb",
    "api-version", "1.0",
    "domains": [
      { "domain": "www.nlnetlabs.nl",
        "status": "failed" },
      { "domain": "opennetlabs.nl",
        "status": "ok",
        "score": "80",
        "link": "https://<batch_domain>/domain/opennetlabs.nl/28905/",
        "categories": [
          { "category": "ipv6",
            "passed": true },
          { "category": "dnssec",
            "passed": false },
          { "category": "appsecpriv",
            "passed": false },
          { "category": "tls",
            "passed": true } ],
        "views" : [
          { "name": "only_tls",
            "result": true } ] },
            ...
            ...
    ]
  }
}
```
Notes on return values:
- The period between `submission-date` and `finished-date` does not indicate
  the duration of the batch test. This is only true when only one batch test is
  running;
- A change in `api-version` may indicate changes in the response's structure;
- `status` could be either `"ok"` or `"failed"`. A `"failed"` status means that
  something went wrong (i.e. not all categories could be tested) and does not
  include any more results for that domain;
- The url in the `link` points to the results page of <batch_domain>. This
  is the same report as generated for the vanilla internet.nl site;
- `categories` are the main categories as seen on the vanilla internet.nl site:
  - `ipv6` (web and mail test),
  - `dnssec` (web and mail test),
  - `auth` (mail test only),
  - `tls` (web and mail test);
  - `appsecpriv` (web test only);
- `views` include custom views that return a desired result per domain. These
  views are per user and made available on demand.

### Other answers

Other possible answers could be:

1. Batch test is registering the domains in the DataBase (no results yet, can
   continue polling):
   ```
   HTTP/1.1 200 OK
   Content-Type: application/json

   { "success": false,
     "message": "Batch request is registering domains",
     "data": {
         "results": "https://<batch_domain>/api/batch/v1.0/results/01c70c7972d143ffb0c5b45d5b8116cb/"
     }
   }
   ```
   The `results` url is the same as the one we are requesting.

2. Batch test is running (no results yet, can continue polling):
   ```
   HTTP/1.1 200 OK
   Content-Type: application/json

   { "success": false,
     "message": "Batch request is running",
     "data": {
         "results": "https://<batch_domain>/api/batch/v1.0/results/01c70c7972d143ffb0c5b45d5b8116cb/"
     }
   }
   ```
   The `results` url is the same as the one we are requesting.

3. Results are being generated (continue polling for results):
   ```
   HTTP/1.1 200 OK
   Content-Type: application/json

   { "success": false,
     "message": "Results are being generated",
     "data": {
         "results": "https://<batch_domain>/api/batch/v1.0/results/01c70c7972d143ffb0c5b45d5b8116cb/"
     }
   }
   ```
   Batch testing has finished and the results are being generated in JSON
   format.

4. Error while registering the domains (batch request will not run):
   ```
   HTTP/1.1 200 OK
   Content-Type: application/json

   { "success": false,
     "message": "Error while registering the domains",
     "data": []
   }
   ```

## Custom views

Custom views are extra/more specific information per domain tested as
indicated in the "Getting results" section. They can be defined by the users
and made available only to the users that requested them.

Examples of views could be as simple as
> I want to know if an SPF record is available per domain

which is a one-on-one mapping of a subtest to a view, or as complex as
> I want to know if the domain is conformant to NCSC's TLS guidelines

and
> I want to know if there are content differences between IPv4 and IPv6

both of which need a subset or combination of different subtests.

What custom views are mainly trying to accomplish is that given a firm
description by the user they can guarantee the same conceptual result even if
tests change between releases.

## General error responses

There are two types of error responses that may be encountered when interfacing
with the API:

1. HTTP method not allowed:
   ```
   HTTP/1.1 405 METHOD NOT ALLOWED
   Allow: [<list of HTTP methods allowed for this url>]
   ```
   This could happen if the wrong HTTP method was used when requesting a url.

2. User misconfiguration:
   ```
   HTTP/1.1 200 OK
   Content-Type: application/json

   { "success": false,
     "message": "Unknown user",
     "data": []
   }
   ```
   This could happen when there is a misconfiguration with the user's
   authentication details on the server side.

3. API version change / invalid URL:
   ```
   HTTP/1.1 200 OK
   Content-Type: application/json

   { "success": false,
     "message": "Make sure you are using a valid URL with the current batch API version (1.0)",
     "data": []
   }
   ```
   This could happen when the URL used was invalid or the API version number
   has changed.
