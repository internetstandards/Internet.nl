# RPKI check

The RPKI test looks for the existence and validity of a ROA for each web server
(web test), mail server (mail test), name server of the domain, and name server
of the MX domain (mail test only). The test takes all IPv4 and IPv6 addresses,
finds all BGP DFZ routes that contain these addresses, and looks for any
matching ROAs. If all routes are covered by a valid ROA, the test is all green.


## Data sources

The check is designed on a source-agnostic way, but the current implemented
backends are
[Team Cymru's IP to ASN mapping](https://team-cymru.com/community-services/ip-asn-mapping/)
and a (preferably local)
[Routinator](https://www.nlnetlabs.nl/projects/rpki/routinator/) instance.

The IP to ASN mapping service is queried over DNS to find all routes in
the DFZ that cover each address.

The Routinator instance is an RPKI Relying Party implementation that downloads
and verifies RPKI data. The check connects to the HTTP API to find ROAs.
This is configured in the `ROUTINATOR_URL` setting or environment variable.
There are some publicly available instances that can be used for local
testing, like `https://rpki-validator.ripe.net/api/v1/validity`. For large
scale or production setups, you should run your own instance.

Responses are currently not cached. There are some alternative options,
if needed in the future, especially for the IP to ASN mapping, like
[roto-api](https://github.com/NLnetLabs/roto-api) or downloads offered
by [bgp.tools](https://bgp.tools).

The data gathering code for RPKI is quite well separated from the check
logic, and is also reused in the connection test for ASN lookups.


## Scoring decisions

For each category, the status can be:

* _Success_ if all routes for all hosts are covered by at least one
  ROA and all routes are valid.
* _Notice_ if any routes for any host are not covered by a ROA
  (RPKI status not-found) but all covered routes are valid.
* _Fail_ if any routes for any host are covered by a ROA,
  but the covered route is invalid (origin or length mismatch).

The terms not-found, valid and invalid are defined in 
[RFC6811](https://datatracker.ietf.org/doc/html/rfc6811#section-2)
and this decision is made by the Routinator API.
Per RFC6811, the test does not care about additional "unused" ROAs,
like an extra ROA  for an origin AS for which there is no BGP route.

Note that all routes are verified, e.g. if the host is 192.0.2.1,
and there is a valid route for 192.0.2.0/24 and a not-found route
for 192.0.2.0/22, the status is _notice_ due to the not-found route.


## Debugging tips

If you are suspecting a possible error in our data or the test logic,
try the IP in [IRRexplorer](https://irrexplorer.nlnog.net/) and check
the BGP and RPKI columns. Do note that this uses a different data
source for both, so differences can also originate there.


## Limitations

* Scoring impact is currently not implemented, the result is only
  informational at this time.
