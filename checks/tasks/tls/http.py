from urllib.parse import urlparse

import requests

from checks import scoring
from checks.http_client import http_get_ip
from checks.models import ForcedHttpsStatus
from checks.tasks.http_headers import (
    HeaderCheckerContentEncoding,
    HeaderCheckerStrictTransportSecurity,
    http_headers_check,
)


def http_checks(af_ip_pair, url, task):
    """
    Perform the HTTP header and HTTPS redirection checks for this webserver.
    """
    forced_https_score, forced_https = forced_http_check(af_ip_pair, url, task)
    header_checkers = [
        HeaderCheckerContentEncoding(),
        HeaderCheckerStrictTransportSecurity(),
    ]
    header_results = http_headers_check(af_ip_pair, url, header_checkers, task)
    results = {
        "forced_https": forced_https,
        "forced_https_score": forced_https_score,
    }
    results.update(header_results)
    return results


def forced_http_check(af_ip_pair, url, task):
    """
    Check if the webserver is properly configured with HTTPS redirection.
    """
    try:
        http_get_ip(hostname=url, ip=af_ip_pair[1], port=443, https=True)
    except requests.RequestException:
        # No HTTPS connection available to our HTTP client.
        # Could also be too outdated config (#1130)
        return scoring.WEB_TLS_FORCED_HTTPS_BAD, ForcedHttpsStatus.no_https

    try:
        response_http = http_get_ip(hostname=url, ip=af_ip_pair[1], port=80, https=False)
    except requests.RequestException:
        # No plain HTTP available, but HTTPS is
        return scoring.WEB_TLS_FORCED_HTTPS_NO_HTTP, ForcedHttpsStatus.no_http

    forced_https = ForcedHttpsStatus.bad
    forced_https_score = scoring.WEB_TLS_FORCED_HTTPS_BAD

    for response in response_http.history[1:] + [response_http]:
        if response.url:
            parsed_url = urlparse(response.url)
            # Requirement: in case of redirecting, a domain should firstly upgrade itself by
            # redirecting to its HTTPS version before it may redirect to another domain (#1208)
            if parsed_url.scheme == "https" and url == parsed_url.hostname:
                forced_https = ForcedHttpsStatus.good
                forced_https_score = scoring.WEB_TLS_FORCED_HTTPS_GOOD
            break

    return forced_https_score, forced_https
