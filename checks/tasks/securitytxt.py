# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from cgi import parse_header
from dataclasses import dataclass
from typing import List, Optional, Dict
from urllib.parse import urlparse

import requests
import sectxt

from checks import scoring
from checks.http_client import http_get_ip, response_content_chunk
from checks.tasks import SetupUnboundContext

SECURITYTXT_LEGACY_PATH = "/security.txt"
SECURITYTXT_EXPECTED_PATH = "/.well-known/security.txt"
SECURITYTXT_MAX_LENGTH = 100 * 1024


@dataclass
class SecuritytxtRetrieveResult:
    found: bool
    content: Optional[str]
    url: str
    found_host: str
    found_url: Optional[str]
    errors: List[Dict[str, str]]


def securitytxt_check(af_ip_pair, domain, task):
    result = _retrieve_securitytxt(af_ip_pair, domain, task)
    return _evaluate_securitytxt(result)


def _retrieve_securitytxt(af_ip_pair, hostname: str, task: SetupUnboundContext) -> SecuritytxtRetrieveResult:
    path = SECURITYTXT_EXPECTED_PATH
    found_host = None
    try:
        http_kwargs = {
            "hostname": hostname,
            "ip": af_ip_pair[1],
            "port": 443,
            "path": path,
        }
        response = http_get_ip(**http_kwargs)
        if response.status_code != 200:
            http_kwargs["path"] = SECURITYTXT_LEGACY_PATH
            response = http_get_ip(**http_kwargs)
        if response.history:
            found_host = urlparse(response.url).hostname
        else:
            found_host = hostname
        content = response_content_chunk(response, SECURITYTXT_MAX_LENGTH).decode("utf-8")
    except UnicodeDecodeError:
        return SecuritytxtRetrieveResult(
            found=True,
            content=None,
            url=f"https://{hostname}{path}",
            found_host=found_host,
            found_url=None,
            errors=[{"msgid": "utf8"}],
        )
    except requests.RequestException:
        return _evaluate_response(None, None, hostname, path, "", hostname, None)
    except StopIteration:  # 200 response with empty content
        content = ""
    return _evaluate_response(
        response.status_code,
        response.headers.get("Content-Type", ""),
        hostname,
        path,
        content,
        found_host,
        response.url,
    )


def _evaluate_response(
    status: Optional[int],
    content_type: Optional[str],
    domain: str,
    path: str,
    content: str,
    found_host: str,
    found_url: Optional[str],
) -> SecuritytxtRetrieveResult:
    errors = []
    media_type, charset = None, None
    if content_type:
        media_type, params = parse_header(content_type)
        charset = params.get("charset", "utf-8").lower()

    if not status or status == 404:
        errors.append(
            {
                "msgid": "no_security_txt_404",
            }
        )
    elif status != 200:
        errors.append(
            {
                "msgid": "no_security_txt_other",
                "context": {"status_code": status},
            }
        )
    elif not content_type:
        errors.append({"msgid": "no_content_type"})
        # In case of missing or not text/plain type, there is a fair chance this
        # is an HTML page, for which there is no point to try to parse the content
        # as it will flood the user with useless errors. Therefore, we ignore content
        # in this scenario.
        content = None
    elif media_type.lower() != "text/plain":
        errors.append({"msgid": "invalid_media"})
        content = None
    elif charset != "utf-8" and charset != "csutf8":
        errors.append({"msgid": "invalid_charset"})

    if status == 200 and path != SECURITYTXT_EXPECTED_PATH:
        errors.append({"msgid": "location"})

    return SecuritytxtRetrieveResult(
        found=status == 200,
        content=content,
        url=f"https://{domain}{path}",
        found_host=found_host,
        found_url=found_url,
        errors=errors,
    )


def _evaluate_securitytxt(result: SecuritytxtRetrieveResult):
    def parser_format(parser_messages):
        return [{"msgid": f"{m['code']}", "context": {"line_no": m.get("line")}} for m in parser_messages]

    if not result.found or not result.content:
        return {
            "securitytxt_enabled": False,
            "securitytxt_score": scoring.WEB_APPSECPRIV_SECURITYTXT_BAD,
            "securitytxt_found_host": result.found_host,
            "securitytxt_errors": result.errors,
            "securitytxt_recommendations": [],
        }

    parser = sectxt.Parser(result.content, urls=result.found_url)

    errors = result.errors + parser_format(parser.errors)
    score = scoring.WEB_APPSECPRIV_SECURITYTXT_BAD if errors else scoring.WEB_APPSECPRIV_SECURITYTXT_GOOD

    return {
        "securitytxt_enabled": True,
        "securitytxt_score": score,
        "securitytxt_found_host": result.found_host,
        "securitytxt_errors": errors,
        "securitytxt_recommendations": parser_format(parser.recommendations),
    }
