# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import http.client
from cgi import parse_header
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict

import sectxt

from checks import scoring
from checks.tasks.tls_connection import http_fetch
from checks.tasks.tls_connection_exceptions import ConnectionHandshakeException, ConnectionSocketException, NoIpError

SECURITYTXT_LEGACY_PATH = "/security.txt"
SECURITYTXT_EXPECTED_PATH = "/.well-known/security.txt"
SECURITYTXT_MAX_LENGTH = 100 * 1024


@dataclass
class SecuritytxtRetrieveResult:
    found: bool
    content: Optional[str]
    url: str
    found_host: str
    errors: List[Dict[str, str]]


def securitytxt_check(af_ip_pair, domain, task):
    result = _retrieve_securitytxt(af_ip_pair, domain, task)
    return _evaluate_securitytxt(result)


def _retrieve_securitytxt(af_ip_pair, domain: str, task) -> SecuritytxtRetrieveResult:
    def retrieve_content(request_path) -> Tuple[Optional[int], str, Optional[str], List[str]]:
        try:
            conn, res, headers, visited_hosts = http_fetch(
                domain,
                af=af_ip_pair[0],
                path=request_path,
                port=443,
                task=task,
                needed_headers=["Content-Type"],
                ip_address=af_ip_pair[1],
                keep_conn_open=True,
                needed_headers_follow_redirect=True,
            )
            response_content = res.read(SECURITYTXT_MAX_LENGTH).decode("utf-8")
            conn.close()

            content_type = ""
            for header, value in headers[443]:
                if header == "Content-Type":
                    content_type = value.lower() if value else None

            return res.status, content_type, response_content, visited_hosts[443]
        except (OSError, http.client.HTTPException, NoIpError, ConnectionHandshakeException, ConnectionSocketException):
            return None, "", None, []

    path = SECURITYTXT_EXPECTED_PATH
    found_host = None
    try:
        status, content_type, content, visited_hosts = retrieve_content(path)
        if status != 200:
            path = SECURITYTXT_LEGACY_PATH
            status, content_type, content, visited_hosts = retrieve_content(path)
        if visited_hosts:
            found_host = visited_hosts[-1]
    except UnicodeDecodeError:
        return SecuritytxtRetrieveResult(
            found=True,
            content=None,
            url=f"https://{domain}{path}",
            found_host=found_host,
            errors=[{"msgid": "utf8"}],
        )
    return _evaluate_response(status, content_type, domain, path, content, found_host)


def _evaluate_response(
    status: int, content_type: Optional[str], domain: str, path: str, content: str, found_host: str
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

    # URL intentionally not passed as Canonical testing is out of scope at this time
    parser = sectxt.Parser(result.content)

    errors = result.errors + parser_format(parser.errors)
    score = scoring.WEB_APPSECPRIV_SECURITYTXT_BAD if errors else scoring.WEB_APPSECPRIV_SECURITYTXT_GOOD

    return {
        "securitytxt_enabled": True,
        "securitytxt_score": score,
        "securitytxt_found_host": result.found_host,
        "securitytxt_errors": errors,
        "securitytxt_recommendations": parser_format(parser.recommendations),
    }
