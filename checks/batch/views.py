# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import json

from django.http import HttpResponseRedirect
from django.views.decorators.http import require_http_methods

from .util import check_valid_user, batch_async_generate_results
from .util import get_site_url, get_report_metadata, list_requests
from .util import register_request, get_request, patch_request
from .responses import api_response, unknown_request_response
from .responses import invalid_url_response, bad_client_request_response
from .responses import general_server_error
from .. import simple_cache_page
from ..models import BatchRequest
from ..models import BatchRequestStatus


@require_http_methods(['GET', 'POST'])
@check_valid_user
def endpoint_requests(request, *args, **kwargs):
    if request.method == "GET":
        return list_requests(request, *args, **kwargs)
    else:
        return register_request(request, *args, **kwargs)


@require_http_methods(['GET', 'PATCH'])
@check_valid_user
def endpoint_request(request, request_id, *args, **kwargs):
    user = kwargs['batch_user']
    try:
        batch_request = BatchRequest.objects.get(
            user=user, request_id=request_id)
    except BatchRequest.DoesNotExist:
        return unknown_request_response()

    if request.method == "GET":
        return get_request(request, batch_request, user)
    elif request.method == "PATCH":
        return patch_request(request, batch_request)


@require_http_methods(['GET'])
@check_valid_user
def endpoint_results(request, request_id, *args, **kwargs):
    user = kwargs['batch_user']
    try:
        batch_request = BatchRequest.objects.get(
            user=user, request_id=request_id)
    except BatchRequest.DoesNotExist:
        return unknown_request_response()

    if batch_request.status != BatchRequestStatus.done:
        return bad_client_request_response("The request is not yet `done`.")
    else:
        if not batch_request.has_report_file():
            batch_async_generate_results.delay(
                user=user,
                batch_request=batch_request,
                site_url=get_site_url(request))
            return bad_client_request_response(
                "The request is not yet `done`.")

        else:
            try:
                batch_request.report_file.open('r')
                data = json.load(batch_request.report_file)
            except Exception:
                return general_server_error("Report could not be generated.")
            finally:
                batch_request.report_file.close()
            return api_response(data)


@require_http_methods(['GET'])
@check_valid_user
def endpoint_metadata_report(request, *args, **kwargs):
    return api_response({"report": get_report_metadata()})


@check_valid_user
def documentation(request, *args, **kwargs):
    return HttpResponseRedirect(
        'https://github.com/NLnetLabs/Internet.nl/blob/master/'
        'documentation/batch_http_api.md')


@check_valid_user
def old_url(request, *args, **kwargs):
    return invalid_url_response()
