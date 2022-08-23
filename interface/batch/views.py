# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import json
from json import JSONDecodeError

from django.http import HttpResponseRedirect
from django.views.decorators.http import require_http_methods

from checks.models import BatchRequest, BatchRequestStatus
from interface.batch.responses import (
    api_response,
    bad_client_request_response,
    general_server_error_response,
    invalid_url_response,
    unknown_request_response,
)
from interface.batch.util import (
    APIMetadata,
    batch_async_generate_results,
    check_valid_user,
    get_json_data_from_request,
    get_request,
    get_site_url,
    list_requests,
    patch_request,
    register_request,
)
from internetnl import log


@require_http_methods(["GET", "POST"])
@check_valid_user
def endpoint_requests(request, *args, **kwargs):
    if request.method == "GET":
        return list_requests(request, *args, **kwargs)
    else:
        exception_data, data = get_json_data_from_request(request)
        if isinstance(exception_data, JSONDecodeError):
            # todo: provide better feedback than just missing fields, this is mixing up messages:
            return bad_client_request_response("Problem parsing json. Did you supply a 'type' and 'domains'?")
        if exception_data:
            log.exception(exception_data)
            return general_server_error_response("Problem parsing domains.")
        return register_request(data, *args, **kwargs)


@require_http_methods(["GET", "PATCH"])
@check_valid_user
def endpoint_request(request, request_id, *args, **kwargs):
    user = kwargs["batch_user"]
    try:
        batch_request = BatchRequest.objects.get(user=user, request_id=request_id)
    except BatchRequest.DoesNotExist:
        return unknown_request_response()

    if request.method == "GET":
        return get_request(request, batch_request, user)
    elif request.method == "PATCH":
        return patch_request(request, batch_request)


def results(request, request_id, *args, technical=False, **kwargs):
    user = kwargs["batch_user"]
    try:
        batch_request = BatchRequest.objects.get(user=user, request_id=request_id)
    except BatchRequest.DoesNotExist:
        return unknown_request_response()

    if batch_request.status != BatchRequestStatus.done:
        return bad_client_request_response("The request is not yet `done`.")
    else:
        if not batch_request.has_report_file():
            batch_async_generate_results.delay(user=user, batch_request=batch_request, site_url=get_site_url(request))
            return bad_client_request_response("The request is not yet `done`.")

        else:
            report_file = batch_request.get_report_file(technical)
            try:
                report_file.open("r")
                data = json.load(report_file)
            except Exception:
                return general_server_error_response("Report could not be generated.")
            finally:
                report_file.close()
            return api_response(data)


@require_http_methods(["GET"])
@check_valid_user
def endpoint_results(request, request_id, *args, **kwargs):
    return results(request, request_id, *args, **kwargs)


@require_http_methods(["GET"])
@check_valid_user
def endpoint_results_technical(request, request_id, *args, **kwargs):
    return results(request, request_id, *args, technical=True, **kwargs)


@require_http_methods(["GET"])
@check_valid_user
def endpoint_metadata_report(request, *args, **kwargs):
    return api_response({"report": APIMetadata.get_report_metadata()})


@require_http_methods(["GET"])
def documentation(request, *args, **kwargs):
    return HttpResponseRedirect("/static/openapi.yaml")


@check_valid_user
def old_url(request, *args, **kwargs):
    return invalid_url_response()
