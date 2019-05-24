# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import os
import random
import json

from django.core.urlresolvers import reverse
from django.http import JsonResponse, HttpResponseRedirect
from django.views.decorators.http import require_http_methods

from .util import check_valid_user, batch_async_generate_results
from .util import get_site_url
from .. import simple_cache_page
from ..batch import BATCH_API_VERSION
from ..batch.util import batch_async_register
from ..models import BatchRequest
from ..models import BatchRequestType
from ..models import BatchRequestStatus
from ..models import BatchDomain, BatchDomainStatus


@check_valid_user
def documentation(request, *args, **kwargs):
    return HttpResponseRedirect(
        'https://github.com/NLnetLabs/Internet.nl/blob/master/'
        'documentation/batch_http_api.md')


@require_http_methods(['POST'])
@check_valid_user
def register_web_test(request, *args, **kwargs):
    return register_batch_request(
        request, kwargs['batch_user'], BatchRequestType.web)


@require_http_methods(['POST'])
@check_valid_user
def register_mail_test(request, *args, **kwargs):
    return register_batch_request(
        request, kwargs['batch_user'], BatchRequestType.mail)


def register_batch_request(request, user, test_type):
    try:
        json_req = json.loads(request.body.decode('utf-8'))
        domains = json_req.get('domains')
        name = json_req.get('name', 'no-name')
        if not domains:
            raise Exception("No domains")
    except Exception:
        return JsonResponse(
            dict(
                success=False,
                message="Problem parsing domains",
                data={}))

    batch_request = BatchRequest(user=user, name=name, type=test_type)
    batch_request.save()

    # Sort domains and shuffle them. Cheap countermeasure to avoid testing the
    # same end-systems simultaneously.
    domains = sorted(set(domains))
    random.shuffle(domains)
    batch_async_register.delay(
        batch_request=batch_request, test_type=test_type, domains=domains)

    resp = {
        "results": "{}{}".format(
            get_site_url(request),
            reverse('batch_results', args=(batch_request.request_id,)))}

    return JsonResponse(
        dict(
            success=True,
            message="OK",
            data=resp))


@require_http_methods(['GET'])
@check_valid_user
@simple_cache_page
def get_results(request, testid, *args, **kwargs):
    user = kwargs['batch_user']
    try:
        batch_request = BatchRequest.objects.get(user=user, request_id=testid)
    except BatchRequest.DoesNotExist:
        return JsonResponse(
            dict(
                success=False,
                message="Unknown batch request",
                data={}))

    if batch_request.status in (BatchRequestStatus.live,
                                BatchRequestStatus.running):
        success = False
        message = "Batch request is running"
        # total_domains = BatchDomain.objects.filter(batch_request=batch_request).count()
        # finished_domains = BatchDomain.objects.filter(
        #         batch_request=batch_request,
        #         status__in=(BatchDomainStatus.done, BatchDomainStatus.error)).count()
        resp = {
            "results": "{}{}".format(
                get_site_url(request),
                reverse('batch_results', args=(batch_request.request_id,)))
            # "progress": "{}/{}".format(finished_domains, total_domains)
        }

    elif batch_request.status == BatchRequestStatus.registering:
        success = False
        message = "Batch request is registering domains"
        resp = {
            "results": "{}{}".format(
                get_site_url(request),
                reverse('batch_results', args=(batch_request.request_id,)))}

    elif batch_request.status == BatchRequestStatus.cancelled:
        success = False
        message = "Batch request was cancelled by user"
        resp = {}

    elif batch_request.status == BatchRequestStatus.error:
        success = False
        message = "Error while registering the domains"
        resp = {}

    else:
        if (batch_request.report_file
                and os.path.isfile(batch_request.report_file.path)):
            try:
                batch_request.report_file.open('r')
                resp = json.load(batch_request.report_file)
                success = True
                message = "OK"
            except Exception:
                success = False
                message = "Results could not be generated"
                resp = {}
            finally:
                batch_request.report_file.close()
        else:
            batch_async_generate_results.delay(
                user=user,
                batch_request=batch_request,
                site_url=get_site_url(request))
            success = False
            message = "Report is being generated"
            resp = {
                "results": "{}{}".format(
                    get_site_url(request),
                    reverse(
                        'batch_results', args=(batch_request.request_id,)))}

    return JsonResponse(
        dict(
            success=success,
            message=message,
            data=resp))


@require_http_methods(['GET'])
@check_valid_user
def list_tests(request, *args, **kwargs):
    user = kwargs['batch_user']
    try:
        limit = int(request.GET.get('limit'))
    except TypeError:
        limit = None
    batch_requests = BatchRequest.objects.filter(user=user).order_by('-id')[:limit]
    batch_info = []
    for batch_request in batch_requests:
        total_domains = BatchDomain.objects.filter(
            batch_request=batch_request).count()
        finished_domains = BatchDomain.objects.filter(
            batch_request=batch_request,
            status__in=(BatchDomainStatus.done,
                        BatchDomainStatus.error)).count()
        finished_date = batch_request.finished_date
        if finished_date:
            finished_date = finished_date.isoformat()

        batch_info.append(
            dict(
                name=batch_request.name,
                submit_date=batch_request.submit_date.isoformat(),
                finished_date=finished_date,
                type=batch_request.type.label,
                status=batch_request.status.label,
                request_id=batch_request.request_id,
                results="{}{}".format(
                    get_site_url(request),
                    reverse(
                        'batch_results', args=(batch_request.request_id, ))),
                progress="{}/{}".format(finished_domains, total_domains),
                num_domains=total_domains))

    resp = dict(batch_requests=batch_info)
    return JsonResponse(
        dict(
            success=True,
            message="OK",
            data=resp))


@require_http_methods(['GET'])
@check_valid_user
def cancel_test(request, testid, *args, **kwargs):
    user = kwargs['batch_user']
    try:
        batch_request = BatchRequest.objects.get(user=user, request_id=testid)
    except BatchRequest.DoesNotExist:
        return JsonResponse(
            dict(
                success=False,
                message="Unknown batch request",
                data={}))

    batch_request.status = BatchRequestStatus.cancelled
    batch_request.save()
    BatchDomain.objects.filter(batch_request=batch_request).update(
       status=BatchDomainStatus.cancelled)
    return JsonResponse(
        dict(
            success=True,
            message="OK",
            data={}))


@check_valid_user
def old_url(request, *args, **kwargs):
    message = (
        "Make sure you are using a valid URL with the current batch API "
        "version ({}).".format(BATCH_API_VERSION))
    return JsonResponse(
        dict(
            success=False,
            message=message,
            data={}))
