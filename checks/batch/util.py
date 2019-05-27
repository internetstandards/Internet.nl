# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import json
from functools import wraps
import os

from celery.five import monotonic
from contextlib import contextmanager
from django.conf import settings
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.core.urlresolvers import reverse
from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone

from . import BATCH_API_VERSION
from .custom_views import get_applicable_views, gather_views_results
from .custom_views import ForumStandaardisatieView
from .. import batch_shared_task, redis_id
from ..probes import batch_webprobes, batch_mailprobes
from ..models import BatchUser, BatchRequestType, BatchDomainStatus
from ..models import BatchCustomView, BatchWebTest, BatchMailTest
from ..models import BatchDomain, BatchRequestStatus
from ..views.shared import pretty_domain_name
from ..views.shared import get_valid_domain_web, get_valid_domain_mail


def get_site_url(request):
    """
    Compose the url that the user used to connect to the API.

    """
    if settings.get('DJANGO_IS_PROXIED'):
        scheme = 'https'
    else:
        scheme = request.scheme
    return "{}://{}".format(scheme, request.get_host())


def check_valid_user(function):
    """
    Custom decorator for batch views.
    Check if the authenticated user is a user in the batch database and make
    the record available in the decorated function.

    """
    @wraps(function)
    def wrap(request, *args, **kwargs):
        user = get_user_from_request(request)
        if not user:
            return JsonResponse(dict(
                success=False,
                message="Unknown user",
                data=[]))
        kwargs['batch_user'] = user
        return function(request, *args, **kwargs)

    return wrap


def get_user_from_request(request):
    """
    If the user that made the request is a legitimate batch user (exists in the
    DB) return the relevant user object from the DB.

    """
    user = None
    try:
        username = (
            request.META.get('REMOTE_USER')
            or request.META.get('HTTP_REMOTE_USER'))
        if not username:
            username = getattr(settings, 'BATCH_TEST_USER', None)
        user = BatchUser.objects.get(username=username)
    except BatchUser.DoesNotExist:
        pass
    return user


@contextmanager
def memcache_lock(lock_id, lock_duration=60*5):
    """
    Simple cache lock to keep celerybeat tasks from running before the previous
    execution has not finished yet.

    Also used for simple tasks that may be triggered more than one for the same
    task.

    .. note:: Mostly as documented in the celery documentation.

    """
    if lock_duration is not None:
        timeout_at = monotonic() + lock_duration - 3
    # cache.add fails if the key already exists
    status = cache.add(lock_id, True, lock_duration)
    try:
        yield status
    finally:
        # memcache delete is very slow, but we have to use it to take
        # advantage of using add() for atomic locking
        if lock_duration is None or (monotonic() < timeout_at and status):
            # don't release the lock if we exceeded the timeout
            # to lessen the chance of releasing an expired lock
            # owned by someone else
            # also don't release the lock if we didn't acquire it
            cache.delete(lock_id)


@batch_shared_task(bind=True, ignore_result=True)
def batch_async_generate_results(self, user, batch_request, site_url):
    """
    Generate the batch results and save to file.

    """
    lock_id_name = redis_id.batch_results_lock.id
    lock_ttl = redis_id.batch_results_lock.ttl

    def on_failure(exc, task_id, args, kwargs, einfo):
        """
        Custom on_failure function to delete state from cache.

        """
        user = kwargs['user']
        batch_request = kwargs['batch_request']
        lock_id = lock_id_name.format(
            user.username, batch_request.request_id)
        cache.delete(lock_id)

    self.on_failure = on_failure

    lock_id = lock_id_name.format(user.username, batch_request.request_id)
    batch_request.refresh_from_db()
    if not (batch_request.report_file
            and os.path.isfile(batch_request.report_file.path)):
        with memcache_lock(lock_id, lock_ttl) as acquired:
            if acquired:
                results = gather_batch_results(user, batch_request, site_url)
                save_batch_results_to_file(user, batch_request, results)


def gather_batch_results(user, batch_request, site_url):
    """
    Gather all the results for the batch request and return them in a
    dictionary that will be eventually converted to JSON for the API answer.

    """
    results = {
        'submission-date': batch_request.submit_date.isoformat(),
        'finished-date': batch_request.finished_date.isoformat(),
        'name': batch_request.name,
        'identifier': batch_request.request_id,
        'api-version': BATCH_API_VERSION
    }

    if batch_request.type is BatchRequestType.web:
        probes = batch_webprobes.getset()
        url_name = 'webtest_results'
        url_arg = ['site']
        related_testset = 'webtest'
    else:
        probes = batch_mailprobes.getset()
        url_name = 'mailtest_results'
        url_arg = []
        related_testset = 'mailtest'

    dom_results = []
    custom_views = get_applicable_views(user, batch_request)

    # Quering for the related rows upfront minimizes further DB queries and
    # gives ~33% boost to performance.
    related_fields = []
    for probe in probes:
        related_fields.append(
            '{}__report__{}'.format(related_testset, probe.name))

    batch_domains = batch_request.domains.all().select_related(*related_fields)
    for batch_domain in batch_domains:
        domain_name_idna = pretty_domain_name(batch_domain.domain)
        if batch_domain.status == BatchDomainStatus.error:
            dom_results.append(
                dict(domain=domain_name_idna, status="failed"))
            continue

        batch_test = batch_domain.get_batch_test()
        report = batch_test.report
        score = report.score

        args = url_arg + [batch_domain.domain, report.id]
        link = "{}{}".format(site_url, reverse(url_name, args=args))

        categories = []
        for probe in probes:
            category = probe.name
            model = getattr(report, probe.name)
            _, _, verdict = probe.get_scores_and_verdict(model)
            passed = False
            if verdict == 'passed':
                passed = True
            categories.append(dict(category=category, passed=passed))

        result = dict(
            domain=domain_name_idna,
            status="ok",
            score=score,
            link=link,
            categories=categories)

        views = gather_views_results(
            custom_views, batch_domain, batch_request.type)
        if views:
            views = sorted(views, key=lambda view: view['name'])
            result['views'] = views

        dom_results.append(result)

    results['domains'] = dom_results

    # Add a temporary identifier for the new custom view.
    # Will be replaced in a later release with a universal default output.
    if (len(custom_views) == 1
            and isinstance(custom_views[0], ForumStandaardisatieView)
            and custom_views[0].view_id):
        results['api-view-id'] = custom_views[0].view_id
    return results


def save_batch_results_to_file(user, batch_request, results):
    """
    Save results to file using the Django's ORM utilities.

    """
    filename = '{}-{}-{}.json'.format(
        user.username, batch_request.type.label, batch_request.id)
    batch_request.report_file.save(filename, ContentFile(json.dumps(results)))


@batch_shared_task(bind=True, ignore_result=True)
@transaction.atomic
def batch_async_register(self, batch_request, test_type, domains):
    """
    Register the submitted domains for future batch testing. Domains need to
    pass validity tests similar to vanilla internet.nl. Invalid domains are not
    registered.

    """
    def on_failure(exc, task_id, args, kwargs, einfo):
        """
        Custom on_failure function to record the error.

        """
        batch_request = kwargs['batch_request']
        batch_request.refresh_from_db()
        if batch_request.status != BatchRequestStatus.cancelled:
            batch_request.status = BatchRequestStatus.error
        batch_request.finished_date = timezone.now()
        batch_request.save()

    self.on_failure = on_failure

    if test_type is BatchRequestType.web:
        batch_test_model = BatchWebTest
        keys = ('domain', 'batch_request', 'webtest')
        get_valid_domain = get_valid_domain_web
    else:
        batch_test_model = BatchMailTest
        keys = ('domain', 'batch_request', 'mailtest')
        get_valid_domain = get_valid_domain_mail

    for domain in domains:
        # Ignore leading/trailing whitespace.
        domain = domain.strip()
        # Only register valid domain names like vanilla internet.nl
        domain = get_valid_domain(domain)
        if not domain:
            continue

        batch_test = batch_test_model()
        batch_test.save()
        values = (domain, batch_request, batch_test)
        batch_domain = BatchDomain(**{k: v for k, v in zip(keys, values)})
        batch_domain.save()

    batch_request.refresh_from_db()
    if batch_request.status != BatchRequestStatus.cancelled:
        batch_request.status = BatchRequestStatus.live
    batch_request.save()


@transaction.atomic
def delete_batch_request(batch_request):
    """
    Remove the batch request together with all the batch related tables'
    entries.

    .. note:: It DOES NOT remove any entries from the vanilla tables.

    """
    batch_domains = batch_request.domains.all()
    for batch_domain in batch_domains:
        batch_domain.get_batch_test().delete()
        batch_domain.delete()
    batch_request.delete()


def create_batch_user(username, name, organization, email):
    """
    Create a batch user in the DB.

    """
    user = BatchUser(
        username=username, name=name, organization=organization, email=email)
    user.save()
    return user


def create_custom_view(name, description, usernames=[]):
    """
    Create a custom view in the DB.

    """
    view = BatchCustomView(name=name, description=description)
    view.save()
    for user in BatchUser.objects.filter(username__in=usernames):
        user.custom_views.add(view)
    return view


def add_custom_view_to_user(view_name, username):
    """
    Add the mapping from user to custom view in the DB.

    """
    view = None
    user = None
    try:
        view = BatchCustomView.objects.get(name=view_name)
        user = BatchUser.objects.get(username=username)
    except BatchCustomView.DoesNotExist:
        return view, user

    user.custom_views.add(view)
    return view, user
