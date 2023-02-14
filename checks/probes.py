# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.conf import settings
from django.utils.translation import ugettext as _

from checks import categories
from checks.categories import MailTlsStarttlsExists, WebTlsHttpsExists
from checks.models import (
    ConnectionTest,
    DomainTestDnssec,
    DomainTestIpv6,
    MailTestAuth,
    MailTestDnssec,
    MailTestIpv6,
    MailTestTls,
    MailTestRpki,
    WebTestRpki,
    WebTestAppsecpriv,
    WebTestTls,
)
from checks.scoring import (
    STATUS_ERROR,
    STATUS_FAIL,
    STATUS_GOOD_NOT_TESTED,
    STATUS_INFO,
    STATUS_NOT_TESTED,
    STATUS_NOTICE,
    STATUS_SUCCESS,
    STATUSES_HTML_CSS_TEXT_MAP,
)
from checks.tasks import dispatcher
from checks.tasks.dispatcher import ProbeTaskResult

if settings.INTERNET_NL_CHECK_SUPPORT_IPV6:
    from checks.tasks import ipv6

if settings.INTERNET_NL_CHECK_SUPPORT_DNSSEC:
    from checks.tasks import dnssec

if settings.INTERNET_NL_CHECK_SUPPORT_MAIL:
    from checks.tasks import mail

if settings.INTERNET_NL_CHECK_SUPPORT_TLS:
    from checks.tasks import tls

if settings.INTERNET_NL_CHECK_SUPPORT_APPSECPRIV:
    from checks.tasks import appsecpriv

if settings.INTERNET_NL_CHECK_SUPPORT_RPKI:
    from checks.tasks import rpki


class ProbeSet:
    def __init__(self):
        """
        A set that contains all the necessary probes for a test.

        """
        self.probes = {}
        self.order = {}

    def add(self, probe, order):
        """
        Add probe to the set.

        """
        self.probes[probe.name] = probe
        self.order[order] = probe.name

    def __getitem__(self, probename):
        return self.probes[probename]

    def __iter__(self):
        for probename in self.probes:
            yield self.probes[probename]

    def getset(self):
        """
        Get ordered set, usefull for passing to template.

        """
        return [self.probes[self.order[o]] for o in sorted(self.order)]

    def get_probe_reports(self, report):
        """
        Return all the reports from all the probes that were available during
        the test.

        """
        probe_reports = []
        for probe in self.getset():
            model = getattr(report, probe.name)
            # Check that the probe was available for the stored report.
            if model:
                probe_report = probe.rated_results_by_model(model)
                probe_reports.append(probe_report)
        return probe_reports

    def count_probe_reports_score(self, probe_reports):
        """
        Get final percentage score from the probes' reports.

        Only categories that consist of at least one mandatory test
        (maxscore > 0) are included in the score calculation.

        """
        scores = []
        for pr in probe_reports:
            total_score = pr["totalscore"]
            max_score = pr["maxscore"]
            if max_score == 0:
                continue
            scores.append(total_score)

        return max(min(int(sum(scores) / len(scores)), 100), 0)


class Probe:
    def __init__(
        self,
        name,
        prefix,
        category=None,
        nourl=False,
        model=None,
        taskset=None,
        reportfield="report",
        scorename=None,
        maxscore=None,
    ):
        """
        Each category has a probe, a probe is the unit that can be passed to
        templates to start test, can start celery tasks, can get task results
        from celery and model.

        """
        self.name = name
        self.prefix = prefix
        self.scorename = scorename
        self.title = f"test {prefix}{name} title"
        self.description = ""
        if not nourl:
            self.probesurl = f"/{prefix}/probes/"
            self.testurl = f"/{prefix}/{name}/"

        self.taskset = taskset
        self.model = model
        self.reportfield = reportfield

        self.category = category
        if not category:
            # For the connection test only.
            self.maxscore = maxscore

    def _verdict(self, report):
        """
        Return the verdict for the category. Also return if *all* the subtests
        in this category were not tested.

        The verdict is based on the requirement level of the failed tests:
        - If all tests passed -> passed
        - If at least one test failed:
          - If it was a mandatory test -> failed
          - If it was an optional test and no mandatory tests are in this
            category -> warning
          - If it was an informational test and no mandatory nor optional tests
            are in this category -> info

        """
        count = {
            STATUS_SUCCESS: 0,
            STATUS_FAIL: 0,
            STATUS_ERROR: 0,
            STATUS_INFO: 0,
            STATUS_NOTICE: 0,
            STATUS_GOOD_NOT_TESTED: 0,
            STATUS_NOT_TESTED: 0,
        }
        not_tested = False
        has_mandatory = False
        has_optional = False
        for name, subtest in report.items():
            status = report[name]["status"]
            worst_status = report[name]["worst_status"]
            if worst_status == STATUS_FAIL:
                has_mandatory = True
            elif worst_status == STATUS_NOTICE:
                has_optional = True
            count[status] += 1
            if status in (STATUS_GOOD_NOT_TESTED, STATUS_NOT_TESTED):
                count[worst_status] += 1

        if count[STATUS_ERROR]:
            verdict = STATUSES_HTML_CSS_TEXT_MAP[STATUS_ERROR]
        elif count[STATUS_FAIL]:
            verdict = STATUSES_HTML_CSS_TEXT_MAP[STATUS_FAIL]
        elif count[STATUS_NOTICE] and not has_mandatory:
            verdict = STATUSES_HTML_CSS_TEXT_MAP[STATUS_NOTICE]
        elif count[STATUS_INFO] and not (has_mandatory or has_optional):
            verdict = STATUSES_HTML_CSS_TEXT_MAP[STATUS_INFO]
        else:
            verdict = STATUSES_HTML_CSS_TEXT_MAP[STATUS_SUCCESS]

        if len(report) == count[STATUS_NOT_TESTED]:
            not_tested = True

        # TLS is kind of an anomally as the first test has no score but
        # reflects the overall verdict of the category if it is the only
        # result present.
        if self.name == "tls":
            if len(report) - 1 <= count[STATUS_NOT_TESTED]:
                if self.prefix == "mail":
                    status = report["starttls_exists"]["status"]
                else:
                    status = report["https_exists"]["status"]

                # Currently we don't have NOT_TESTED for a whole category.
                if status == STATUS_NOT_TESTED:
                    status = STATUS_INFO

                verdict = STATUSES_HTML_CSS_TEXT_MAP[status]

        return verdict, not_tested

    def _verdict_connection(self, total_score):
        """
        Verdict for the connection test.

        It can be either `passed` or `failed` based on the total score of the
        category.

        """
        if total_score >= 100:
            verdict = STATUSES_HTML_CSS_TEXT_MAP[STATUS_SUCCESS]
        else:
            verdict = STATUSES_HTML_CSS_TEXT_MAP[STATUS_FAIL]
        return verdict

    def raw_results(self, dname, remote_addr) -> ProbeTaskResult:
        """
        Get results from the taskset.
        Start the taskset if not running or cached.
        """
        return dispatcher.check_results(dname, self.taskset, remote_addr, get_results=True)

    def check_results(self, dname, remote_addr) -> ProbeTaskResult:
        """
        Get just the status of the taskset.
        Start the taskset if not running or cached.
        """
        return dispatcher.check_results(dname, self.taskset, remote_addr, get_results=False)

    def rated_results(self, dname):
        """
        Get results from model.

        """
        filter_value = dict(domain=dname)
        if self.model is DomainTestDnssec:
            filter_value["maildomain_id"] = None
        modelobj = self.model.objects.filter(**filter_value).order_by("-id")[0]
        return self.rated_results_by_model(modelobj)

    def rated_results_by_model(self, modelobj):
        if not modelobj:
            return None

        max_score, total_score, verdict, text_verdict = self.get_scores_and_verdict(modelobj)
        summary = _(f"test {self.prefix}{self.name} {text_verdict} summary")
        description = _(f"test {self.prefix}{self.name} {text_verdict} description")

        return dict(
            done=True,
            name=f"{self.prefix}{self.name}",
            title=self.title,
            details_set=modelobj.details_set(self),
            totalscore=total_score,
            maxscore=max_score,
            verdict=verdict,
            icon=verdict,
            summary=summary,
            description=description,
        )

    def get_scores_and_verdict(self, modelobj):
        """
        Return max_score, total_score and verdict for this model.

        """
        if not modelobj:
            return None

        report = getattr(modelobj, self.reportfield)
        if self.prefix == "conn":
            total_score_arg = self
            maxscore = self.maxscore
        else:
            category = self.category()
            category.update_from_report(report)
            total_score_arg = category.score_fields
            maxscore = category.max_score

        max_score = self.get_max_score(modelobj, maxscore)
        if max_score == 0:
            total_score = 0
            modelobj.totalscore(total_score_arg)
        else:
            total_score = int(100.0 / max_score * modelobj.totalscore(total_score_arg))

        if self.prefix == "conn":
            verdict = self._verdict_connection(total_score)
        else:
            verdict, not_tested = self._verdict(report)

        text_verdict = self.get_text_verdict(verdict, modelobj, report)
        return max_score, total_score, verdict, text_verdict

    def get_text_verdict(self, verdict, modelobj, report):
        """
        Returns the verdict that should be used for translations. It can
        override the default verdict if a rule matches here. That would
        influence the text of the category in case we need to show something
        other than the generic texts for failures.

        """
        if isinstance(modelobj, WebTestTls):
            test_instance = WebTlsHttpsExists()
            test_instance.result_unreachable()
            if report[test_instance.name]["verdict"] == test_instance.verdict:
                # test sitetls unreachable description
                # test sitetls unreachable summary
                return "unreachable"
        elif isinstance(modelobj, MailTestTls):
            test_instance = MailTlsStarttlsExists()
            test_instance.result_unreachable()
            if report[test_instance.name]["verdict"] == test_instance.verdict:
                # test mailtls unreachable description
                # test mailtls unreachable summary
                return "unreachable"
            test_instance.result_could_not_test()
            if report[test_instance.name]["verdict"] == test_instance.verdict:
                # test mailtls untestable description
                # test mailtls untestable summary
                return "untestable"
            test_instance.result_no_mailservers()
            if report[test_instance.name]["verdict"] == test_instance.verdict:
                # test mailtls no-mx description
                # test mailtls no-mx summary
                return "no-mx"
            test_instance.result_null_mx()
            if report[test_instance.name]["verdict"] == test_instance.verdict:
                # test mailtls null-mx description
                # test mailtls null-mx summary
                return "null-mx"
            test_instance.result_no_null_mx()
            if report[test_instance.name]["verdict"] == test_instance.verdict:
                # test mailtls no-null-mx description
                # test mailtls no-null-mx summary
                return "no-null-mx"
            test_instance.result_null_mx_with_other_mx()
            if report[test_instance.name]["verdict"] == test_instance.verdict:
                # test mailtls null-mx-with-other-mx description
                # test mailtls null-mx-with-other-mx summary
                return "null-mx-with-other-mx"
            test_instance.result_null_mx_without_a_aaaa()
            if report[test_instance.name]["verdict"] == test_instance.verdict:
                # test mailtls null-mx-without-a-aaaa description
                # test mailtls null-mx-without-a-aaaa summary
                return "null-mx-without-a-aaaa"
        return verdict

    def get_max_score(self, modelobj, maxscore):
        """
        Return the max score for this probe.

        .. note:: Future requests (permalinks) for this value will return the
                  value used during the test.

        """
        if type(modelobj) is ConnectionTest:
            # .. note:: ConenctionTest does not have dedicated score fields yet
            if self.scorename == "ipv6":
                if modelobj.score_ipv6_max is None:
                    modelobj.score_ipv6_max = maxscore
                    modelobj.save()
                max_score = modelobj.score_ipv6_max
            else:
                if modelobj.score_dnssec_max is None:
                    modelobj.score_dnssec_max = maxscore
                    modelobj.save()
                max_score = modelobj.score_dnssec_max
        else:
            if modelobj.max_score is None:
                # Save current max score to modelobj.
                modelobj.max_score = maxscore
                modelobj.save()
            max_score = modelobj.max_score

        return max_score


if settings.INTERNET_NL_CHECK_SUPPORT_IPV6:
    web_probe_ipv6 = Probe(
        "ipv6", "site", model=DomainTestIpv6, category=categories.WebIpv6, taskset=ipv6.web_registered
    )

if settings.INTERNET_NL_CHECK_SUPPORT_DNSSEC:
    web_probe_dnssec = Probe(
        "dnssec", "site", model=DomainTestDnssec, category=categories.WebDnssec, taskset=dnssec.web_registered
    )

if settings.INTERNET_NL_CHECK_SUPPORT_TLS:
    web_probe_tls = Probe("tls", "site", model=WebTestTls, category=categories.WebTls, taskset=tls.web_registered)

if settings.INTERNET_NL_CHECK_SUPPORT_APPSECPRIV:
    web_probe_appsecpriv = Probe(
        "appsecpriv",
        "site",
        model=WebTestAppsecpriv,
        category=categories.WebAppsecpriv,
        taskset=appsecpriv.web_registered,
    )

if settings.INTERNET_NL_CHECK_SUPPORT_RPKI:
    web_probe_rpki = Probe(
        "rpki",
        "site",
        model=WebTestRpki,
        category=categories.WebRpki,
        taskset=rpki.web_registered,
    )

if settings.INTERNET_NL_CHECK_SUPPORT_IPV6:
    batch_web_probe_ipv6 = Probe(
        "ipv6", "site", model=DomainTestIpv6, category=categories.WebIpv6, taskset=ipv6.batch_web_registered
    )

if settings.INTERNET_NL_CHECK_SUPPORT_DNSSEC:
    batch_web_probe_dnssec = Probe(
        "dnssec", "site", model=DomainTestDnssec, category=categories.WebDnssec, taskset=dnssec.batch_web_registered
    )

if settings.INTERNET_NL_CHECK_SUPPORT_TLS:
    batch_web_probe_tls = Probe(
        "tls", "site", model=WebTestTls, category=categories.WebTls, taskset=tls.batch_web_registered
    )

if settings.INTERNET_NL_CHECK_SUPPORT_APPSECPRIV:
    batch_web_probe_appsecpriv = Probe(
        "appsecpriv",
        "site",
        model=WebTestAppsecpriv,
        category=categories.WebAppsecpriv,
        taskset=appsecpriv.batch_web_registered,
    )

if settings.INTERNET_NL_CHECK_SUPPORT_RPKI:
    batch_web_probe_rpki = Probe(
        "rpki",
        "site",
        model=WebTestRpki,
        category=categories.WebRpki,
        taskset=rpki.batch_web_registered,
    )

webprobes = ProbeSet()
counter = -1
if settings.INTERNET_NL_CHECK_SUPPORT_IPV6:
    counter += 1
    webprobes.add(web_probe_ipv6, counter)
if settings.INTERNET_NL_CHECK_SUPPORT_DNSSEC:
    counter += 1
    webprobes.add(web_probe_dnssec, counter)
if settings.INTERNET_NL_CHECK_SUPPORT_TLS:
    counter += 1
    webprobes.add(web_probe_tls, counter)
if settings.INTERNET_NL_CHECK_SUPPORT_APPSECPRIV:
    counter += 1
    webprobes.add(web_probe_appsecpriv, counter)
if settings.INTERNET_NL_CHECK_SUPPORT_RPKI:
    counter += 1
    webprobes.add(web_probe_rpki, counter)

counter = -1
batch_webprobes = ProbeSet()
if settings.INTERNET_NL_CHECK_SUPPORT_IPV6:
    counter += 1
    batch_webprobes.add(batch_web_probe_ipv6, counter)
if settings.INTERNET_NL_CHECK_SUPPORT_DNSSEC:
    counter += 1
    batch_webprobes.add(batch_web_probe_dnssec, counter)
if settings.INTERNET_NL_CHECK_SUPPORT_TLS:
    counter += 1
    batch_webprobes.add(batch_web_probe_tls, counter)
if settings.INTERNET_NL_CHECK_SUPPORT_APPSECPRIV:
    counter += 1
    batch_webprobes.add(batch_web_probe_appsecpriv, counter)
if settings.INTERNET_NL_CHECK_SUPPORT_RPKI:
    counter += 1
    batch_webprobes.add(batch_web_probe_rpki, counter)

if settings.INTERNET_NL_CHECK_SUPPORT_IPV6:
    mail_probe_ipv6 = Probe(
        "ipv6", "mail", model=MailTestIpv6, category=categories.MailIpv6, taskset=ipv6.mail_registered
    )

if settings.INTERNET_NL_CHECK_SUPPORT_DNSSEC:
    mail_probe_dnssec = Probe(
        "dnssec", "mail", model=MailTestDnssec, category=categories.MailDnssec, taskset=dnssec.mail_registered
    )

if settings.INTERNET_NL_CHECK_SUPPORT_MAIL:
    mail_probe_auth = Probe(
        "auth", "mail", model=MailTestAuth, category=categories.MailAuth, taskset=mail.mail_registered
    )

if settings.INTERNET_NL_CHECK_SUPPORT_TLS:
    mail_probe_tls = Probe("tls", "mail", model=MailTestTls, category=categories.MailTls, taskset=tls.mail_registered)

if settings.INTERNET_NL_CHECK_SUPPORT_RPKI:
    mail_probe_rpki = Probe(
        "rpki", "mail", model=MailTestRpki, category=categories.MailRpki, taskset=rpki.mail_registered
    )

if settings.INTERNET_NL_CHECK_SUPPORT_IPV6:
    batch_mail_probe_ipv6 = Probe(
        "ipv6", "mail", model=MailTestIpv6, category=categories.MailIpv6, taskset=ipv6.batch_mail_registered
    )

if settings.INTERNET_NL_CHECK_SUPPORT_DNSSEC:
    batch_mail_probe_dnssec = Probe(
        "dnssec", "mail", model=MailTestDnssec, category=categories.MailDnssec, taskset=dnssec.batch_mail_registered
    )

if settings.INTERNET_NL_CHECK_SUPPORT_MAIL:
    batch_mail_probe_auth = Probe(
        "auth", "mail", model=MailTestAuth, category=categories.MailAuth, taskset=mail.batch_mail_registered
    )

if settings.INTERNET_NL_CHECK_SUPPORT_TLS:
    batch_mail_probe_tls = Probe(
        "tls", "mail", model=MailTestTls, category=categories.MailTls, taskset=tls.batch_mail_registered
    )

if settings.INTERNET_NL_CHECK_SUPPORT_RPKI:
    batch_mail_probe_rpki = Probe(
        "rpki", "mail", model=MailTestRpki, category=categories.MailRpki, taskset=rpki.batch_mail_registered
    )


mailprobes = ProbeSet()
counter = -1
if settings.INTERNET_NL_CHECK_SUPPORT_IPV6:
    counter += 1
    mailprobes.add(mail_probe_ipv6, counter)
if settings.INTERNET_NL_CHECK_SUPPORT_DNSSEC:
    counter += 1
    mailprobes.add(mail_probe_dnssec, counter)
if settings.INTERNET_NL_CHECK_SUPPORT_MAIL:
    counter += 1
    mailprobes.add(mail_probe_auth, counter)
if settings.INTERNET_NL_CHECK_SUPPORT_TLS:
    counter += 1
    mailprobes.add(mail_probe_tls, counter)
if settings.INTERNET_NL_CHECK_SUPPORT_RPKI:
    counter += 1
    mailprobes.add(mail_probe_rpki, counter)

batch_mailprobes = ProbeSet()
counter = -1
if settings.INTERNET_NL_CHECK_SUPPORT_IPV6:
    counter += 1
    batch_mailprobes.add(batch_mail_probe_ipv6, counter)
if settings.INTERNET_NL_CHECK_SUPPORT_DNSSEC:
    counter += 1
    batch_mailprobes.add(batch_mail_probe_dnssec, counter)
if settings.INTERNET_NL_CHECK_SUPPORT_MAIL:
    counter += 1
    batch_mailprobes.add(batch_mail_probe_auth, counter)
if settings.INTERNET_NL_CHECK_SUPPORT_TLS:
    counter += 1
    batch_mailprobes.add(batch_mail_probe_tls, counter)
if settings.INTERNET_NL_CHECK_SUPPORT_RPKI:
    counter += 1
    batch_mailprobes.add(batch_mail_probe_rpki, counter)
