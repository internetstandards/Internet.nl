# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import logging
import re

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import DisallowedRedirect
from django.db import models, transaction
from django.db.models import Case, Count, F, Q, Value, When
from django.db.models.functions import Coalesce, Greatest
from django.db.models.lookups import GreaterThan
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.utils import translation
from django.utils.translation import gettext as _

from checks.models import ConnectionTest, DomainTestReport, Fame, MailTestReport
from interface import redis_id, simple_cache_page
from interface.views.shared import get_hof_manual, SafeHttpResponseRedirect

hof_champion = (
    Fame.objects.alias(
        timestamp=Greatest("site_report_timestamp", "mail_report_timestamp"),
        report_type=Case(
            When(GreaterThan(F("site_report_timestamp"), F("mail_report_timestamp")), then=Value("s")),
            default=Value("m"),
            output_field=models.CharField(max_length=1),
        ),
        report_id=Case(
            When(GreaterThan(F("site_report_timestamp"), F("mail_report_timestamp")), then="site_report_id"),
            default="mail_report_id",
        ),
    )
    .annotate(timestamp=F("timestamp"), report_type=F("report_type"), report_id=F("report_id"))
    .filter(Q(site_report_id__isnull=False) & Q(mail_report_id__isnull=False))
    .order_by("-timestamp")
)


def make_hof_champion_permalink(entry):
    return "/{report_type}/{domain}/{report_id}/".format(
        report_type="site" if entry.report_type == "s" else "mail", domain=entry.domain, report_id=entry.report_id
    )


def page404(request, exception):
    return render(
        request, "404.html", dict(pageclass="error404", pagetitle=_("page404 title"), pagemenu="home"), status=404
    )


@simple_cache_page
@transaction.atomic
def indexpage(request):
    if settings.INTERNETNL_BRANDING:
        articles = _("article .index").split()
    else:
        articles = _("article custom .index").split()
    articles = articles[0:6]
    statswebsite = DomainTestReport.objects.aggregate(n=Count("domain", distinct=True))["n"]
    statswebsitegood = Fame.objects.all().filter(Q(site_report_id__isnull=False)).count()
    statswebsitebad = statswebsite - statswebsitegood
    statsmail = MailTestReport.objects.aggregate(n=Count("domain", distinct=True))["n"]
    statsmailgood = Fame.objects.all().filter(Q(mail_report_id__isnull=False)).count()
    statsmailbad = statsmail - statsmailgood
    statsconnection = (
        ConnectionTest.objects.all()
        .filter(finished=True)
        .aggregate(n=Count(Coalesce("ipv4_addr", "ipv6_addr"), distinct=True))["n"]
    )
    statsconnectiongood = (
        ConnectionTest.objects.all()
        .filter(finished=True, score_dnssec=100, score_ipv6=100)
        .aggregate(n=Count(Coalesce("ipv4_addr", "ipv6_addr"), distinct=True))["n"]
    )
    statsconnectionbad = statsconnection - statsconnectiongood

    hof_count = Fame.objects.filter(Q(site_report_id__isnull=False) & Q(mail_report_id__isnull=False)).count()
    hof_entries = []
    hof_date = None
    for entry in hof_champion.only("domain").all()[:10]:
        if hof_date is None:
            hof_date = entry.timestamp
        hof_entries.append({"domain": entry.domain, "permalink": make_hof_champion_permalink(entry)})

    return render(
        request,
        "index.html",
        dict(
            pageclass="home",
            pagemenu="home",
            pagetitle=_("home pagetitle"),
            halloffame=hof_entries,
            count=hof_count,
            statswebsite=statswebsite,
            statswebsitegood=statswebsitegood,
            statswebsitebad=statswebsitebad,
            statsconnection=statsconnection,
            statsconnectiongood=statsconnectiongood,
            statsconnectionbad=statsconnectionbad,
            statsmail=statsmail,
            statsmailgood=statsmailgood,
            statsmailbad=statsmailbad,
            latest=hof_date,
            articles=articles,
        ),
    )


# URL: /clear/<dname>
def clear(request, dname):
    url = dname.lower()
    if url in settings.CACHE_RESET_ALLOWLIST:
        for test in [
            "dnssec",
            "mail_auth",
            "mail_dnssec",
            "mail_ipv6",
            "mail_rpki",
            "mail_tls",
            "web_appsecpriv",
            "web_ipv6",
            "web_rpki",
            "web_tls",
        ]:
            cache.delete(redis_id.dom_task.id.format(url, test))
        return HttpResponse("Domain name cleared from cache.")
    return HttpResponse("Permission denied to clear domain name from cache.")


def testconnectionpage(request):
    return render(request, "test-connection.html", dict(pagemenu="faqs", pagetitle=_("base test connection title")))


def testsitepage(request):
    return render(request, "test-site.html", dict(pagemenu="faqs", pagetitle=_("base test website title")))


def testmailpage(request):
    return render(request, "test-mail.html", dict(pagemenu="faqs", pagetitle=_("base test mail title")))


def disclosurepage(request):
    return render(request, "disclosure.html", dict(pagemenu="home", pagetitle=_("base disclosure")))


def copyrightpage(request):
    return render(request, "copyright.html", dict(pagemenu="home", pagetitle=_("base copyright")))


def privacypage(request):
    return render(request, "privacy.html", dict(pagemenu="home", pagetitle=_("base privacy")))


def aboutpage(request):
    return render(request, "about.html", dict(pagemenu="about", pageclass="contact", pagetitle=_("base about")))


def widgetsitepage(request):
    return render(request, "widget-site.html", dict(pagemenu="faqs", pageclass="faqs", pagetitle=_("base widget site")))


def widgetmailpage(request):
    return render(request, "widget-mail.html", dict(pagemenu="faqs", pageclass="faqs", pagetitle=_("base widget mail")))


def faqindexpage(request):
    return render(request, "faqindex.html", dict(pagemenu="faqs", pageclass="faqs", pagetitle=_("base faqs")))


def faqreport(request):
    return render(request, "faq-report.html", dict(pagemenu="faqs", pageclass="faqs", pagetitle=_("faqs report title")))


def faqbadges(request):
    return render(request, "faq-badges.html", dict(pagemenu="faqs", pageclass="faqs", pagetitle=_("faqs badges title")))


def faqarticlepage(request, subject):
    title = "faqs " + subject + " title"
    # If there is no such translated article give a 404.
    if _(title) == title:
        return page404(request, None)

    content = "faqs " + subject + " content"
    return render(
        request,
        "faqarticle.html",
        dict(pagemenu="faqs", pageclass="faqs", pagetitle=_(title), title=title, content=content),
    )


def accessibility(request):
    return render(request, "accessibility.html", dict(pagemenu="home", pagetitle=_("base accessibility")))


def blogindexpage(request):
    return redirect("/articles/")


def blogarticlepage(request, author, article):
    return redirect("/article/" + article)


def newsindexpage(request):
    return redirect("/article/")


def newsarticlepage(request, article):
    return redirect("/article/" + article)


def articlespage(request):
    if settings.INTERNETNL_BRANDING:
        articles = _("article .index").split()
    else:
        articles = _("article custom .index").split()
    article = articles[0]
    return redirect("/article/" + article)


def articleindexpage(request):
    if settings.INTERNETNL_BRANDING:
        articles = _("article .index").split()
    else:
        articles = _("article custom .index").split()
    if len(articles) < 1:
        articles = []
    return render(
        request,
        "articles.html",
        dict(pageclass="newsitem", pagetitle=_("base news"), pagemenu="news", articles=articles),
    )


def articlepage(request, article):
    title = "article " + article + " title"
    # If there is no such translated article give a 404.
    if _(title) == title:
        return page404(request, None)

    if settings.INTERNETNL_BRANDING:
        articles = _("article .index").split()
    else:
        articles = _("article custom .index").split()
    articles = articles[0:6]
    date = "article " + article + " date"
    lead = "article " + article + " lead"
    body = "article " + article + " body"
    author = _("article " + article + " author")
    if author == "article " + article + " author":
        author = ""
    return render(
        request,
        "article.html",
        dict(
            pageclass="newsitem",
            pagetitle=_(title),
            pagemenu="news",
            article=article,
            articles=articles,
            date=date,
            title=title,
            lead=lead,
            author=author,
            body=body,
        ),
    )


def _update_hof_with_manual(template_dict, current=None):
    # todo: inverse if statements to reduce indents.
    if hasattr(settings, "MANUAL_HOF") and settings.MANUAL_HOF:
        template_dict.update(
            dict(
                manuals=[
                    (k, f"manual halloffame {'translate_key' in v and v['translate_key'] or k} menu")
                    for k, v in settings.MANUAL_HOF.items()
                ]
            )
        )
        if current:
            if "icon_file" in settings.MANUAL_HOF[current]:
                icon_type = (
                    "translate_key" in settings.MANUAL_HOF[current]
                    and settings.MANUAL_HOF[current]["translate_key"]
                    or current
                )
                template_dict.update(
                    dict(
                        manual_icon=f"{settings.MANUAL_HOF[current]['icon_file']}",
                        manual_icon_alt=f"manual halloffame {icon_type} badge",
                    )
                )


@simple_cache_page
def hofchampionspage(request):
    hof_entries = []
    for entry in hof_champion.only("domain").iterator():
        hof_entries.append({"domain": entry.domain, "permalink": make_hof_champion_permalink(entry)})

    template_dict = dict(
        pageclass="hall-of-fame",
        pagetitle=_("base halloffame champions"),
        pagemenu="halloffame",
        hof_title="halloffame champions title",
        cpage="champions",
        hof_text="halloffame champions text",
        hof_subtitle="halloffame champions subtitle",
        count=len(hof_entries),
        halloffame=hof_entries,
    )
    _update_hof_with_manual(template_dict)
    return render(request, "halloffame.html", template_dict)


@simple_cache_page
def hofwebpage(request):
    hof_entries = []
    hof_site = Fame.objects.alias().filter(Q(site_report_id__isnull=False)).order_by("-site_report_timestamp")
    for entry in hof_site.only("domain", "site_report_id").iterator():
        hof_entries.append({"domain": entry.domain, "permalink": f"/site/{entry.domain}/{entry.site_report_id}/"})

    template_dict = dict(
        pageclass="hall-of-fame",
        pagetitle=_("base halloffame web"),
        pagemenu="halloffame",
        hof_title="halloffame web title",
        cpage="web",
        hof_text="halloffame web text",
        hof_subtitle="halloffame web subtitle",
        count=len(hof_entries),
        halloffame=hof_entries,
    )
    _update_hof_with_manual(template_dict)
    return render(request, "halloffame.html", template_dict)


@simple_cache_page
def hofmailpage(request):
    hof_entries = []
    hof_mail = Fame.objects.alias().filter(Q(mail_report_id__isnull=False)).order_by("-mail_report_timestamp")
    for entry in hof_mail.only("domain", "mail_report_id").iterator():
        hof_entries.append({"domain": entry.domain, "permalink": f"/mail/{entry.domain}/{entry.mail_report_id}/"})

    template_dict = dict(
        pageclass="hall-of-fame",
        pagetitle=_("base halloffame mail"),
        pagemenu="halloffame",
        hof_title="halloffame mail title",
        cpage="mail",
        hof_text="halloffame mail text",
        hof_subtitle="halloffame mail subtitle",
        count=len(hof_entries),
        halloffame=hof_entries,
    )
    _update_hof_with_manual(template_dict)
    return render(request, "halloffame.html", template_dict)


@simple_cache_page
def hofmanualpage(request, manual_url):
    translate_key = (
        "translate_key" in settings.MANUAL_HOF[manual_url] and settings.MANUAL_HOF[manual_url]["translate_key"]
    ) or manual_url
    template_file = (
        "template_file" in settings.MANUAL_HOF[manual_url] and settings.MANUAL_HOF[manual_url]["template_file"]
    ) or "halloffame.html"
    hof_count, hof_entries = get_hof_manual(manual_url)
    template_dict = dict(
        pageclass="hall-of-fame",
        pagetitle=_(f"manual halloffame {translate_key} title"),
        pagemenu="halloffame",
        hof_title=f"manual halloffame {translate_key} title",
        cpage=manual_url,
        hof_text=f"manual halloffame {translate_key} text",
        hof_subtitle=f"manual halloffame {translate_key} subtitle",
        count=hof_count,
        halloffame=hof_entries,
    )
    _update_hof_with_manual(template_dict, current=manual_url)
    return render(request, template_file, template_dict)


def change_language(request):
    """
    Redirect to a new hostname when the user wishes for a language change.
    The user will be redirected to the same page he was before.

    """
    if request.method == "POST":
        hostname = request.get_host().split(":")[0]
        previous_page = request.POST.get("previous-page", "/")
        new_language = request.POST.get("language")

        # The News category may have articles available only for certain
        # languages, so we redirect to the News index instead.
        # BAD: the urls are coded in code, rather than to the sole knowledge
        #      of the urls.py definition.
        news_url = re.match(r"^/news/.*$", previous_page)
        if news_url:
            previous_page = "/news/"
        news_url = re.match(r"^/blogs/.*$", previous_page)
        if news_url:
            previous_page = "/blogs/"
        news_url = re.match(r"^/blogarticle/.*$", previous_page)
        if news_url:
            previous_page = "/blogarticle/"
        news_url = re.match(r"^/article/(.*)$", previous_page)
        if news_url:
            article_name = news_url.group(1)
            with translation.override(new_language):
                translation_key = f"article {article_name.replace('/', '')} body"
                has_translation = translation.gettext(translation_key) != translation_key
                if not has_translation:
                    previous_page = "/articles/"

        known_languages = [language[0] for language in settings.LANGUAGES]
        if new_language and new_language in known_languages:
            url_regex = re.compile("^(?P<protocol>http[s]?://).*$")
            uri = request.build_absolute_uri()
            protocol = url_regex.match(uri).group("protocol")

            # If the previous language is in the host remove it.
            # Also if the hostname starts with 'www.' (may appear in the
            # default language site) remove it so that the language prefix gets
            # applied to the domain name.
            previous_language = hostname.split(".", 1)[0]
            if previous_language in known_languages or previous_language == "www":
                no_language_host = request.get_host().replace(previous_language + ".", "", 1)
            else:
                no_language_host = request.get_host()

            language_prefix = new_language + "."
            redirect_url = protocol + language_prefix + no_language_host + previous_page
        else:
            redirect_url = previous_page
        try:
            return SafeHttpResponseRedirect(redirect_url)
        except DisallowedRedirect as exc:
            logging.info(f"Rejected redirect: {exc}")
            return HttpResponseRedirect("/")

    return HttpResponseRedirect("/")
