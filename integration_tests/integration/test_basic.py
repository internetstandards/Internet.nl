"""Basis functionality that should always be present."""
import re
import pytest
import requests
from playwright.sync_api import expect

FOOTER_TEXT_EN = "Internet.nl is an initiative of the Internet community and the Dutch"
FOOTER_TEXT_NL = "Internet.nl is een initiatief van de internetgemeenschap en de Nederlandse"

SECURITY_TXT_TEXT = "Policy: https://internet.nl/disclosure/"

ROBOTS_TXT_TEXT = "Disallow: /site/"


def test_index_http_ok(page, app_url_subdomain):
    response = page.request.get(app_url_subdomain)
    expect(response).to_be_ok()


@pytest.mark.parametrize(
    ("app_url", "footer_text"),
    [("https://en.internet.test", FOOTER_TEXT_EN), ("https://nl.internet.test", FOOTER_TEXT_NL)],
)
def test_index_footer_text_present(page, app_url, footer_text):
    page.goto(app_url)
    footer = page.locator("#footer")

    assert footer_text in footer.text_content()


def test_security_txt(page, app_url_subdomain):
    page.goto(app_url_subdomain + "/.well-known/security.txt")

    assert SECURITY_TXT_TEXT in page.content()


def test_robots_txt(page, app_url_subdomain):
    page.goto(app_url_subdomain + "/robots.txt")

    assert ROBOTS_TXT_TEXT in page.content()


def test_favicon_ico(page, app_url_subdomain):
    response = page.request.get(app_url_subdomain + "/favicon.ico")
    expect(response).to_be_ok()


def test_static_files(page, app_url_subdomain):
    response = requests.get(app_url_subdomain + "/static/logo_en.png", verify=False)
    response.raise_for_status()


def test_generated_css_static_files(page, app_url_subdomain):
    response = requests.get(app_url_subdomain + "/static/css/style-min.css", verify=False)
    response.raise_for_status()
    assert "@font-face" in response.text
    assert "expires" in response.headers


def test_generated_js_static_files(page, app_url_subdomain):
    response = requests.get(app_url_subdomain + "/static/js/menu-min.js", verify=False)
    response.raise_for_status()
    assert "hideMenuButton" in response.text
    assert "expires" in response.headers


@pytest.mark.parametrize(
    "path",
    ["/grafana", "/prometheus", "/prometheus/targets"],
)
def test_monitoring_auth(page, app_url, path):
    """Monitoring endpoints must be behind basic auth."""

    response = requests.get(app_url + path, verify=False)
    assert response.status_code == 401

    # MONITORING_AUTH provided in docker/test.env
    auth = ("test", "test")

    response = requests.get(app_url + path, auth=auth, verify=False)
    response.raise_for_status()


def test_monitoring_auth_raw(page, app_url):
    """Monitoring endpoints must be behind basic auth."""
    path = "/grafana"

    response = requests.get(app_url + path, verify=False)
    assert response.status_code == 401

    # MONITORING_AUTH_RAW provided in docker/test.env
    auth = ("test_raw", "test_raw")

    response = requests.get(app_url + path, auth=auth, verify=False)
    response.raise_for_status()


def test_no_server_banner(page, app_url_subdomain):
    response = requests.get(app_url_subdomain, verify=False)
    assert response.headers["server"] == "nginx"


def test_http_redirect_https(page, app_url_subdomain):
    response = requests.get(app_url_subdomain.replace("https", "http"), allow_redirects=False)
    assert response.status_code == 301
    assert re.match(app_url_subdomain, response.headers["location"])


def test_nowww_class_b(page, app_domain, app_url):
    response = requests.get(f"https://www.{app_domain}", allow_redirects=False, verify=False)
    assert response.status_code == 301
    assert response.headers["location"] == f"{app_url}/"


def test_additional_redirect_domains(page, app_url):
    """Additional configured redirect subdomains should redirect to the frontpage."""
    response = requests.get("https://platforminternet.test", allow_redirects=False, verify=False)
    assert response.status_code == 301
    assert response.headers["location"] == f"{app_url}/"


def test_default_sni_none(app_domain):
    """Default vhost should 404 on any non explicitly configured domain. #894"""

    not_configured_domain = "telefax.test"

    # make a https request to the webserver's adres but request a vhost that is not configured
    response = requests.get(
        f"https://{app_domain}", headers={"Host": not_configured_domain}, verify=False, allow_redirects=False
    )
    assert response.status_code == 404


def test_conn_over_https_no_hsts(app_domain):
    """Serving conn. over HTTPS should disable HSTS and downgrade to HTTP. #894"""

    # make a https request to the webserver's adres but request a vhost that is not configured
    response = requests.get(f"https://conn.{app_domain}", verify=False, allow_redirects=False)
    assert response.status_code == 301
    assert response.headers["Strict-Transport-Security"] == "max-age=0;"
    assert response.headers["location"] == f"http://conn.{app_domain}"


@pytest.mark.parametrize(
    ("from_language", "to_language", "footer_text"),
    [("nl", "en", FOOTER_TEXT_EN), ("en", "nl", FOOTER_TEXT_NL)],
)
def test_change_language(page, app_domain, from_language, to_language, footer_text):
    """Test clicking the language change button."""

    page.goto(f"https://{from_language}.{app_domain}")
    page.locator("#language-switch-header-container button:not(:disabled)").click()
    page.wait_for_url(f"https://{to_language}.internet.test/")

    footer = page.locator("#footer")
    assert footer_text in footer.text_content()


@pytest.mark.parametrize(
    ("language", "footer_text"),
    [("en", FOOTER_TEXT_EN), ("nl", FOOTER_TEXT_NL)],
)
def test_accept_language_header(page, app_domain, language, footer_text):
    """Browser preferred language should be respected."""

    page.set_extra_http_headers({"Accept-Language": language})
    page.goto(f"https://{app_domain}")

    footer = page.locator("#footer")
    assert footer_text in footer.text_content()


def test_cron_manual_hosters_hof(page, app_url, trigger_cron):
    """Test if manual hosters file can be downloaded and parsed."""

    trigger_cron("15min/download_hof")

    page.goto(app_url)
    page.get_by_role("link", name="Hall of Fame", exact=True).click()
    page.get_by_text("Hosters").click()

    hof_content = page.locator(".hof-content")

    assert "The 51 hosters mentioned below" in hof_content.text_content()


def test_cron_postgres_backups(trigger_cron, docker_compose_exec):
    """Test if database backup files are created."""

    docker_compose_exec("cron", "rm -f /var/lib/postgresql/backups/internetnl_db1.daily.sql.gz")
    docker_compose_exec("cron", "rm -f /var/lib/postgresql/backups/internetnl_db1.weekly.sql.gz")

    trigger_cron("daily/postgresql_backup")
    trigger_cron("weekly/postgresql_backup")

    assert docker_compose_exec("cron", "ls /var/lib/postgresql/backups/internetnl_db1.daily.sql.gz")
    assert docker_compose_exec("cron", "ls /var/lib/postgresql/backups/internetnl_db1.weekly.sql.gz")


def test_hof_update(page, app_url, trigger_scheduled_task, unique_id, docker_compose_exec, clear_webserver_cache):
    """Test if Hall of Fame can be updated."""

    domain = f"{unique_id}.example.com"

    # create new domain result
    docker_compose_exec(
        "app",
        (
            './manage.py shell -c "from checks.models import DomainTestReport;'
            f"DomainTestReport(domain='{domain}', score=100).save()\""
        ),
    )

    # generate hof
    trigger_scheduled_task("generate_HoF")

    page.goto(app_url)
    page.get_by_role("link", name="Hall of Fame", exact=True).click()
    page.get_by_text("Websites").click()

    expect(page.get_by_role("listitem").filter(has_text=domain)).to_be_visible()
