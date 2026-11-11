"""Basis functionality that should always be present."""

from playwright.sync_api import expect


def test_cron_manual_hosters_hof(page, app_url, trigger_cron):
    """Test if manual hosters file can be downloaded and parsed."""

    trigger_cron("15min/download_hof")

    page.goto(f"{app_url}/halloffame/")
    page.get_by_role("link", name="Hosters", exact=True).click()

    expect(page.get_by_text("The 51 hosters mentioned below")).to_be_visible()


def test_hof_update(page, app_url, trigger_scheduled_task, unique_id, docker_compose_exec, clear_webserver_cache):
    """Test if Hall of Fame can be updated."""

    domain = f"{unique_id}.example.com"

    # create new domain results, champions need 100% for both website and email
    docker_compose_exec(
        "app",
        (
            './manage.py shell -c "from checks.models import DomainTestReport, MailTestReport;'
            f"DomainTestReport(domain='{domain}', score=100).save();"
            f"MailTestReport(domain='{domain}', score=100).save()\""
        ),
    )

    # generate hof
    trigger_scheduled_task("generate_HoF")

    page.goto(f"{app_url}/halloffame/")

    expect(page.get_by_role("listitem").filter(has_text=domain)).to_be_visible()
