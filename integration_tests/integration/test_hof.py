"""Basis functionality that should always be present."""
from playwright.sync_api import expect


def test_cron_manual_hosters_hof(page, app_url, trigger_cron):
    """Test if manual hosters file can be downloaded and parsed."""

    trigger_cron("15min/download_hof")

    page.goto(app_url)
    page.get_by_role("link", name="Hall of Fame", exact=True).click()
    page.get_by_text("Hosters", exact=True).click()

    hof_content = page.locator(".hof-content")

    assert "The 51 hosters mentioned below" in hof_content.text_content()


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
