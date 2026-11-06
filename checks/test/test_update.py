from django.core.cache import cache

from checks.models import ConnectionTest, DomainTestReport, MailTestReport
from checks.tasks.update import _update_hof
from interface import redis_id


def test_update_hof(db, client, settings):
    # use a local cache, because the test environment shares its redis
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}

    DomainTestReport.objects.create(domain="perfect.example", score=100)
    DomainTestReport.objects.create(domain="lapsed.example", score=100)
    DomainTestReport.objects.create(domain="lapsed.example", score=80)
    DomainTestReport.objects.create(domain="partial.example", score=50)
    mail = MailTestReport.objects.create(domain="perfect.example", score=100)
    MailTestReport.objects.create(domain="lapsed.example", score=100)
    ConnectionTest.objects.create(finished=True, score_ipv6=100, score_dnssec=100)
    ConnectionTest.objects.create(finished=True, score_ipv6=100, score_dnssec=0)
    ConnectionTest.objects.create(finished=False)

    _update_hof()

    champions = cache.get(redis_id.hof_champions.id)
    # the mail test came last, so the entry links to it
    assert champions == {
        "count": 1,
        "data": [
            {"permalink": f"/mail/perfect.example/{mail.id}/", "domain": "perfect.example", "timestamp": mail.timestamp}
        ],
    }
    assert cache.get(redis_id.home_stats.id) == {
        "web": {"tested": 3, "percent": 33},
        "mail": {"tested": 2, "percent": 100},
        "connection": {"tested": 2, "percent": 50},
    }
    assert "33%" in client.get("/").content.decode()
