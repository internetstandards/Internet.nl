from checks import categories
from checks.models import DomainTestIpv6, NsDomain
from checks.tasks.ipv6 import callback


def test_ipv6_nameserver_callback(db):
    """
    Verify that data from a nameserver scan is processed and stored correctly.

    """
    # todo: are we testing web_callback here? Perhaps call that instead of re-running the same statements.

    assert NsDomain.objects.all().count() == 0

    results = [
        (
            "ns",
            {
                "domains": [
                    {
                        "domain": "auth00.ns.nl.uu.net.",
                        "v4_good": ["193.79.237.134"],
                        "v4_bad": [],
                        "v6_good": ["2001:600:1c0:e000::35:1"],
                        "v6_bad": [],
                        "v6_conn_diff": [],
                        "score": 10,
                    },
                    {
                        "domain": "ns.amersfoort.nl.",
                        "v4_good": [],
                        "v4_bad": ["83.80.84.250"],
                        "v6_good": [],
                        "v6_bad": [],
                        "v6_conn_diff": [],
                        "score": 0,
                    },
                    {
                        "domain": "auth60.ns.nl.uu.net.",
                        "v4_good": ["193.67.79.134"],
                        "v4_bad": [],
                        "v6_good": ["2001:600:1c0:e001::35:1"],
                        "v6_bad": [],
                        "v6_conn_diff": [],
                        "score": 10,
                    },
                ],
                "score": 10,
            },
        )
    ]

    callback(results, "123.123.123.123", DomainTestIpv6(), "domaintestipv6", categories.WebIpv6())

    assert NsDomain.objects.all().count() == 3

    # Another domain where we don't see results being stored.
    more_results = [
        (
            "ns",
            {
                "domains": [
                    {
                        "domain": "a1-12.akam.net.",
                        "v4_good": ["193.108.91.12"],
                        "v4_bad": [],
                        "v6_good": ["2600:1401:2::c"],
                        "v6_bad": [],
                        "v6_conn_diff": [],
                        "score": 10,
                    },
                    {
                        "domain": "a28-65.akam.net.",
                        "v4_good": ["95.100.173.65"],
                        "v4_bad": [],
                        "v6_good": [],
                        "v6_bad": [],
                        "v6_conn_diff": [53],
                        "score": 0,
                    },
                    {
                        "domain": "edns69.ultradns.com.",
                        "v4_good": ["204.74.66.69"],
                        "v4_bad": [],
                        "v6_good": ["2001:502:f3ff::245"],
                        "v6_bad": [],
                        "v6_conn_diff": [],
                        "score": 10,
                    },
                    {
                        "domain": "a12-64.akam.net.",
                        "v4_good": ["184.26.160.64"],
                        "v4_bad": [],
                        "v6_good": [],
                        "v6_bad": ["2600:1480:f000::40"],
                        "v6_conn_diff": [53],
                        "score": 0,
                    },
                    {
                        "domain": "a7-66.akam.net.",
                        "v4_good": ["23.61.199.66"],
                        "v4_bad": [],
                        "v6_good": ["2600:1406:32::42"],
                        "v6_bad": [],
                        "v6_conn_diff": [],
                        "score": 10,
                    },
                    {
                        "domain": "a10-67.akam.net.",
                        "v4_good": ["96.7.50.67"],
                        "v4_bad": [],
                        "v6_good": [],
                        "v6_bad": [],
                        "v6_conn_diff": [53],
                        "score": 0,
                    },
                    {
                        "domain": "a9-67.akam.net.",
                        "v4_good": ["184.85.248.67"],
                        "v4_bad": [],
                        "v6_good": ["2a02:26f0:117::43"],
                        "v6_bad": [],
                        "v6_conn_diff": [],
                        "score": 10,
                    },
                ],
                "score": 8,
            },
        )
    ]
    callback(more_results, "123.123.123.123", DomainTestIpv6(), "domaintestipv6", categories.WebIpv6())

    assert NsDomain.objects.all().count() == 10

    # let's find a specific result
    assert (
        NsDomain.objects.all()
        .filter(v6_good="['2a02:26f0:117::43']", v4_good="['184.85.248.67']", domain="a9-67.akam.net.")
        .count()
        == 1
    )
