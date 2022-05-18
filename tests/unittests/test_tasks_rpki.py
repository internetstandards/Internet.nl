from django.test import SimpleTestCase

from checks.tasks import SetupUnboundContext as Task
from checks.tasks.rpki import do_rpki
from checks.tasks.shared import do_resolve_a_aaaa

# RIPE NCC RPKI Routing beacons
# see: https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/current-ris-routing-beacons
BEACONS = {
    "cert-valid.ris.ripe.net": {
        "state": "valid",
        "routes": [("12654", "93.175.146.0/24"), ("12654", "2001:7fb:fd02::/48")],
    },
    "cert-bad-origin.ris.ripe.net": {
        "state": "invalid",
        "routes": [("12654", "93.175.147.0/24"), ("12654", "2001:7fb:fd03::/48")],
    },
    "cert-none.ris.ripe.net": {
        "state": "not-found",
        "routes": [("12654", "84.205.83.0/24"), ("12654", "2001:7fb:ff03::/48")],
    },
}


class RpkiTestCase(SimpleTestCase):
    def setUp(self) -> None:
        self.task = Task()

        return super().setUp()

    def test_do_rpki(self):
        for domain, expected_result in BEACONS.items():
            with self.subTest(f"{domain}"):
                fqdn_ip_pairs = [(domain, do_resolve_a_aaaa(self.task, domain))]
                result = do_rpki(self.task, fqdn_ip_pairs)

                for ip in result[domain]:
                    for route in ip["routes"]:
                        self.assertIn(route, expected_result["routes"])
                        self.assertEquals(ip["validity"][route]["state"], expected_result["state"])
