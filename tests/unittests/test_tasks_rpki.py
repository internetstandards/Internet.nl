import responses

from django.test import SimpleTestCase, override_settings

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

    @override_settings(ROUTINATOR_URL="https://example.net/api/v1/validity")
    def test_do_rpki(self):
        for domain, expected_result in BEACONS.items():
            with self.subTest(f"{domain}"):
                for asn, prefix in expected_result["routes"]:
                    routinator_url = f"https://example.net/api/v1/validity/{asn}/{prefix}"
                    routinator_response = self._generate_routinator_response(prefix, expected_result["state"])
                    responses.add(
                        method=responses.GET,
                        url=routinator_url,
                        json=routinator_response,
                    )
                fqdn_ip_pairs = [(domain, do_resolve_a_aaaa(self.task, domain))]
                result = do_rpki(self.task, fqdn_ip_pairs)

                assert result

                for ip in result[domain]:
                    for route in ip["routes"]:
                        self.assertIn(route, expected_result["routes"])
                        self.assertEqual(ip["validity"][route]["state"], expected_result["state"])

                        if expected_result["state"] != "not-found":
                            asn, prefix = route
                            expected_vrps = [{"asn": asn, "prefix": prefix, "max_length": 32}]
                            self.assertEqual(ip["validity"][route]["vrps"], expected_vrps)

    def _generate_routinator_response(self, prefix, state):
        # These responses are not entirely complete - only far enough as needed for this test
        response = {
            "validated_route": {
                "route": {
                    "origin_asn": "AS12654",
                    "prefix": prefix,
                },
                "validity": {
                    "state": state,
                    "description": "...",
                    "VRPs": {"matched": [], "unmatched_as": [], "unmatched_length": []},
                },
            },
            "generatedTime": "2022-06-14T20:19:55Z",
        }
        vrp = {
            "asn": "AS12654",
            "prefix": prefix,
            "max_length": 32,
        }
        if state == "valid":
            response["validated_route"]["validity"]["VRPs"]["matched"] = [vrp]
        if state == "invalid":
            response["validated_route"]["validity"]["reason"] = "as"
            response["validated_route"]["validity"]["VRPs"]["unmatched_as"] = [vrp]
        return response
