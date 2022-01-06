from django.test import SimpleTestCase
from django_redis import get_redis_connection

from interface import redis_id
from interface.views import connection


class SlaacPrivacyExtensionTestCase(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.vendor_list = get_redis_connection().hgetall(redis_id.padded_macs.id)

    def test_decoding_on_mac_vendors(self):
        try:
            for vendor in self.vendor_list.values():
                vendor.decode(errors='replace')
        except Exception:
            self.assertTrue(False)
        self.assertTrue(True)

    def test_privacy_on(self):
        """
        This tests if the IPv6 specific part does not match any known vendors.

        """
        ip = "2001:db8::dead:beef:1:1"
        self.assertEqual(connection.get_slaac_mac_vendor(ip), 'false')

    def test_privacy_off(self):
        """
        This tests if the IPv6 specific part does match the known vendor.

        """
        # The following part should be the vendor part of Intel's MAC addresses
        # with the relevant bit (7th bit of first byte) flipped for the SLAAC
        # IPv6 address:
        #                *
        #               ------------
        ip = "2001:db8::76e5:f9fe:ff11:1"
        self.assertEqual(connection.get_slaac_mac_vendor(ip), 'Intel Corporate')
