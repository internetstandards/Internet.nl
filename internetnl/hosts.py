# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from django.conf import settings
from django_hosts import host, patterns

testid = r"((?P<test_id>[a-zA-Z0-9]*))?"
nstype = r"(?P<ns_type>(test-ns-signed|test-ns6-signed))"

cb = "interface.views.connection.hostname_callback"
bcb = "interface.views.connection.hostname_bogus_callback"

host_patterns = patterns(
    "",
    host(r"www", settings.ROOT_URLCONF, name="www"),
    host(testid + r".aaaa.conn." + nstype, "interface.conntesturls.ipv6_urls", name="ipv6-test", callback=cb),
    host(testid + r".a.conn." + nstype, "interface.conntesturls.ipv4_urls", name="ipv4-test", callback=cb),
    host(testid + r".a-aaaa.conn." + nstype, "interface.conntesturls.resolver_urls", name="resolver-test", callback=cb),
    host(
        testid + r".bogus.conn." + nstype,
        "interface.conntesturls.resolver_urls",
        name="resolver-bogus-test",
        callback=bcb,
    ),
    host(r"", settings.ROOT_URLCONF, name="empty"),
)
