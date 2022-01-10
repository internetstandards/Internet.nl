# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from collections import namedtuple

from django.conf import settings

# .. note:: None ttl means cache indefinitely.
REDIS_RECORD = namedtuple("REDIS_RECORD", "id ttl")

# Autoconf
autoconf = REDIS_RECORD("autoconf:{}", None)

# Padded MACs
# .. note:: The TTL value is not used and set explicitly to not expire.
padded_macs = REDIS_RECORD("conn:lookup:padded_macs", None)

# WHOIS requests
whois = REDIS_RECORD("whois:{}", settings.CACHE_WHOIS_TTL)

# starttls results per mailserver
mail_starttls = REDIS_RECORD("mx:starttls:{}", settings.CACHE_TTL)

# ipv6 results per mailserver
mail_ipv6 = REDIS_RECORD("mx:ipv6:{}", settings.CACHE_TTL)

# Started tasks per domain name
dom_task = REDIS_RECORD("dom:task:{}:{}", settings.CACHE_TTL)

# Request limit per address
req_limit = REDIS_RECORD("dom:req_limit:{}", 2 * 60 * 60)

# Lock for HoF updater
hof_lock = REDIS_RECORD("hof:updater:lock", 60 * 5)

# HoF data
hof_champions = REDIS_RECORD("hof:champions", None)
hof_web = REDIS_RECORD("hof:web", None)
hof_mail = REDIS_RECORD("hof:mail", None)

# Public suffix list data
psl_data = REDIS_RECORD("public:suffix:list", settings.PUBLIC_SUFFIX_LIST_RENEWAL)

# Public suffix list loading flag
psl_loading = REDIS_RECORD("public:suffix:list:loading", 60)

# Home page stats data
home_stats_data = REDIS_RECORD("home:stats:{}", None)

# Home page stats lock
home_stats_lock = REDIS_RECORD("home:stats:lock", 60 * 2)

# Started connection test
conn_test = REDIS_RECORD("conn:{}", settings.CACHE_TTL)

# Bogus connection test
conn_test_bogus = REDIS_RECORD("conn:{}:bogus", settings.CACHE_TTL)

# NS IPv6 connection test
conn_test_ns6 = REDIS_RECORD("conn:{}:ns6", settings.CACHE_TTL)

# Connection test resolvers
conn_test_resolvers = REDIS_RECORD("conn:{}:resolv", settings.CACHE_TTL)

# Connection test resolver's AS
conn_test_resolver_as = REDIS_RECORD("conn:{}:resolv:{}", settings.CACHE_TTL)

# Connection test IPv6
conn_test_v6 = REDIS_RECORD("conn:{}:ipv6", settings.CACHE_TTL)

# Connection test IPv6 AAAA
conn_test_aaaa = REDIS_RECORD("conn:{}:ipv6:aaaa", settings.CACHE_TTL)

# Connection test IPv6 reachability
conn_test_v6_reach = REDIS_RECORD("conn:{}:ipv6:addr", settings.CACHE_TTL)

# Conection test IPv4
conn_test_v4 = REDIS_RECORD("conn:{}:ipv4", settings.CACHE_TTL)

# Connection test AS
conn_test_as = REDIS_RECORD("asn:{}", settings.CACHE_TTL)

# Simple request cache for batch users
simple_cache_page = REDIS_RECORD("cached_page:{}:{}:{}", getattr(settings, "PAGE_CACHE_TIME", 60 * 5))

# Lock for generating batch results
batch_results_lock = REDIS_RECORD("batch:results:gen:{}:{}", None)

# Lock for batch scheduler
batch_scheduler_lock = REDIS_RECORD("batch:scheduler:lock", 60 * 5)

# Running batch test id
running_batch_test = REDIS_RECORD("batch:task_id:{}", 60 * 10)

# Report metadata
# .. note:: The TTL value is not used and set explicitly to not expire.
report_metadata = REDIS_RECORD("batch:report_metadata", None)

# Batch metadata for test name map
# .. note:: The TTL value is not used and set explicitly to not expire.
batch_metadata = REDIS_RECORD("batch:name_map_metadata", None)
