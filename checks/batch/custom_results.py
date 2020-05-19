# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import re
from abc import ABC, abstractmethod

from ..models import BatchRequestType, ZeroRttStatus


def _create_custom_results_map(instances):
    results_map = {}
    for custom in instances:
        name = custom.__class__.__name__
        results_map[name] = custom
    return results_map


class CustomResult(ABC):
    """

    """
    @abstractmethod
    def get_data(self, batch_request_type, batch_domain):
        """
        Returns `None` if the custom result is not relevant for the domain
        e.g., the `batch_request_type` is of type mail and the custom result
        is for web domains.

        """
        pass

    @property
    @abstractmethod
    def name(self):
        """
        Should return a string with the name that is going to be used in the
        API spec and output.

        """
        pass

    @property
    @abstractmethod
    def required(self):
        """
        Should be a boolean value that indicates if the custom result is
        required or not.

        """
        pass

    @property
    @abstractmethod
    def openapi_spec(self):
        """
        Should return a dict with the desired OPENAPI specification.

        """
        pass


class MailNonSendingDomain(CustomResult):
    """
    Checks if the domain seems configured for no outgoing email.

    """
    @property
    def name(self):
        return "mail_non_sending_domain"

    @property
    def required(self):
        return False

    @property
    def openapi_spec(self):
        return {
            'type': 'boolean',
            'description': """[Only for mailtests]
Checks if the domain is configured for *not* sending email. For this test this
is translated as:
* SPF record with `v=spf1 -all`, and
* DMARC record with `v=DMARC1;p=reject;`.

(If `true`, the DKIM test could be considered as not relevant.)
""",
        }

    def get_data(self, batch_request_type, batch_domain):
        if batch_request_type != BatchRequestType.mail:
            return None

        batch_test = batch_domain.get_batch_test()
        non_sending_domain = False
        dmarc_re = re.compile(r'v=DMARC1;\ *p=reject;?')
        spf_re = re.compile(r'v=spf1\ +-all;?')
        dmarc_available = batch_test.auth.dmarc_available
        dmarc_record = batch_test.auth.dmarc_record
        spf_available = batch_test.auth.spf_available
        spf_record = batch_test.auth.spf_record
        if (dmarc_available and spf_available
                and len(dmarc_record) == 1 and len(spf_record) == 1
                and dmarc_re.match(dmarc_record[0])
                and spf_re.fullmatch(spf_record[0])):
            non_sending_domain = True
        return non_sending_domain


class MailServersTestableStatus(CustomResult):
    """
    Checks if all mail servers could be tested.

    """
    @property
    def name(self):
        return "mail_servers_testable_status"

    @property
    def required(self):
        return False

    @property
    def openapi_spec(self):
        return {
            'type': 'string',
            'enum': ['no_mx', 'unreachable', 'untestable', 'ok'],
            'description': """[Only for mailtests]
Checks the testability status of the mailservers:
* `no_mx` - No mailservers are configured for the domain.
* `unreachable` - Network connectivity was not possible with at least one
  mailserver.
* `untestable` - At least one mailserver stopped communicating back (e.g.,
  ratelimit was in place). Instead of partial (and probably not correct)
  results, that mailserver is treated as non testable.
* `ok` - All mailservers could be tested propertly.
""",
        }

    def get_data(self, batch_request_type, batch_domain):
        if batch_request_type != BatchRequestType.mail:
            return None

        batch_test = batch_domain.get_batch_test()
        report = batch_test.tls.report
        verdict = report['starttls_exists']['verdict']
        if verdict == 'detail mail tls starttls-exists verdict other-2':
            status = 'no_mx'
        elif verdict == 'detail verdict could-not-test':
            status = 'untestable'
        elif verdict == 'detail mail tls starttls-exists verdict other':
            status = 'unreachable'
        else:
            status = 'ok'

        return status


class Tls13Support(CustomResult):
    """
    Checks TLS1.3 support through the 0-RTT test.

    """
    @property
    def name(self):
        return "tls_1_3_support"

    @property
    def required(self):
        return True

    @property
    def openapi_spec(self):
        return {
            'type': 'string',
            'enum': ['yes', 'no', 'undetermined'],
            'description': """Derives TLS1.3 support through the 0-RTT test.
Explicitly testing for TLS1.3 support is not part of the compliance tool.
However, TLS1.3 support could be derived from the 0-RTT test as the function
is only available starting from TLS1.3:
* `yes` - All the servers support TLS1.3.
* `no` - At least one of servers does not support TLS1.3.
* `undetermined` - We cannot properly determine TLS1.3 support for at least one
  of the servers (connection problems or we couldn't thoroughly test the
  server).
""",
        }

    def get_data(self, batch_request_type, batch_domain):
        status = 'yes'
        batch_test = batch_domain.get_batch_test()
        testset = 'testset'
        if batch_request_type == BatchRequestType.web:
            testset = 'webtestset'
        servers = getattr(batch_test.tls, testset).all()
        if not servers:
            status = 'no'
        for dttls in servers:
            if (dttls.could_not_test_smtp_starttls
                    or not dttls.server_reachable):
                status = 'undetermined'
                break
            if (not dttls.tls_enabled
                    or dttls.zero_rtt == ZeroRttStatus.na):
                status = 'no'
        return status


CUSTOM_RESULTS_MAP = _create_custom_results_map([
    MailNonSendingDomain(),
    MailServersTestableStatus(),
    Tls13Support(),
])
