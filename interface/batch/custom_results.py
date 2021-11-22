# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from abc import ABC, abstractmethod

from checks.models import DomainTestReport, MailTestReport, ZeroRttStatus
from checks.models import BatchRequestType, DmarcPolicyStatus, SpfPolicyStatus
from checks.categories import MailTlsStarttlsExists
from checks import DMARC_NON_SENDING_POLICY, DMARC_NON_SENDING_POLICY_ORG, SPF_NON_SENDING_POLICY


def _create_custom_results_map(instances):
    results_map = {}
    for custom in instances:
        name = custom.__class__.__name__
        results_map[name] = custom
    return results_map


class CustomResult(ABC):
    """
    Abstract class for custom results.

    """
    @abstractmethod
    def get_data(self, report_table):
        """
        Should return `None` if the custom result is not relevant for the
        domain e.g., the request is of type mail and the custom result is only
        relevant for web domains.

        `report_table` is one of `DomainTestReport` or `MailTestReport` for
        web and mail tests respectively. If extra information is needed you
        can navigate away to individual test tables from there.

        """
        pass

    @abstractmethod
    def related_db_tables(self, batch_request_type):
        """
        Should return a set with any related DB tables needed for the custom
        data. These related tables are the OneToMany related tables that need
        to be fetched with extra queries.

        Related DB entries should be of the format
        "<testtable>__<relative_name>" and they will be ultimately used to form
        the relation:

        batchdomain__<webtest/mailtest>__report__<testtable>__<relative_name>

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
            'description': """_[Only for mailtests]_

Checks if the domain is configured for *not* sending email. For this test this
is translated as:
* SPF record with `v=spf1 -all`, and
* DMARC record with `v=DMARC1;p=reject;`.

(If `true`, the DKIM test could be considered as not relevant.)
""",
        }

    def related_db_tables(self, batch_request_type):
        return set()

    def get_data(self, report_table):
        if not isinstance(report_table, MailTestReport):
            return None

        mtauth = report_table.auth
        if not mtauth:
            # No guarantee that auth has been tested in this batch test, might be disabled in a feature flag
            return False
        is_org = mtauth.dmarc_record_org_domain

        if (mtauth.dmarc_available
                and mtauth.dmarc_policy_status == DmarcPolicyStatus.valid
                and ((is_org and DMARC_NON_SENDING_POLICY_ORG.match(
                        mtauth.dmarc_record[0]))
                     or (not is_org and DMARC_NON_SENDING_POLICY.match(
                         mtauth.dmarc_record[0])))
                and mtauth.spf_available
                and mtauth.spf_policy_status == SpfPolicyStatus.valid
                and SPF_NON_SENDING_POLICY.match(mtauth.spf_record[0])):
            return True
        return False


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

            'description': """_[Only for mailtests; relates to the STARTTLS
category]_

This result gives a clearer insight on the STARTTLS testability status:
* `no_mx` - No mailservers are configured for the domain.
* `unreachable` - Network connectivity was not possible with at least one
  mailserver for the STARTTLS tests. That mailserver is treated as non
  testable.
* `untestable` - We encountered errors during testing with at least one
  mailserver. These could be persistent SMTP errors and/or dropped connections
  that we couldn't overcome even after several retries. Instead of partial (and
  probably not correct) STARTTLS results, that mailserver is treated as
  non testable.
* `ok` - All mailservers could be tested thoroughly for all the STARTTLS
  related tests.
""",
        }

    def related_db_tables(self, batch_request_type):
        return set()

    def get_data(self, report_table):
        if not isinstance(report_table, MailTestReport):
            return None

        report = report_table.tls.report
        test_instance = MailTlsStarttlsExists()
        test_instance.result_no_mailservers()
        if report[test_instance.name]['verdict'] == test_instance.verdict:
            return 'no_mx'
        test_instance.result_could_not_test()
        if report[test_instance.name]['verdict'] == test_instance.verdict:
            return 'untestable'
        test_instance.result_unreachable()
        if report[test_instance.name]['verdict'] == test_instance.verdict:
            return 'unreachable'
        return 'ok'


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
is only available starting from TLS1.3. As there is no explicit TLS1.3
connection during testing, the test assumes that the server chose TLS1.3 when
given the opportunity to do so.
* `yes` - All the servers support TLS1.3.
* `no` - At least one server does not support TLS1.3.
* `undetermined` - We cannot properly determine TLS1.3 support for at least one
  of the servers (connection problems or we couldn't thoroughly test the
  server).
""",
        }

    def related_db_tables(self, batch_request_type):
        related = set()
        if batch_request_type is BatchRequestType.web:
            related.add('tls__webtestset')
        else:
            related.add('tls__testset')
        return related

    def get_data(self, report_table):
        status = 'yes'
        testset = 'testset'
        if isinstance(report_table, DomainTestReport):
            testset = 'webtestset'
        try:
            servers = getattr(report_table.tls, testset).all()
        except AttributeError:
            # if tls tests are not run, there is no webtestset inside of reporttable.tls as .tls is None:
            return 'no'

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
