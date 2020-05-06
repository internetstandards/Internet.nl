# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import re
from abc import ABC, abstractmethod

from ..models import BatchRequestType


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
        pass

    @property
    @abstractmethod
    def name(self):
        pass

    @property
    @abstractmethod
    def openapi_spec(self):
        pass


class MailNonSendingDomain(CustomResult):
    """
    Checks if the domain seems configured for no outgoing email.

    """
    @property
    def name(self):
        return "mail_non_sending_domain"

    @property
    def openapi_spec(self):
        return {
            'type': 'boolean',
            'description': """Checks if the domain is configured for *not*
sending email. For this test this is translated as:
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


CUSTOM_RESULTS_MAP = _create_custom_results_map([
    MailNonSendingDomain(),
])
