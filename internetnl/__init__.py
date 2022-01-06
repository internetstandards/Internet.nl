# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from internetnl.celery import app as celery_app
import logging

log = logging.getLogger(__package__)

__all__ = ('celery_app',)
