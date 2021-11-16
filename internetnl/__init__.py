# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from .celery import app as celery_app

__all__ = ('celery_app',)
