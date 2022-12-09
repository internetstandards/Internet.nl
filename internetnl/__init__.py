# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0

from internetnl.celery import app as celery_app

from celery.utils.log import get_task_logger

log = get_task_logger(__package__)

__all__ = ("celery_app",)
