# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from datetime import datetime

from django.db import connection
from django.http import HttpResponseBadRequest
from django.shortcuts import render


def statistics(request, start_date, end_date):
    """
    Simple db dump of the completed tests per day.

    .. note:: SQL was necessary because the tables are not related and django
              ORM related queries could not be used and were inefficient.

    """
    try:
        start_date = datetime.strptime(start_date, "%Y%m%d")
        end_date = datetime.strptime(end_date, "%Y%m%d")
    except ValueError:
        return HttpResponseBadRequest("Invalid input parameters.")
    with connection.cursor() as c:
        c.execute(
            """
            select coalesce(c.res, w.res, m.res), c.cc, w.cc, m.cc
            from
            (select date_trunc('day', timestamp)::date as res, count(*) as cc
            from checks_connectiontest
            where timestamp >= %s
              and timestamp < %s
              and finished = True
            group by res) c

            full join
            (select date_trunc('day', timestamp)::date as res, count(*) as cc
            from checks_domaintestreport
            where timestamp >= %s
              and timestamp < %s
            group by res) w on c.res = w.res

            full join
            (select date_trunc('day', timestamp)::date as res, count(*) as cc
            from checks_mailtestreport
            where timestamp >= %s
              and timestamp < %s
            group by res) m on c.res = m.res
            """,
            [start_date, end_date, start_date, end_date, start_date, end_date])
        table_content = c.fetchall()
    return render(
        request, 'statistics.html',
        dict(
            table_headers=["Date", "Connection", "Website", "Mail"],
            table_content=table_content,
        ))
