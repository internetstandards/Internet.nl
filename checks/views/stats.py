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
select res, sum(cc), sum(cw), sum(cm)
from (
    select date_trunc('day', timestamp)::date as res,
        count(*) as cc, null::bigint as cw, null::bigint as cm
    from checks_connectiontest
    where timestamp >= %s
        and timestamp < %s
        and finished = True
    group by res

    union
    select date_trunc('day', timestamp)::date as res,
        null::bigint as cc, count(*) as cw, null::bigint as cm
    from checks_domaintestreport
    where timestamp >= %s
        and timestamp < %s
    group by res

    union
    select date_trunc('day', timestamp)::date as res,
        null::bigint as cc, null::bigint as cw, count(*) as cm
    from checks_mailtestreport
    where timestamp >= %s
        and timestamp < %s
    group by res
) as t
group by res
order by res asc
""", [start_date, end_date, start_date, end_date, start_date, end_date])
        table_content = c.fetchall()
    return render(
        request, 'statistics.html',
        dict(
            table_headers=["Date", "Connection", "Website", "Mail"],
            table_content=table_content,
        ))
