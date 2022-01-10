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
select res, ww, mm, cc, coalesce(ww, 0) + coalesce(mm, 0) + coalesce(cc, 0)
from (

select res, sum(cw) as ww, sum(cm) as mm, sum(cc) as cc
from (
    select date_trunc('day', timestamp)::date as res,
        count(*) as cw, null::bigint as cm, null::bigint as cc
    from checks_domaintestreport
    where timestamp >= %s
        and timestamp < %s
    group by res

    union
    select date_trunc('day', timestamp)::date as res,
        null::bigint as cw, count(*) as cm, null::bigint as cc
    from checks_mailtestreport
    where timestamp >= %s
        and timestamp < %s
    group by res

    union
    select date_trunc('day', timestamp)::date as res,
        null::bigint as cw, null::bigint as cm, count(*) as cc
    from checks_connectiontest
    where timestamp >= %s
        and timestamp < %s
        and finished = True
    group by res
) as t
group by res

) as per_day
group by res, ww, mm, cc
order by res asc
""",
            [start_date, end_date, start_date, end_date, start_date, end_date],
        )
        table_content = c.fetchall()

    per_test = [sum(filter(None, x)) if i > 0 else "" for i, x in enumerate(zip(*table_content))]
    per_test[0] = "Total per period"
    return render(
        request,
        "statistics.html",
        dict(
            table_headers=["Date", "Website", "Mail", "Connection", "Total per day"],
            table_content=table_content,
            per_test=per_test,
        ),
    )
