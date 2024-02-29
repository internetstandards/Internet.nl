# Created by Uwe Kamper <uk@sys4.de> with Django 3.2.23 on 2024-02-12 13:30

import checks.models
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("checks", "0015_auto_20240212_1616"),
    ]

    operations = [
         migrations.AddField(
            model_name="mailtestauth",
            name="tlsrpt_score",
            field=models.IntegerField(null=True),
        ),
        migrations.AddField(
            model_name="mailtestauth",
            name="tlsrpt_available",
            field=models.BooleanField(default=False, null=True),
        ),
        migrations.AddField(
            model_name="mailtestauth",
            name="tlsrpt_record",
            field=checks.models.ListField(default=[]),
        ),
    ]
