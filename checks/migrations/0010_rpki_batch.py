# Generated by Django 3.2.5 on 2021-10-22 12:33

import checks.models
from django.db import migrations, models
import django.db.models.deletion
import enumfields.fields


class Migration(migrations.Migration):

    dependencies = [
        ('checks', '0009_rpki'),
    ]

    operations = [
        migrations.AddField(
            model_name='batchmailtest',
            name='rpki',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='checks.mailtestrpki'),
        ),
        migrations.AddField(
            model_name='batchmailtest',
            name='rpki_errors',
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='batchmailtest',
            name='rpki_status',
            field=enumfields.fields.EnumIntegerField(default=0, enum=checks.models.BatchTestStatus),
        ),
    ]