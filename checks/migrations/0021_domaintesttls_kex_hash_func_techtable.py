from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("checks", "0020_domaintesttls_extended_master_secret_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="domaintesttls",
            name="kex_hash_func_bad_hash",
            field=models.CharField(default=None, max_length=255, null=True),
        ),
    ]
