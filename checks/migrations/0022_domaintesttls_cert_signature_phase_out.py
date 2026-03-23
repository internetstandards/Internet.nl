import checks.models
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("checks", "0021_domaintesttls_kex_hash_func_techtable"),
    ]

    operations = [
        migrations.AddField(
            model_name="domaintesttls",
            name="cert_signature_phase_out",
            field=checks.models.ListField(null=True),
        ),
    ]
