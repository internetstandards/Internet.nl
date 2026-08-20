import checks.models
from django.db import migrations, models
import enumfields.fields


class Migration(migrations.Migration):
    # 0022 (not 0023) is the graph leaf: 0b94ed36 re-parented 0022 onto 0023,
    # so the chain is 0021 -> 0023 -> 0022 -> 0024 despite the numbering.
    dependencies = [
        ("checks", "0022_domaintesttls_cert_signature_phase_out"),
    ]

    operations = [
        migrations.AddField(
            model_name="domaintesttls",
            name="pq_kex_support",
            field=enumfields.fields.EnumField(
                default=3,
                enum=checks.models.PqKexSupportStatus,
                max_length=10,
            ),
        ),
        migrations.AddField(
            model_name="domaintesttls",
            name="pq_kex_supported_groups",
            field=checks.models.ListField(default=[]),
        ),
        migrations.AddField(
            model_name="domaintesttls",
            name="pq_kex_score",
            field=models.IntegerField(null=True),
        ),
    ]
