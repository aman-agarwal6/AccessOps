from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0006_leaver_assurance"),
    ]

    operations = [
        # Every existing signal belongs to the SOC stream, the only one until now.
        migrations.AddField(
            model_name="securityevent",
            name="receiver",
            field=models.CharField(default="soc", max_length=20),
        ),
        migrations.AlterField(
            model_name="securityevent",
            name="source_ref",
            field=models.CharField(max_length=200),
        ),
        migrations.AddConstraint(
            model_name="securityevent",
            constraint=models.UniqueConstraint(
                fields=("receiver", "source_ref"), name="one_signal_per_fact_per_receiver"
            ),
        ),
    ]
