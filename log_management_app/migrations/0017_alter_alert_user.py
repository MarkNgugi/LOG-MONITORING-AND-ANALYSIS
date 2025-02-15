# Generated by Django 4.2.11 on 2025-01-21 12:22

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('log_management_app', '0016_alter_alert_alert_title'),
    ]

    operations = [
        migrations.AlterField(
            model_name='alert',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='alerts_user', to=settings.AUTH_USER_MODEL),
        ),
    ]
