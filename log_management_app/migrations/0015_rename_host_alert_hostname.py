# Generated by Django 4.2.11 on 2025-01-20 13:25

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0014_alter_alert_severity'),
    ]

    operations = [
        migrations.RenameField(
            model_name='alert',
            old_name='host',
            new_name='hostname',
        ),
    ]