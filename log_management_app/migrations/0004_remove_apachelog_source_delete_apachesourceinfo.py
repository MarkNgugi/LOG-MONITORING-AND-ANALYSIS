# Generated by Django 4.2.11 on 2025-01-18 08:22

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0003_apachesourceinfo_apachelog_source'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='apachelog',
            name='source',
        ),
        migrations.DeleteModel(
            name='ApacheSourceInfo',
        ),
    ]