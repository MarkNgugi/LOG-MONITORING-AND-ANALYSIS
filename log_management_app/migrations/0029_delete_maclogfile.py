# Generated by Django 4.2.11 on 2025-02-01 15:00

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0028_windowsadlog_delete_linuxlogfile_and_more'),
    ]

    operations = [
        migrations.DeleteModel(
            name='MacLogFile',
        ),
    ]
