# Generated by Django 5.1.5 on 2025-02-12 11:48

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0031_linuxlog_is_processing_alter_linuxlog_processed'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='linuxlog',
            name='is_processing',
        ),
    ]
