# Generated by Django 5.1.5 on 2025-02-12 11:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0032_remove_linuxlog_is_processing'),
    ]

    operations = [
        migrations.AlterField(
            model_name='linuxlog',
            name='processed',
            field=models.BooleanField(default=False),
        ),
    ]
