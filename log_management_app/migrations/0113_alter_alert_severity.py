# Generated by Django 5.1.2 on 2024-12-04 13:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0112_remove_alert_content_type_remove_alert_object_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='alert',
            name='severity',
            field=models.CharField(default='None', max_length=10),
        ),
    ]
