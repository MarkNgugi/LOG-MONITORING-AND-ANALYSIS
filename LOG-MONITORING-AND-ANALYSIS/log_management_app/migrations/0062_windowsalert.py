# Generated by Django 4.2.11 on 2024-08-07 18:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0061_delete_alert'),
    ]

    operations = [
        migrations.CreateModel(
            name='WindowsAlert',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('event_id', models.CharField(max_length=50)),
                ('entry_type', models.CharField(max_length=50)),
                ('provider', models.CharField(max_length=100)),
                ('alert_level', models.CharField(max_length=100)),
                ('message', models.TextField()),
                ('source_name', models.CharField(default='windows', max_length=100)),
                ('timestamp', models.DateTimeField()),
            ],
        ),
    ]
