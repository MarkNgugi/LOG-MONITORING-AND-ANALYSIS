# Generated by Django 5.0.7 on 2024-07-29 09:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0025_alter_securitylog_time_created'),
    ]

    operations = [
        migrations.RenameField(
            model_name='securitylog',
            old_name='ip_port',
            new_name='event_id',
        ),
        migrations.RenameField(
            model_name='securitylog',
            old_name='user_data',
            new_name='message',
        ),
        migrations.RemoveField(
            model_name='securitylog',
            name='access_mask',
        ),
        migrations.RemoveField(
            model_name='securitylog',
            name='authentication_package',
        ),
        migrations.RemoveField(
            model_name='securitylog',
            name='handle_id',
        ),
        migrations.RemoveField(
            model_name='securitylog',
            name='ip_address',
        ),
        migrations.RemoveField(
            model_name='securitylog',
            name='logon_process',
        ),
        migrations.RemoveField(
            model_name='securitylog',
            name='logon_type',
        ),
        migrations.RemoveField(
            model_name='securitylog',
            name='object_name',
        ),
        migrations.RemoveField(
            model_name='securitylog',
            name='object_type',
        ),
        migrations.RemoveField(
            model_name='securitylog',
            name='privileges',
        ),
        migrations.RemoveField(
            model_name='securitylog',
            name='restricted_sid_count',
        ),
        migrations.RemoveField(
            model_name='securitylog',
            name='time_created',
        ),
        migrations.RemoveField(
            model_name='securitylog',
            name='workstation_name',
        ),
        migrations.AddField(
            model_name='securitylog',
            name='timestamp',
            field=models.DateTimeField(null=True),
        ),
    ]
