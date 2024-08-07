# Generated by Django 5.0.7 on 2024-07-29 08:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0022_securitylog'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='securitylog',
            name='correlation',
        ),
        migrations.RemoveField(
            model_name='securitylog',
            name='qualifiers',
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='access_mask',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='account_domain',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='account_logon_id',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='authentication_package',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='channel',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='event_id',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='execution',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='handle_id',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='ip_address',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='ip_port',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='keywords',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='level',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='log_name',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='logon_process',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='logon_type',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='object_name',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='object_type',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='opcode',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='opcode_value',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='privileges',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='process_id',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='provider_id',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='record_id',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='restricted_sid_count',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='severity',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='task',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='thread_id',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='user_data',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='securitylog',
            name='version',
            field=models.CharField(max_length=255),
        ),
    ]
