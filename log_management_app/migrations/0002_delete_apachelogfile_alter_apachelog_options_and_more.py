# Generated by Django 4.2.11 on 2025-01-10 20:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0001_initial'),
    ]

    operations = [
        migrations.DeleteModel(
            name='ApacheLogFile',
        ),
        migrations.AlterModelOptions(
            name='apachelog',
            options={'ordering': ['-timestamp'], 'verbose_name': 'Apache Log', 'verbose_name_plural': 'Apache Logs'},
        ),
        migrations.RemoveField(
            model_name='apachelog',
            name='error_message',
        ),
        migrations.RemoveField(
            model_name='apachelog',
            name='error_module',
        ),
        migrations.RemoveField(
            model_name='apachelog',
            name='file_path',
        ),
        migrations.RemoveField(
            model_name='apachelog',
            name='method',
        ),
        migrations.RemoveField(
            model_name='apachelog',
            name='process_id',
        ),
        migrations.RemoveField(
            model_name='apachelog',
            name='protocol',
        ),
        migrations.RemoveField(
            model_name='apachelog',
            name='status_code',
        ),
        migrations.RemoveField(
            model_name='apachelog',
            name='url',
        ),
        migrations.AddField(
            model_name='apachelog',
            name='remote_logname',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='apachelog',
            name='remote_user',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='apachelog',
            name='request_line',
            field=models.CharField(default='none', max_length=255),
        ),
        migrations.AddField(
            model_name='apachelog',
            name='response_code',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='apachelog',
            name='response_size',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='apachelog',
            name='client_ip',
            field=models.GenericIPAddressField(null=True),
        ),
        migrations.AlterField(
            model_name='apachelog',
            name='referrer',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='apachelog',
            name='timestamp',
            field=models.DateTimeField(null=True),
        ),
        migrations.AlterField(
            model_name='apachelog',
            name='user_agent',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]