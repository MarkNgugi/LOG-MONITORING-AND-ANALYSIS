# Generated by Django 3.2.8 on 2024-07-08 10:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0006_auto_20240708_0952'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='windowslogsource',
            name='ingestion_method',
        ),
        migrations.AddField(
            model_name='windowslogsource',
            name='machine_type',
            field=models.CharField(choices=[('Single machine', 'Single machine'), ('PowerShellScripts', 'Windows PowerShell Commands')], default='Single machine', max_length=30),
        ),
    ]
