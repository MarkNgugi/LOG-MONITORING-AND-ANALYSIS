# Generated by Django 3.2.8 on 2024-07-17 10:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0015_performancemetric_windowsperflogs'),
    ]

    operations = [
        migrations.CreateModel(
            name='WindowsActiveDirectoryLogSource',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('log_source_name', models.CharField(max_length=100, verbose_name='Log Source Name')),
                ('domain_name', models.CharField(max_length=100, verbose_name='Domain Name')),
                ('domain_controller_ip', models.GenericIPAddressField(protocol='IPv4', verbose_name='Domain Controller IP Address')),
                ('port_number', models.PositiveIntegerField(default=389, verbose_name='Port Number')),
                ('username', models.CharField(max_length=100, verbose_name='Username')),
                ('password', models.CharField(max_length=100, verbose_name='Password')),
                ('log_level', models.CharField(choices=[('info', 'INFO'), ('warn', 'WARN'), ('error', 'ERROR')], default='info', max_length=10, verbose_name='Log Level')),
                ('log_format', models.CharField(choices=[('json', 'JSON'), ('xml', 'XML'), ('csv', 'CSV')], default='json', max_length=10, verbose_name='Log Format')),
                ('collection_interval', models.PositiveIntegerField(default=60, verbose_name='Collection Interval (seconds)')),
                ('retention_period', models.PositiveIntegerField(default=7, verbose_name='Retention Period (days)')),
            ],
        ),
    ]
