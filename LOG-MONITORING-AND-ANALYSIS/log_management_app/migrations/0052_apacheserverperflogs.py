# Generated by Django 4.2.11 on 2024-08-02 20:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0051_apacheserverlogfilestream'),
    ]

    operations = [
        migrations.CreateModel(
            name='ApacheserverPerfLogs',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('log_source_name', models.CharField(max_length=100)),
                ('hostname_ip_address', models.CharField(default='localhost', max_length=255, null=True)),
                ('status', models.CharField(choices=[('Online', 'Active'), ('Offline', 'Inactive')], default='Offline', max_length=10)),
                ('log_file_path', models.CharField(max_length=255)),
                ('log_level', models.CharField(choices=[('DEBUG', 'DEBUG'), ('INFO', 'INFO'), ('WARN', 'WARN'), ('ERROR', 'ERROR')], default='INFO', max_length=10)),
                ('filter_keyword', models.CharField(blank=True, max_length=100, null=True)),
                ('log_rotation_interval', models.CharField(choices=[('5m', 'Every 5 minutes'), ('15m', 'Every 15 minutes'), ('30m', 'Every 30 minutes'), ('1h', 'Every 1 hour'), ('6h', 'Every 6 hours'), ('12h', 'Every 12 hours'), ('24h', 'Every 24 hours')], default='24h', max_length=10)),
                ('web_server_type', models.CharField(default='Apache', max_length=50)),
                ('collection_interval', models.CharField(choices=[('5m', 'Every 5 minutes'), ('15m', 'Every 15 minutes'), ('30m', 'Every 30 minutes'), ('1h', 'Every 1 hour'), ('6h', 'Every 6 hours'), ('12h', 'Every 12 hours'), ('24h', 'Every 24 hours')], default='24h', max_length=10)),
                ('retention_policy', models.CharField(choices=[('7d', '7 days'), ('14d', '14 days'), ('30d', '30 days'), ('60d', '60 days'), ('90d', '90 days'), ('180d', '180 days'), ('365d', '365 days')], default='30d', max_length=10)),
                ('collection_mtd', models.CharField(default='Log streaming', max_length=50)),
                ('activate', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
            ],
        ),
    ]
