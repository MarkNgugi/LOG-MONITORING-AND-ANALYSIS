# Generated by Django 4.2.11 on 2024-08-01 15:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0046_windowslogtype_rename_logtype_linuxlogtype_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='LDAPLogSource',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('log_source_name', models.CharField(default='log_source', max_length=100)),
                ('hostname_ip_address', models.CharField(default='localhost', max_length=255, null=True)),
                ('domain_name', models.CharField(max_length=200)),
                ('status', models.CharField(choices=[('Online', 'Active'), ('Offline', 'Inactive')], default='Offline', max_length=10)),
                ('collection_interval', models.CharField(choices=[('5m', 'Every 5 minutes'), ('15m', 'Every 15 minutes'), ('30m', 'Every 30 minutes'), ('1h', 'Every 1 hour'), ('6h', 'Every 6 hours'), ('12h', 'Every 12 hours'), ('24h', 'Every 24 hours')], default='24h', max_length=10)),
                ('retention_policy', models.CharField(choices=[('7d', '7 days'), ('14d', '14 days'), ('30d', '30 days'), ('60d', '60 days'), ('90d', '90 days'), ('180d', '180 days'), ('365d', '365 days')], default='30d', max_length=10)),
                ('collection_mtd', models.CharField(default='AD logs', max_length=50)),
                ('activate', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='LinuxFileLogSource',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('log_source_name', models.CharField(default='log_source', max_length=100)),
                ('hostname_ip_address', models.CharField(default='localhost', max_length=255, null=True)),
                ('log_file_path', models.CharField(max_length=255)),
                ('log_file_type', models.CharField(choices=[('text', 'Text'), ('csv', 'CSV'), ('json', 'JSON'), ('xml', 'XML')], max_length=10)),
                ('status', models.CharField(choices=[('Online', 'Active'), ('Offline', 'Inactive')], default='Offline', max_length=10)),
                ('collection_interval', models.CharField(choices=[('5m', 'Every 5 minutes'), ('15m', 'Every 15 minutes'), ('30m', 'Every 30 minutes'), ('1h', 'Every 1 hour'), ('6h', 'Every 6 hours'), ('12h', 'Every 12 hours'), ('24h', 'Every 24 hours')], default='24h', max_length=10)),
                ('retention_policy', models.CharField(choices=[('7d', '7 days'), ('14d', '14 days'), ('30d', '30 days'), ('60d', '60 days'), ('90d', '90 days'), ('180d', '180 days'), ('365d', '365 days')], default='30d', max_length=10)),
                ('file_size_limit', models.PositiveIntegerField()),
                ('collection_mtd', models.CharField(default='file streaming', max_length=50)),
                ('activate', models.BooleanField(default=True)),
                ('rotation_policy', models.CharField(choices=[('size', 'By Size'), ('date', 'By Date'), ('size_date', 'By Size and Date')], max_length=15)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='WindowsPerformanceMetric',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, verbose_name='Metric Name')),
            ],
        ),
        migrations.RemoveField(
            model_name='linuxlogsource',
            name='comments',
        ),
        migrations.RemoveField(
            model_name='linuxlogsource',
            name='description',
        ),
        migrations.RemoveField(
            model_name='linuxlogsource',
            name='ingestion_mtd',
        ),
        migrations.AlterField(
            model_name='linuxlogsource',
            name='collection_mtd',
            field=models.CharField(default='log streaming', max_length=50),
        ),
        migrations.AlterField(
            model_name='linuxlogsource',
            name='log_source_name',
            field=models.CharField(default='log_source', max_length=100),
        ),
        migrations.AlterField(
            model_name='windowsactivedirectorylogsource',
            name='domain_name',
            field=models.CharField(max_length=200),
        ),
        migrations.AlterField(
            model_name='windowsactivedirectorylogsource',
            name='log_source_name',
            field=models.CharField(default='log_source', max_length=100),
        ),
        migrations.RenameModel(
            old_name='PerformanceMetric',
            new_name='LinuxPerformanceMetric',
        ),
        migrations.CreateModel(
            name='LinuxPerfLogs',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('log_source_name', models.CharField(default='log_source', max_length=100)),
                ('hostname_ip_address', models.CharField(default='localhost', max_length=255, null=True)),
                ('status', models.CharField(choices=[('Online', 'Active'), ('Offline', 'Inactive')], default='Offline', max_length=10)),
                ('collection_interval', models.CharField(choices=[('5m', 'Every 5 minutes'), ('15m', 'Every 15 minutes'), ('30m', 'Every 30 minutes'), ('1h', 'Every 1 hour'), ('6h', 'Every 6 hours'), ('12h', 'Every 12 hours'), ('24h', 'Every 24 hours')], default='24h', max_length=10)),
                ('retention_policy', models.CharField(choices=[('7d', '7 days'), ('14d', '14 days'), ('30d', '30 days'), ('60d', '60 days'), ('90d', '90 days'), ('180d', '180 days'), ('365d', '365 days')], default='30d', max_length=10)),
                ('collection_mtd', models.CharField(default='perf logs', max_length=50)),
                ('activate', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('performance_metrics', models.ManyToManyField(help_text='Select the metrics to collect', to='log_management_app.linuxperformancemetric', verbose_name='Performance Metrics')),
            ],
        ),
        migrations.AlterField(
            model_name='windowsperflogs',
            name='performance_metrics',
            field=models.ManyToManyField(help_text='Select the metrics to collect', to='log_management_app.windowsperformancemetric', verbose_name='Performance Metrics'),
        ),
    ]
