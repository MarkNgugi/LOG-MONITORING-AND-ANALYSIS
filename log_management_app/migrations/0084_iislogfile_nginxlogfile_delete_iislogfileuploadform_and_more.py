# Generated by Django 5.1.2 on 2024-11-12 22:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0083_apachelogfile_delete_apachelogfileuploadform_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='IISLogFile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source_name', models.CharField(blank=True, max_length=20, null=True)),
                ('os_type', models.CharField(default='iis', max_length=50)),
                ('file', models.FileField(upload_to='uploaded_logs/iis/')),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='NginxLogFile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source_name', models.CharField(blank=True, max_length=20, null=True)),
                ('os_type', models.CharField(default='nginx', max_length=50)),
                ('file', models.FileField(upload_to='uploaded_logs/nginx/')),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.DeleteModel(
            name='IISLogFileUploadForm',
        ),
        migrations.DeleteModel(
            name='IISserverLogFileStream',
        ),
        migrations.DeleteModel(
            name='IISserverLogStream',
        ),
        migrations.DeleteModel(
            name='IISserverPerfLogs',
        ),
        migrations.DeleteModel(
            name='LighttpdLogFileUploadForm',
        ),
        migrations.DeleteModel(
            name='LighttpdserverLogFileStream',
        ),
        migrations.DeleteModel(
            name='LighttpdserverLogStream',
        ),
        migrations.DeleteModel(
            name='LighttpdserverPerfLogs',
        ),
        migrations.DeleteModel(
            name='NginxLogFileUploadForm',
        ),
        migrations.DeleteModel(
            name='NginxserverLogFileStream',
        ),
        migrations.DeleteModel(
            name='NginxserverLogStream',
        ),
        migrations.DeleteModel(
            name='NginxserverPerfLogs',
        ),
        migrations.DeleteModel(
            name='TomcatLogFileUploadForm',
        ),
        migrations.DeleteModel(
            name='TomcatserverLogFileStream',
        ),
        migrations.DeleteModel(
            name='TomcatserverLogStream',
        ),
        migrations.DeleteModel(
            name='TomcatserverPerfLogs',
        ),
    ]
