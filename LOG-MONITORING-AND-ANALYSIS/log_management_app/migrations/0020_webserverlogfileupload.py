# Generated by Django 5.0.7 on 2024-07-22 11:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0019_merge_20240717_1415'),
    ]

    operations = [
        migrations.CreateModel(
            name='WebserverLogFileUpload',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source_name', models.CharField(max_length=100)),
                ('file_type', models.CharField(max_length=50)),
                ('upload_date', models.DateTimeField(auto_now_add=True)),
                ('log_file_description', models.TextField()),
            ],
        ),
    ]
