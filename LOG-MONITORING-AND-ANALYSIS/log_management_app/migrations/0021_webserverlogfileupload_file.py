# Generated by Django 5.0.7 on 2024-07-22 12:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0020_webserverlogfileupload'),
    ]

    operations = [
        migrations.AddField(
            model_name='webserverlogfileupload',
            name='file',
            field=models.FileField(null=True, upload_to='uploads/'),
        ),
    ]
