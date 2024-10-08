# Generated by Django 4.2.11 on 2024-08-18 18:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0070_remove_mongodblogfilestream_web_server_type_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mysqllogfilestream',
            name='db_type',
            field=models.CharField(default='Mysql', max_length=50),
        ),
        migrations.AlterField(
            model_name='mysqllogstream',
            name='db_type',
            field=models.CharField(default='Mysql', max_length=50),
        ),
        migrations.AlterField(
            model_name='mysqlperflogs',
            name='db_type',
            field=models.CharField(default='Mysql', max_length=50),
        ),
        migrations.AlterField(
            model_name='windowslogsource',
            name='collection_interval',
            field=models.CharField(default='Real-time', max_length=10),
        ),
    ]
