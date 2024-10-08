# Generated by Django 4.2.11 on 2024-08-17 20:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0069_apacheserverlogfilestream_server_type_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='mongodblogfilestream',
            name='web_server_type',
        ),
        migrations.RemoveField(
            model_name='mongodblogstream',
            name='web_server_type',
        ),
        migrations.RemoveField(
            model_name='mongodbperflogs',
            name='web_server_type',
        ),
        migrations.RemoveField(
            model_name='mysqllogfilestream',
            name='web_server_type',
        ),
        migrations.RemoveField(
            model_name='mysqllogstream',
            name='web_server_type',
        ),
        migrations.RemoveField(
            model_name='mysqlperflogs',
            name='web_server_type',
        ),
        migrations.RemoveField(
            model_name='postgreslogfilestream',
            name='web_server_type',
        ),
        migrations.RemoveField(
            model_name='postgreslogstream',
            name='web_server_type',
        ),
        migrations.RemoveField(
            model_name='postgresperflogs',
            name='web_server_type',
        ),
        migrations.AddField(
            model_name='mongodblogfilestream',
            name='db_type',
            field=models.CharField(default='Mongodb', max_length=50),
        ),
        migrations.AddField(
            model_name='mongodblogstream',
            name='db_type',
            field=models.CharField(default='Mongodb', max_length=50),
        ),
        migrations.AddField(
            model_name='mongodbperflogs',
            name='db_type',
            field=models.CharField(default='Mongodb', max_length=50),
        ),
        migrations.AddField(
            model_name='mysqllogfilestream',
            name='db_type',
            field=models.CharField(default='Postgres', max_length=50),
        ),
        migrations.AddField(
            model_name='mysqllogstream',
            name='db_type',
            field=models.CharField(default='Postgres', max_length=50),
        ),
        migrations.AddField(
            model_name='mysqlperflogs',
            name='db_type',
            field=models.CharField(default='Postgres', max_length=50),
        ),
        migrations.AddField(
            model_name='postgreslogfilestream',
            name='db_type',
            field=models.CharField(default='Postgres', max_length=50),
        ),
        migrations.AddField(
            model_name='postgreslogstream',
            name='db_type',
            field=models.CharField(default='Postgres', max_length=50),
        ),
        migrations.AddField(
            model_name='postgresperflogs',
            name='db_type',
            field=models.CharField(default='Postgres', max_length=50),
        ),
    ]
