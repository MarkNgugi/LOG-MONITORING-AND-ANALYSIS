from django.db import migrations

def create_log_types(apps, schema_editor):
    LogType = apps.get_model('log_management_app', 'LogType')
    log_types = ['Application', 'Security', 'Setup', 'System']
    for log_type in log_types:
        LogType.objects.create(name=log_type)

class Migration(migrations.Migration):

    dependencies = [
        ('log_management_app', '0012_auto_20240716_1954'),
    ]

    operations = [
        migrations.RunPython(create_log_types),
    ]
