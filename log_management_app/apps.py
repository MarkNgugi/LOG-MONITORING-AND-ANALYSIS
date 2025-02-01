from django.apps import AppConfig


class LogManagementAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'log_management_app'

    def ready(self):
        import log_management_app.signals  # Ensure signals are loaded






