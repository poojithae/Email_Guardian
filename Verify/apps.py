from django.apps import AppConfig


class VerifyConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'Verify'

    def ready(self):
        import Verify.signals 
