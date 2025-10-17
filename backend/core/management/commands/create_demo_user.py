from django.core.management.base import BaseCommand
from django.contrib.auth.models import User

class Command(BaseCommand):
    help = 'Creates a demo superuser'

    def handle(self, *args, **kwargs):
        if not User.objects.filter(username='admin').exists():
            User.objects.create_superuser('admin', 'admin@example.com', 'Admin@123')
            self.stdout.write(self.style.SUCCESS('Demo user created: admin/Admin@123'))
        else:
            self.stdout.write(self.style.WARNING('Admin user already exists'))