from django.db import migrations

def forwards(apps, schema_editor):
    UserProfile = apps.get_model('core', 'UserProfile')
    UserProfile.objects.filter(role='adviser').update(role='instructor')

def backwards(apps, schema_editor):
    UserProfile = apps.get_model('core', 'UserProfile')
    UserProfile.objects.filter(role='instructor').update(role='adviser')

class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),   # ← your latest real migration
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
