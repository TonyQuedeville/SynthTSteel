# Generated by Django 4.2.6 on 2023-10-22 09:57

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0015_remove_customuser_tokenkey'),
    ]

    operations = [
        migrations.RenameField(
            model_name='customuser',
            old_name='is_authenticated',
            new_name='isAuthenticated',
        ),
    ]