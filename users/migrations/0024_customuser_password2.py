# Generated by Django 4.2.6 on 2023-10-25 14:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0023_remove_customuser_password2'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='password2',
            field=models.CharField(blank=True, max_length=128),
        ),
    ]
