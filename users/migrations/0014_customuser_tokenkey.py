# Generated by Django 4.2.6 on 2023-10-22 09:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0013_customuser_is_authenticated'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='tokenKey',
            field=models.CharField(blank=True, max_length=150),
        ),
    ]