# Generated by Django 4.2.6 on 2023-10-21 19:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0011_alter_customuser_avatar'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='avatar',
            field=models.ImageField(blank=True, upload_to='avatars'),
        ),
    ]