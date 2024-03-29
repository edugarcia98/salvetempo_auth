# Generated by Django 3.1.7 on 2021-05-18 22:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='is_active',
            field=models.BooleanField(default=True, verbose_name='Active'),
        ),
        migrations.AlterField(
            model_name='user',
            name='is_admin',
            field=models.BooleanField(default=False, verbose_name='Admin'),
        ),
        migrations.AlterField(
            model_name='user',
            name='is_staff',
            field=models.BooleanField(default=False, verbose_name='Staff'),
        ),
        migrations.AlterField(
            model_name='user',
            name='is_superuser',
            field=models.BooleanField(default=False, verbose_name='Superuser'),
        ),
    ]
