# Generated by Django 4.2.20 on 2025-03-25 08:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('otp_app', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otptoken',
            name='otp_code',
            field=models.CharField(default='98c99f', max_length=6),
        ),
    ]
