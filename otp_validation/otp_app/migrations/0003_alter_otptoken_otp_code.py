# Generated by Django 4.2.20 on 2025-03-25 09:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('otp_app', '0002_alter_otptoken_otp_code'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otptoken',
            name='otp_code',
            field=models.CharField(default='73a5d6', max_length=6),
        ),
    ]
