# Generated by Django 5.1.3 on 2025-01-11 05:56

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0015_rename_approved_image_complaintmodel_approved_media'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userinfomodel',
            name='score',
        ),
    ]
