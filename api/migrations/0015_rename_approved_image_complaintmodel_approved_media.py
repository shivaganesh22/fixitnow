# Generated by Django 5.1.3 on 2025-01-10 18:18

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0014_complaintmodel_approved_date_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='complaintmodel',
            old_name='approved_image',
            new_name='approved_media',
        ),
    ]
