# Generated by Django 5.1.3 on 2025-01-09 07:45

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_alter_complaintmodel_unique_together_and_more'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='complaintmodel',
            unique_together=set(),
        ),
    ]
