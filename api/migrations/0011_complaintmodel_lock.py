# Generated by Django 5.1.3 on 2025-01-10 11:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_alter_commentmodel_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='complaintmodel',
            name='lock',
            field=models.TextField(blank=True, null=True),
        ),
    ]
