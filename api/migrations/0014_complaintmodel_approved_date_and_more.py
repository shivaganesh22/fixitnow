# Generated by Django 5.1.3 on 2025-01-10 12:12

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0013_alter_complaintmodel_lock'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='complaintmodel',
            name='approved_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='complaintmodel',
            name='approved_image',
            field=models.FileField(blank=True, null=True, upload_to='uploads/'),
        ),
        migrations.AddField(
            model_name='complaintmodel',
            name='approved_media_type',
            field=models.CharField(blank=True, max_length=10, null=True),
        ),
        migrations.AddField(
            model_name='complaintmodel',
            name='lock_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.CreateModel(
            name='ApproveDislike',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('complaint', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='approve_disliked_set', to='api.complaintmodel')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='approve_disliked_user', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('user', 'complaint')},
            },
        ),
        migrations.CreateModel(
            name='ApproveLike',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('complaint', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='approve_liked_set', to='api.complaintmodel')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='approve_liked_user', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('user', 'complaint')},
            },
        ),
    ]
