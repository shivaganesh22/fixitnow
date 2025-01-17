# Generated by Django 5.1.3 on 2025-01-09 05:24

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0004_rename_userinfo_userinfomodel_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Dislike',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('complaint', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='disliked_set', to='api.complaintmodel')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='disliked_user', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('user', 'complaint')},
            },
        ),
        migrations.CreateModel(
            name='Like',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('complaint', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='liked_set', to='api.complaintmodel')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='liked_user', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('user', 'complaint')},
            },
        ),
    ]
