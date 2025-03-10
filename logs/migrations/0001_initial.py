# Generated by Django 5.1.6 on 2025-03-01 13:17

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='LogEntry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('app_name', models.CharField(choices=[('accounts', 'Accounts'), ('applications', 'Applications'), ('payments', 'Payments')], max_length=50, verbose_name='Ilova nomi')),
                ('model_name', models.CharField(max_length=100, verbose_name='Model nomi')),
                ('object_id', models.IntegerField(verbose_name='Obyekt ID si')),
                ('action', models.CharField(max_length=20, verbose_name='Harakat')),
                ('timestamp', models.DateTimeField(auto_now_add=True, verbose_name='Vaqt')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='custom_log_entries', to=settings.AUTH_USER_MODEL, verbose_name='Foydalanuvchi')),
            ],
        ),
    ]
